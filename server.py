# server.py
from __future__ import annotations

import base64
import json
import os
import time
import uuid
from datetime import datetime
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Form
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, or_
from crypto_pqc import (
     pqc_encapsulate,
     pqc_decapsulate,
     pqc_encrypt,
     pqc_decrypt,
)
from database import Base, engine, get_db
from models_sql import User, Message, FileRecord
from models import (
    RegisterRequest, RegisterResponse,
    LoginRequest, LoginResponse,
    PQCPublicKeyResponse,
    SendMessageRequest, MessageResponse,
)

from crypto_pqc import (
    PQCSignatureKeyPair,
    generate_pqc_sig_keypair,
    pqc_sign,
    pqc_verify,
)

TOKEN_LIFETIME_SECONDS = 1000 * 3600  # 8 hours

app = FastAPI(title="PQC-only Messaging & File Sharing (Kyber768 + Dilithium3)")
security = HTTPBearer()

# Server-wide PQC signing keypair (Dilithium3)
SERVER_SIG_KEYS: PQCSignatureKeyPair | None = None


def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


def init_server_sig_keys():
    global SERVER_SIG_KEYS
    if SERVER_SIG_KEYS is None:
        SERVER_SIG_KEYS = generate_pqc_sig_keypair()


@app.on_event("startup")
async def on_startup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    init_server_sig_keys()


# ------------- PQC token (Dilithium3-signed) -------------


def create_pqc_token(username: str, lifetime: int = TOKEN_LIFETIME_SECONDS) -> str:
    """
    Create a JWT-like token signed with Dilithium3.
    Format: base64url(header).base64url(payload).base64url(signature)
    """
    assert SERVER_SIG_KEYS is not None
    now = int(time.time())
    header = {
        "alg": "ML-DSA-65",  # matches SIG_ALG in crypto_pqc.py
        "typ": "PQCJWT",
    }
    payload = {
        "sub": username,
        "iat": now,
        "exp": now + lifetime,
    }

    header_b = json.dumps(header, separators=(",", ":")).encode()
    payload_b = json.dumps(payload, separators=(",", ":")).encode()

    header_b64 = b64url_encode(header_b)
    payload_b64 = b64url_encode(payload_b)

    signing_input = (header_b64 + "." + payload_b64).encode()

    signature = pqc_sign(signing_input, SERVER_SIG_KEYS.secret_key)
    sig_b64 = b64url_encode(signature)

    return header_b64 + "." + payload_b64 + "." + sig_b64


def verify_pqc_token(token: str) -> str:
    """
    Verify a Dilithium3-signed token and return username (sub).
    Raises HTTPException on failure.
    """
    assert SERVER_SIG_KEYS is not None
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid token format")

    signing_input = (header_b64 + "." + payload_b64).encode()
    signature = b64url_decode(sig_b64)

    header = json.loads(b64url_decode(header_b64))
    payload = json.loads(b64url_decode(payload_b64))

    if header.get("alg") != "ML-DSA-65":
        raise HTTPException(status_code=401, detail="Unexpected token algorithm")

    ok = pqc_verify(signing_input, signature, SERVER_SIG_KEYS.public_key)
    if not ok:
        raise HTTPException(status_code=401, detail="Invalid token signature")

    now = int(time.time())
    if now > int(payload.get("exp", 0)):
        raise HTTPException(status_code=401, detail="Token expired")

    sub = payload.get("sub")
    if not sub:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    return sub


def get_current_user(creds: HTTPAuthorizationCredentials = Depends(security)) -> str:
    token = creds.credentials
    return verify_pqc_token(token)


# ---------------- User endpoints ----------------

@app.post("/register", response_model=RegisterResponse)
async def register(req: RegisterRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.username == req.username))
    existing = result.scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")

    user = User(
        username=req.username,
        password=req.password,  # TODO: hash in real deployment
        pqc_public_key_b64=req.pqc_public_key_b64,
    )
    db.add(user)
    await db.commit()
    return RegisterResponse(user_id=req.username)


@app.post("/login", response_model=LoginResponse)
async def login(req: LoginRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.username == req.username))
    user = result.scalar_one_or_none()
    if not user or user.password != req.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_pqc_token(req.username)
    return LoginResponse(access_token=token)


@app.get("/pqc_public_key/{username}", response_model=PQCPublicKeyResponse)
async def get_pqc_public_key(username: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return PQCPublicKeyResponse(
        username=username,
        public_key_pqc=user.pqc_public_key_b64,
    )


# ---------------- Messaging endpoints ----------------

@app.post("/send_message", response_model=MessageResponse)
async def send_message(
    req: SendMessageRequest,
    current_user: str = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).where(User.username == req.recipient))
    recipient = result.scalar_one_or_none()
    if not recipient:
        raise HTTPException(status_code=404, detail="Recipient not found")

    msg_id = str(uuid.uuid4())

    msg = Message(
        id=msg_id,
        sender=current_user,
        recipient=req.recipient,
        kem_ciphertext_b64=req.kem_ciphertext_b64,
        nonce_b64=req.nonce_b64,
        ciphertext_b64=req.ciphertext_b64,
        tag_b64=req.tag_b64,
        aad_b64=req.aad_b64,
    )
    db.add(msg)
    await db.commit()
    await db.refresh(msg)

    return MessageResponse(
        id=msg.id,
        sender=msg.sender,
        recipient=msg.recipient,
        kem_ciphertext_b64=msg.kem_ciphertext_b64,
        nonce_b64=msg.nonce_b64,
        ciphertext_b64=msg.ciphertext_b64,
        tag_b64=msg.tag_b64,
        aad_b64=msg.aad_b64,
        timestamp=msg.timestamp.isoformat(),
    )


@app.get("/inbox", response_model=List[MessageResponse])
async def inbox(
    current_user: str = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Message)
        .where(Message.recipient == current_user)
        .order_by(Message.timestamp.desc())
    )
    rows = result.scalars().all()
    return [
        MessageResponse(
            id=m.id,
            sender=m.sender,
            recipient=m.recipient,
            kem_ciphertext_b64=m.kem_ciphertext_b64,
            nonce_b64=m.nonce_b64,
            ciphertext_b64=m.ciphertext_b64,
            tag_b64=m.tag_b64,
            aad_b64=m.aad_b64,
            timestamp=m.timestamp.isoformat(),
        )
        for m in rows
    ]


@app.get("/sent", response_model=List[MessageResponse])
async def sent(
    current_user: str = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Message)
        .where(Message.sender == current_user)
        .order_by(Message.timestamp.desc())
    )
    rows = result.scalars().all()
    return [
        MessageResponse(
            id=m.id,
            sender=m.sender,
            recipient=m.recipient,
            kem_ciphertext_b64=m.kem_ciphertext_b64,
            nonce_b64=m.nonce_b64,
            ciphertext_b64=m.ciphertext_b64,
            tag_b64=m.tag_b64,
            aad_b64=m.aad_b64,
            timestamp=m.timestamp.isoformat(),
        )
        for m in rows
    ]
