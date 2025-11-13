# server.py
from __future__ import annotations

import os
import uuid
import base64
from datetime import datetime, timedelta
from typing import List

from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Form
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt

from models import (
    RegisterRequest, RegisterResponse,
    LoginRequest, LoginResponse,
    PQCPublicKeyResponse,
    SendMessageRequest, MessageResponse,
)

SECRET_JWT_KEY = os.environ.get("PQC_PLATFORM_JWT_SECRET", "dev-secret-key")  # change in prod
JWT_ALG = "HS256"

app = FastAPI(title="PQC-only Messaging & File Sharing")
security = HTTPBearer()

# In-memory DBs for example purposes
USERS: dict[str, dict] = {}  # username -> {password, pqc_public_key (bytes)}
MESSAGES: list[dict] = []    # each is a message record
FILES: dict[str, dict] = {}  # file_id -> {uploader, recipient, kem_ciphertext_b64, ...}

STORAGE_DIR = "storage"
os.makedirs(STORAGE_DIR, exist_ok=True)


# ---------- Auth helpers ----------

def create_access_token(username: str, expires_delta: timedelta = timedelta(hours=8)) -> str:
    payload = {
        "sub": username,
        "exp": datetime.utcnow() + expires_delta
    }
    token = jwt.encode(payload, SECRET_JWT_KEY, algorithm=JWT_ALG)
    return token


def get_current_user(creds: HTTPAuthorizationCredentials = Depends(security)) -> str:
    token = creds.credentials
    try:
        payload = jwt.decode(token, SECRET_JWT_KEY, algorithms=[JWT_ALG])
        return payload["sub"]
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


# ---------- User endpoints ----------

@app.post("/register", response_model=RegisterResponse)
def register(req: RegisterRequest):
    if req.username in USERS:
        raise HTTPException(status_code=400, detail="Username already exists")

    pqc_pub = base64.b64decode(req.pqc_public_key_b64)

    USERS[req.username] = {
        "password": req.password,
        "pqc_public_key": pqc_pub,
    }
    return RegisterResponse(user_id=req.username)


@app.post("/login", response_model=LoginResponse)
def login(req: LoginRequest):
    user = USERS.get(req.username)
    if not user or user["password"] != req.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token(req.username)
    return LoginResponse(access_token=token)


@app.get("/pqc_public_key/{username}", response_model=PQCPublicKeyResponse)
def get_pqc_public_key(username: str):
    user = USERS.get(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if not user["pqc_public_key"]:
        raise HTTPException(status_code=404, detail="User PQC key not set")

    return PQCPublicKeyResponse(
        username=username,
        public_key_pqc=base64.b64encode(user["pqc_public_key"]).decode()
    )


# ---------- Messaging endpoints (E2E PQC) ----------

@app.post("/send_message", response_model=MessageResponse)
def send_message(req: SendMessageRequest, current_user: str = Depends(get_current_user)):
    if req.recipient not in USERS:
        raise HTTPException(status_code=404, detail="Recipient not found")

    msg_id = str(uuid.uuid4())
    record = {
        "id": msg_id,
        "sender": current_user,
        "recipient": req.recipient,
        "kem_ciphertext_b64": req.kem_ciphertext_b64,
        "nonce_b64": req.nonce_b64,
        "ciphertext_b64": req.ciphertext_b64,
        "tag_b64": req.tag_b64,
        "aad_b64": req.aad_b64,
        "timestamp": datetime.utcnow().isoformat(),
    }
    MESSAGES.append(record)
    return MessageResponse(**record)


@app.get("/inbox", response_model=List[MessageResponse])
def inbox(current_user: str = Depends(get_current_user)):
    msgs = [m for m in MESSAGES if m["recipient"] == current_user]
    return [MessageResponse(**m) for m in msgs]


@app.get("/sent", response_model=List[MessageResponse])
def sent(current_user: str = Depends(get_current_user)):
    msgs = [m for m in MESSAGES if m["sender"] == current_user]
    return [MessageResponse(**m) for m in msgs]


# ---------- File sharing endpoints (PQC ciphertext only) ----------

@app.post("/upload_file")
async def upload_file(
    recipient: str = Form(...),
    kem_ciphertext_b64: str = Form(...),
    nonce_b64: str = Form(...),
    tag_b64: str = Form(...),
    aad_b64: str | None = Form(None),
    file: UploadFile = File(...),
    current_user: str = Depends(get_current_user),
):
    if recipient not in USERS:
        raise HTTPException(status_code=404, detail="Recipient not found")

    file_id = str(uuid.uuid4())
    filename = f"{file_id}.bin"
    path = os.path.join(STORAGE_DIR, filename)

    # We assume client already encrypted file content using pqc_encrypt
    # and is sending *ciphertext* here.
    data = await file.read()
    with open(path, "wb") as f:
        f.write(data)

    FILES[file_id] = {
        "uploader": current_user,
        "recipient": recipient,
        "kem_ciphertext_b64": kem_ciphertext_b64,
        "nonce_b64": nonce_b64,
        "tag_b64": tag_b64,
        "aad_b64": aad_b64,
        "path": path,
        "original_filename": file.filename,
        "timestamp": datetime.utcnow().isoformat(),
    }
    return {"file_id": file_id}


@app.get("/files")
def list_files(current_user: str = Depends(get_current_user)):
    # list ciphertext files the user can decrypt
    accessible = [
        {"file_id": fid,
         "uploader": meta["uploader"],
         "recipient": meta["recipient"],
         "original_filename": meta["original_filename"],
         "kem_ciphertext_b64": meta["kem_ciphertext_b64"],
         "nonce_b64": meta["nonce_b64"],
         "tag_b64": meta["tag_b64"],
         "aad_b64": meta["aad_b64"],
         "timestamp": meta["timestamp"],
        }
        for fid, meta in FILES.items()
        if meta["recipient"] == current_user or meta["uploader"] == current_user
    ]
    return accessible


@app.get("/download_file/{file_id}")
def download_file(file_id: str, current_user: str = Depends(get_current_user)):
    meta = FILES.get(file_id)
    if not meta:
        raise HTTPException(status_code=404, detail="File not found")

    if current_user not in (meta["recipient"], meta["uploader"]):
        raise HTTPException(status_code=403, detail="Not allowed")

    with open(meta["path"], "rb") as f:
        data = f.read()

    # We return ciphertext; client decrypts using shared_secret and pqc_decrypt.
    return {
        "file_id": file_id,
        "ciphertext_b64": base64.b64encode(data).decode(),
        "kem_ciphertext_b64": meta["kem_ciphertext_b64"],
        "nonce_b64": meta["nonce_b64"],
        "tag_b64": meta["tag_b64"],
        "aad_b64": meta["aad_b64"],
        "original_filename": meta["original_filename"],
        "timestamp": meta["timestamp"],
    }
