# models.py
from datetime import datetime
from pydantic import BaseModel
from typing import Optional


class RegisterRequest(BaseModel):
    username: str
    password: str
    pqc_public_key_b64: str  # client-generated Kyber public key (base64)


class RegisterResponse(BaseModel):
    user_id: str


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class PQCPublicKeyResponse(BaseModel):
    username: str
    public_key_pqc: str


class SendMessageRequest(BaseModel):
    recipient: str
    kem_ciphertext_b64: str
    nonce_b64: str
    ciphertext_b64: str
    tag_b64: str
    aad_b64: Optional[str] = None


class MessageResponse(BaseModel):
    id: str
    sender: str
    recipient: str
    kem_ciphertext_b64: str
    nonce_b64: str
    ciphertext_b64: str
    tag_b64: str
    aad_b64: Optional[str] = None
    timestamp: str
