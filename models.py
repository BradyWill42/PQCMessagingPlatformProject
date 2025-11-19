# models.py
from pydantic import BaseModel


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
    public_key_pqc: str  # base64


class SendMessageRequest(BaseModel):
    recipient: str
    kem_ciphertext_b64: str
    nonce_b64: str
    ciphertext_b64: str
    tag_b64: str
    aad_b64: str | None = None


class MessageResponse(BaseModel):
    id: str
    sender: str
    recipient: str
    kem_ciphertext_b64: str
    nonce_b64: str
    ciphertext_b64: str
    tag_b64: str
    aad_b64: str | None = None
    timestamp: str

class FileInfoResponse(BaseModel):
    file_id: str
    uploader: str
    recipient: str
    original_filename: str
    kem_ciphertext_b64: str
    nonce_b64: str
    tag_b64: str
    aad_b64: Optional[str] = None
    timestamp: str


class FileDownloadResponse(FileInfoResponse):
    ciphertext_b64: str
