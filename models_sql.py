# models_sql.py
from sqlalchemy import Column, Integer, String, DateTime, Text, LargeBinary
from sqlalchemy.sql import func
from database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, index=True, nullable=False)
    password = Column(String(128), nullable=False)  # TODO: hash properly for prod
    pqc_public_key_b64 = Column(Text, nullable=False)


class Message(Base):
    __tablename__ = "messages"

    id = Column(String(64), primary_key=True, index=True)   # UUID string
    sender = Column(String(64), index=True, nullable=False)
    recipient = Column(String(64), index=True, nullable=False)

    kem_ciphertext_b64 = Column(Text, nullable=False)
    nonce_b64 = Column(Text, nullable=False)
    ciphertext_b64 = Column(Text, nullable=False)
    tag_b64 = Column(Text, nullable=False)
    aad_b64 = Column(Text, nullable=True)

    timestamp = Column(DateTime(timezone=True), server_default=func.now())


class FileRecord(Base):
    __tablename__ = "files"

    id = Column(String(64), primary_key=True, index=True)  # UUID
    uploader = Column(String(64), index=True, nullable=False)
    recipient = Column(String(64), index=True, nullable=False)

    kem_ciphertext_b64 = Column(Text, nullable=False)
    nonce_b64 = Column(Text, nullable=False)
    tag_b64 = Column(Text, nullable=False)
    aad_b64 = Column(Text, nullable=True)

    original_filename = Column(String(255), nullable=False)

    # Encrypted file bytes stored directly in SQL
    ciphertext = Column(LargeBinary, nullable=False)

    timestamp = Column(DateTime(timezone=True), server_default=func.now())
