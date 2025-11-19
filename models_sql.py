# models_sql.py
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, LargeBinary
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from database import Base
import uuid

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

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    sender = Column(String, ForeignKey("users.username"), nullable=False)
    recipient = Column(String, ForeignKey("users.username"), nullable=False)

    filename = Column(String, nullable=False)
    content_type = Column(String, nullable=True)
    size = Column(Integer, nullable=False)

    # PQC-wrapped key and AES-GCM ciphertext
    kem_ciphertext = Column(LargeBinary, nullable=False)
    nonce = Column(LargeBinary, nullable=False)
    ciphertext = Column(LargeBinary, nullable=False)
    tag = Column(LargeBinary, nullable=False)
    aad = Column(LargeBinary, nullable=True)

    timestamp = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    sender_user = relationship("User", foreign_keys=[sender])
    recipient_user = relationship("User", foreign_keys=[recipient])
