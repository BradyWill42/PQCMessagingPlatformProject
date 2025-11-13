# crypto_pqc.py
import os
import hmac
import hashlib
from dataclasses import dataclass

try:
    import oqs  # pip install oqs-python
except ImportError:
    oqs = None

KEM_ALG = "Kyber768"  # NIST PQC KEM


@dataclass
class PQCKeyPair:
    public_key: bytes
    secret_key: bytes


# ---------- KEM: Kyber keypair / encaps / decaps ----------

def generate_pqc_keypair() -> PQCKeyPair:
    if oqs is None:
        raise RuntimeError("oqs-python (liboqs) not available")

    with oqs.KeyEncapsulation(KEM_ALG) as kem:
        public_key = kem.generate_keypair()
        secret_key = kem.export_secret_key()
    return PQCKeyPair(public_key=public_key, secret_key=secret_key)


def pqc_encapsulate(peer_public_key: bytes) -> tuple[bytes, bytes]:
    """
    peer_public_key: recipient's Kyber public key
    return: (shared_secret, kem_ciphertext)
    """
    if oqs is None:
        raise RuntimeError("oqs-python (liboqs) not available")

    with oqs.KeyEncapsulation(KEM_ALG, peer_public_key) as kem:
        kem_ciphertext, shared_secret = kem.encap_secret()
    return shared_secret, kem_ciphertext


def pqc_decapsulate(ciphertext: bytes, secret_key: bytes, public_key: bytes) -> bytes:
    """
    ciphertext: KEM ciphertext
    return: shared_secret
    """
    if oqs is None:
        raise RuntimeError("oqs-python (liboqs) not available")

    with oqs.KeyEncapsulation(KEM_ALG) as kem:
        kem.import_secret_key(secret_key)
        kem.import_public_key(public_key)
        shared_secret = kem.decap_secret(ciphertext)
    return shared_secret


# ---------- PQC symmetric layer: SHAKE stream + SHA3 MAC ----------

def _derive_keystream(shared_secret: bytes, nonce: bytes, length: int) -> bytes:
    """
    Derive keystream using SHAKE-256 (XOF) from shared_secret and nonce.
    """
    shake = hashlib.shake_256()
    shake.update(shared_secret)
    shake.update(nonce)
    return shake.digest(length)


def pqc_encrypt(shared_secret: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes, bytes]:
    """
    PQC-only authenticated encryption using SHAKE-256 + SHA3-256.

    Returns (nonce, ciphertext, tag).
    """
    nonce = os.urandom(32)  # 256-bit nonce
    keystream = _derive_keystream(shared_secret, nonce, len(plaintext))
    ciphertext = bytes(p ^ k for p, k in zip(plaintext, keystream))

    mac_input = shared_secret + nonce + aad + ciphertext
    tag = hashlib.sha3_256(mac_input).digest()
    return nonce, ciphertext, tag


def pqc_decrypt(shared_secret: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b"") -> bytes:
    """
    Verify MAC then decrypt using same SHAKE-256 keystream.
    """
    mac_input = shared_secret + nonce + aad + ciphertext
    expected_tag = hashlib.sha3_256(mac_input).digest()
    if not hmac.compare_digest(expected_tag, tag):
        raise ValueError("Authentication failed (invalid tag)")
    keystream = _derive_keystream(shared_secret, nonce, len(ciphertext))
    plaintext = bytes(c ^ k for c, k in zip(ciphertext, keystream))
    return plaintext
