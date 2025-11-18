# client_example.py
import base64
import requests

from crypto_pqc import generate_pqc_keypair, pqc_encapsulate, pqc_encrypt, pqc_decrypt
import oqs

SERVER = "http://127.0.0.1:8000"


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode())


def register_and_login(username: str, password: str):
    kp = generate_pqc_keypair()

    # Register (send public key only)
    register = requests.post(f"{SERVER}/register", json={
        "username": username,
        "password": password,
        "pqc_public_key_b64": b64e(kp.public_key),
    })
    print("Register response:", register.status_code, register.text)

    # Login
    resp = requests.post(f"{SERVER}/login", json={
        "username": username,
        "password": password,
    })
    resp.raise_for_status()
    token = resp.json()["access_token"]
    return kp, token


def get_peer_public_key(username: str):
    resp = requests.get(f"{SERVER}/pqc_public_key/{username}")
    resp.raise_for_status()
    return b64d(resp.json()["public_key_pqc"])


def send_pqc_message(sender_token: str, recipient: str, shared_secret: bytes, plaintext: bytes):
    nonce, ciphertext, tag = pqc_encrypt(shared_secret, plaintext)
    # here we already have kem_ciphertext from encapsulation

    headers = {"Authorization": f"Bearer {sender_token}"}
    return nonce, ciphertext, tag, headers


if __name__ == "__main__":
    # Alice and Bob example
    alice_kp, alice_token = register_and_login("alice", "alicepw")
    bob_kp, bob_token = register_and_login("bob", "bobpw")

    # Alice fetches Bob's Kyber public key
    bob_pub = get_peer_public_key("bob")

    # Alice encapsulates to Bob -> PQC shared_secret + kem_ciphertext
    shared_secret, kem_ct = pqc_encapsulate(bob_pub)

    msg = b"Hello Bob, this is PQC-only!"

    nonce, ciphertext, tag = pqc_encrypt(shared_secret, msg)

    headers = {"Authorization": f"Bearer {alice_token}"}
    r = requests.post(f"{SERVER}/send_message", json={
        "recipient": "bob",
        "kem_ciphertext_b64": b64e(kem_ct),
        "nonce_b64": b64e(nonce),
        "ciphertext_b64": b64e(ciphertext),
        "tag_b64": b64e(tag),
        "aad_b64": None,
    }, headers=headers)
    r.raise_for_status()
    print("Message sent:", r.json())
