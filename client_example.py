# client_example.py
import base64
import requests
import os

from crypto_pqc import (
    pqc_encapsulate,
    pqc_decapsulate,
    pqc_encrypt,
    pqc_decrypt,
)
from client_key_manager import load_or_create_user_keys

SERVER = "http://127.0.0.1:8000"

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()


def b64d(s) -> bytes:
    # Be tolerant: accept str or bytes and auto-fix missing base64 padding
    if isinstance(s, bytes):
        s = s.decode()

    if not isinstance(s, str):
        raise TypeError(f"b64d expected str or bytes, got {type(s)}")

    s = s.strip()
    # Fix missing '=' padding if needed
    missing = (-len(s)) % 4
    if missing:
        s += "=" * missing

    return base64.b64decode(s)

def decrypt_and_print(shared_secret, nonce, ciphertext, tag):
    plaintext = pqc_decrypt(shared_secret, nonce, ciphertext, tag)
    try:
        print("Decrypted plaintext:", plaintext.decode())
    except UnicodeDecodeError:
        print("Decrypted plaintext (bytes):", plaintext)


def register_and_login(username: str, password: str):
    kp = load_or_create_user_keys(username)

    # Register public key
    register = requests.post(f"{SERVER}/register", json={
        "username": username,
        "password": password,
        "pqc_public_key_b64": b64e(kp["public_key"]),
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


def get_peer_public_key(username: str) -> bytes:
    resp = requests.get(f"{SERVER}/pqc_public_key/{username}")
    resp.raise_for_status()
    return b64d(resp.json()["public_key_pqc"])


def fetch_and_decrypt_messages(username: str, keypair, token: str, box="inbox"):
    """Decrypt messages by decapsulating per-message KEM ciphertext."""

    assert box in ("inbox", "sent")
    url = f"{SERVER}/{box}"
    headers = {"Authorization": f"Bearer {token}"}

    resp = requests.get(url, headers=headers)
    resp.raise_for_status()
    messages = resp.json()

    print(f"\n=== {username}'s {box} (attempted decryption) ===")

    if not messages:
        print("(empty)")
        return

    for m in messages:
        sender = m["sender"]
        recipient = m["recipient"]

        kem_ct = b64d(m["kem_ciphertext_b64"])
        nonce = b64d(m["nonce_b64"])
        ct = b64d(m["ciphertext_b64"])
        tag = b64d(m["tag_b64"])

        # Only decrypt if we are the intended recipient
        if recipient != username:
            print(f"- {sender} -> {recipient}: (cannot decrypt; {username} is not recipient)")
            continue

        # Per-message decapsulation
        try:
            shared_secret = pqc_decapsulate(kem_ct, keypair["secret_key"])
            plaintext = pqc_decrypt(shared_secret, nonce, ct, tag)
            print(f"- {sender} -> {recipient}: {plaintext.decode(errors='replace')}")
        except Exception as e:
            print(f"- {sender} -> {recipient}: [decryption failed: {e}]")



if __name__ == "__main__":
    # Load or create keys + authenticate
    alice_kp, alice_token = register_and_login("alice", "alicepw")
    bob_kp, bob_token = register_and_login("bob", "bobpw")

    # Fetch KEM public keys
    alice_pub = get_peer_public_key("alice")
    bob_pub = get_peer_public_key("bob")

    #
    # --- Alice → Bob ---
    #
    msg_AB = b"Hello Bob, Im not a big fan of 3"

    shared_secret_AB, kem_ct_AB = pqc_encapsulate(bob_pub)
    nonce_AB, ct_AB, tag_AB = pqc_encrypt(shared_secret_AB, msg_AB)

    r = requests.post(
        f"{SERVER}/send_message",
        json={
            "recipient": "bob",
            "kem_ciphertext_b64": b64e(kem_ct_AB),
            "nonce_b64": b64e(nonce_AB),
            "ciphertext_b64": b64e(ct_AB),
            "tag_b64": b64e(tag_AB),
            "aad_b64": None,
        },
        headers={"Authorization": f"Bearer {alice_token}"},
    )
    r.raise_for_status()
    print("Alice → Bob sent:", r.json())

    #
    # --- Bob → Alice ---
    #
    msg_BA = b"Hello alice, I too am a hater of 3"

    shared_secret_BA, kem_ct_BA = pqc_encapsulate(alice_pub)
    nonce_BA, ct_BA, tag_BA = pqc_encrypt(shared_secret_BA, msg_BA)

    r = requests.post(
        f"{SERVER}/send_message",
        json={
            "recipient": "alice",
            "kem_ciphertext_b64": b64e(kem_ct_BA),
            "nonce_b64": b64e(nonce_BA),
            "ciphertext_b64": b64e(ct_BA),
            "tag_b64": b64e(tag_BA),
            "aad_b64": None,
        },
        headers={"Authorization": f"Bearer {bob_token}"},
    )
    r.raise_for_status()
    print("Bob → Alice sent:", r.json())

    #
    # --- Decrypt mailboxes (NOW WORKS) ---
    #
    fetch_and_decrypt_messages("alice", alice_kp, alice_token, box="inbox")
    fetch_and_decrypt_messages("bob", bob_kp, bob_token, box="inbox")

