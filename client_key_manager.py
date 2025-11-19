import os
import json
import base64
from crypto_pqc import generate_pqc_keypair

def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")

def b64d(data_b64: str) -> bytes:
    return base64.b64decode(data_b64)

KEYSTORE_DIR = "./client_keys"
os.makedirs(KEYSTORE_DIR, exist_ok=True)

def load_or_create_user_keys(username: str):
    path = os.path.join(KEYSTORE_DIR, f"{username}.json")

    if os.path.exists(path):
        with open(path, "r") as f:
            data = json.load(f)
        return {
            "public_key": b64d(data["public_key_b64"]),
            "secret_key": b64d(data["secret_key_b64"]),
        }

    # Generate new PQC keypair
    print(f"[keymgr] Generating new keypair for {username}")
    kp = generate_pqc_keypair()  # returns a PQCKeyPair object

    record = {
        "public_key_b64": b64e(kp.public_key),
        "secret_key_b64": b64e(kp.secret_key),
    }

    with open(path, "w") as f:
        json.dump(record, f)

    # return same structure as loaded case
    return {
        "public_key": kp.public_key,
        "secret_key": kp.secret_key,
    }
