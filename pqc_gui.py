#!/usr/bin/env python3
import os
import base64
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

import requests

from crypto_pqc import (
    pqc_encapsulate,
    pqc_decapsulate,
    pqc_encrypt,
    pqc_decrypt,
)
from client_key_manager import load_or_create_user_keys

SERVER = "http://127.0.0.1:8000"

# ---------- Base64 helpers ----------

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def b64d(s) -> bytes:
    """
    Robust base64 decoder:
    - accepts str or bytes
    - strips whitespace
    - auto-fixes missing '=' padding
    """
    if isinstance(s, bytes):
        s = s.decode("ascii", errors="ignore")
    if not isinstance(s, str):
        raise TypeError(f"b64d expected str/bytes, got {type(s)}")
    s = s.strip().replace("\n", "").replace(" ", "")
    pad = (-len(s)) % 4
    if pad:
        s += "=" * pad
    return base64.b64decode(s)


# ---------- HTTP helpers ----------

def api_post(path: str, json=None, token: str | None = None):
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    resp = requests.post(f"{SERVER}{path}", json=json, headers=headers)
    resp.raise_for_status()
    return resp


def api_get(path: str, token: str | None = None):
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    resp = requests.get(f"{SERVER}{path}", headers=headers)
    resp.raise_for_status()
    return resp


def get_peer_public_key(username: str) -> bytes:
    resp = api_get(f"/pqc_public_key/{username}")
    data = resp.json()
    return b64d(data["public_key_pqc"])


# ---------- GUI Client class ----------

class PQCGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PQC Messaging & File Sharing Client")
        self.geometry("1000x700")

        self.current_user: str | None = None
        self.current_token: str | None = None
        self.current_keypair: dict | None = None  # {"public_key": bytes, "secret_key": bytes}

        self._build_ui()

    # ----- UI layout -----

    def _build_ui(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        # Top: auth / status
        auth_frame = ttk.Frame(self, padding=8)
        auth_frame.grid(row=0, column=0, sticky="ew")
        auth_frame.columnconfigure(5, weight=1)

        ttk.Label(auth_frame, text="Username:").grid(row=0, column=0, sticky="w")
        self.username_var = tk.StringVar()
        ttk.Entry(auth_frame, textvariable=self.username_var, width=16).grid(row=0, column=1, sticky="w")

        ttk.Label(auth_frame, text="Password:").grid(row=0, column=2, sticky="w", padx=(8, 0))
        self.password_var = tk.StringVar()
        ttk.Entry(auth_frame, textvariable=self.password_var, width=16, show="*").grid(row=0, column=3, sticky="w")

        ttk.Button(auth_frame, text="Register + Login", command=self.on_register_login).grid(
            row=0, column=4, sticky="w", padx=(8, 0)
        )

        self.status_var = tk.StringVar(value="Not logged in")
        ttk.Label(auth_frame, textvariable=self.status_var).grid(row=0, column=5, sticky="e")

        # Middle: notebook with two tabs
        notebook = ttk.Notebook(self)
        notebook.grid(row=1, column=0, sticky="nsew", padx=8, pady=8)

        self._build_messages_tab(notebook)

    def _build_messages_tab(self, notebook: ttk.Notebook):
        frame = ttk.Frame(notebook, padding=8)
        notebook.add(frame, text="Messages")

        frame.columnconfigure(0, weight=1)
        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(2, weight=1)

        # Send box
        send_frame = ttk.LabelFrame(frame, text="Send message", padding=8)
        send_frame.grid(row=0, column=0, columnspan=2, sticky="ew")

        ttk.Label(send_frame, text="To:").grid(row=0, column=0, sticky="w")
        self.msg_recipient_var = tk.StringVar()
        ttk.Entry(send_frame, textvariable=self.msg_recipient_var, width=20).grid(row=0, column=1, sticky="w")

        ttk.Label(send_frame, text="Message:").grid(row=1, column=0, sticky="nw", pady=(4, 0))
        self.msg_text = tk.Text(send_frame, width=80, height=4)
        self.msg_text.grid(row=1, column=1, columnspan=3, sticky="ew", pady=(4, 0))

        ttk.Button(send_frame, text="Send", command=self.on_send_message).grid(
            row=0, column=3, rowspan=2, sticky="nsw", padx=(8, 0)
        )

        # Inbox / Sent panes
        inbox_frame = ttk.LabelFrame(frame, text="Inbox (decrypted where possible)", padding=8)
        inbox_frame.grid(row=2, column=0, sticky="nsew", pady=(8, 0))
        inbox_frame.rowconfigure(1, weight=1)
        inbox_frame.columnconfigure(0, weight=1)

        ttk.Button(inbox_frame, text="Refresh inbox", command=self.on_refresh_inbox).grid(
            row=0, column=0, sticky="w"
        )

        self.inbox_text = tk.Text(inbox_frame, wrap="word")
        self.inbox_text.grid(row=1, column=0, sticky="nsew", pady=(4, 0))

        sent_frame = ttk.LabelFrame(frame, text="Sent (cannot decrypt, only metadata)", padding=8)
        sent_frame.grid(row=2, column=1, sticky="nsew", pady=(8, 0))
        sent_frame.rowconfigure(1, weight=1)
        sent_frame.columnconfigure(0, weight=1)

        ttk.Button(sent_frame, text="Refresh sent", command=self.on_refresh_sent).grid(
            row=0, column=0, sticky="w"
        )

        self.sent_text = tk.Text(sent_frame, wrap="word")
        self.sent_text.grid(row=1, column=0, sticky="nsew", pady=(4, 0))

    # ----- Auth logic -----

    def on_register_login(self):
        username = self.username_var.get().strip()
        password = self.password_var.get().strip()
        if not username or not password:
            messagebox.showerror("Error", "Username and password required")
            return

        try:
            # 1) load or create PQC keypair for this user (same as client_example)
            kp = load_or_create_user_keys(username)

            # 2) REGISTER – same JSON body as your working client_example.py
            reg = requests.post(
                f"{SERVER}/register",
                json={
                    "username": username,
                    "password": password,
                    "pqc_public_key_b64": b64e(kp["public_key"]),
                },
            )
            print("Register response:", reg.status_code, reg.text)

            # If user already exists, you might get 400; that's not fatal for GUI
            if reg.status_code not in (200, 400):
                reg.raise_for_status()

            # 3) LOGIN – again, same as client_example.py
            login = requests.post(
                f"{SERVER}/login",
                json={
                    "username": username,
                    "password": password,
                },
            )
            print("Login response:", login.status_code, login.text)
            login.raise_for_status()
            token = login.json()["access_token"]

            # 4) Save state into GUI
            self.current_user = username
            self.current_token = token
            self.current_keypair = kp

            self.status_var.set(f"Logged in as {username}")
            messagebox.showinfo("Success", f"Logged in as {username}")

        except Exception as e:
            self.status_var.set("Login failed")
            messagebox.showerror("Error", f"Register/Login failed:\n{e}")


    # ----- Messaging logic -----

    def _require_auth(self):
        if not self.current_user or not self.current_token or not self.current_keypair:
            raise RuntimeError("You must login first")

    def on_send_message(self):
        try:
            self._require_auth()
        except RuntimeError as e:
            messagebox.showerror("Error", str(e))
            return

        recipient = self.msg_recipient_var.get().strip()
        if not recipient:
            messagebox.showerror("Error", "Recipient required")
            return

        text = self.msg_text.get("1.0", "end").strip()
        if not text:
            messagebox.showerror("Error", "Message text required")
            return

        try:
            # Fetch recipient PQC key
            recipient_pub = get_peer_public_key(recipient)

            # KEM to recipient -> shared secret + KEM ciphertext
            shared_secret, kem_ct = pqc_encapsulate(recipient_pub)

            # AES-GCM encrypt
            nonce, ct, tag = pqc_encrypt(shared_secret, text.encode("utf-8"))

            payload = {
                "recipient": recipient,
                "kem_ciphertext_b64": b64e(kem_ct),
                "nonce_b64": b64e(nonce),
                "ciphertext_b64": b64e(ct),
                "tag_b64": b64e(tag),
                "aad_b64": None,
            }

            resp = api_post("/send_message", json=payload, token=self.current_token)
            msg = resp.json()
            messagebox.showinfo("Sent", f"Message ID: {msg['id']}")
            self.msg_text.delete("1.0", "end")

        except Exception as e:
            messagebox.showerror("Error", f"Send failed:\n{e}")

    def on_refresh_inbox(self):
        try:
            self._require_auth()
        except RuntimeError as e:
            messagebox.showerror("Error", str(e))
            return

        try:
            resp = api_get("/inbox", token=self.current_token)
            messages = resp.json()

            self.inbox_text.delete("1.0", "end")
            if not messages:
                self.inbox_text.insert("end", "(inbox empty)\n")
                return

            for m in messages:
                sender = m["sender"]
                recipient = m["recipient"]
                kem_ct = b64d(m["kem_ciphertext_b64"])
                nonce = b64d(m["nonce_b64"])
                ct = b64d(m["ciphertext_b64"])
                tag = b64d(m["tag_b64"])

                if recipient != self.current_user:
                    self.inbox_text.insert(
                        "end",
                        f"- {sender} → {recipient}: (cannot decrypt; you are not recipient)\n",
                    )
                    continue

                try:
                    shared_secret = pqc_decapsulate(kem_ct, self.current_keypair["secret_key"])
                    plaintext = pqc_decrypt(shared_secret, nonce, ct, tag)
                    text = plaintext.decode("utf-8", errors="replace")
                    self.inbox_text.insert(
                        "end", f"- {sender} → {recipient}: {text}\n"
                    )
                except Exception as e:
                    self.inbox_text.insert(
                        "end",
                        f"- {sender} → {recipient}: [decryption failed: {e}]\n",
                    )

        except Exception as e:
            messagebox.showerror("Error", f"Failed to fetch inbox:\n{e}")

    def on_refresh_sent(self):
        try:
            self._require_auth()
        except RuntimeError as e:
            messagebox.showerror("Error", str(e))
            return

        try:
            resp = api_get("/sent", token=self.current_token)
            messages = resp.json()

            self.sent_text.delete("1.0", "end")
            if not messages:
                self.sent_text.insert("end", "(no sent messages)\n")
                return

            for m in messages:
                sender = m["sender"]
                recipient = m["recipient"]
                self.sent_text.insert(
                    "end",
                    f"- {sender} → {recipient} at {m['timestamp']} (cannot decrypt; encrypted for {recipient})\n",
                )

        except Exception as e:
            messagebox.showerror("Error", f"Failed to fetch sent messages:\n{e}")

    # ----- File logic -----


if __name__ == "__main__":
    app = PQCGUI()
    app.mainloop()
