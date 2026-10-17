from __future__ import annotations

import base64
import hashlib
import secrets
import uuid
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, dh
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = FastAPI(title="SecureTunnel API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Educational in-memory state only. Restarting the server clears sessions.
tls_sessions: dict[str, dict[str, Any]] = {}
ssh_sessions: dict[str, dict[str, Any]] = {}

TLS_STEPS = [
    ("Client Hello", "The client advertises protocol versions, a random value, and supported cipher suites."),
    ("Server Hello & Certificate", "The server selects parameters and presents a certificate/public key. This demo uses a self-generated key, not a trusted public certificate."),
    ("Client Key Exchange", "For a simplified legacy-style teaching flow, the client creates a pre-master secret and encrypts it with the server RSA public key."),
    ("Session Key Generation", "Both sides derive the same demo session key from the pre-master secret and handshake randoms."),
    ("Finished", "Both sides exchange authenticated encrypted Finished messages. Real TLS 1.3 uses ephemeral (EC)DHE and does not use RSA key transport."),
]

SSH_STEPS = [
    ("Protocol Version Exchange", "Client and server exchange protocol identification strings, such as SSH-2.0."),
    ("Key Exchange", "Both sides use Diffie–Hellman to derive a shared secret without sending that secret over the network."),
    ("Server Authentication", "The server presents a host public key. In real SSH, the client validates it against known_hosts or another trust policy."),
    ("User Authentication", "The client demonstrates a simulated password or public-key authentication choice; no real account is checked."),
    ("Secure Channel Established", "The demo derives an AES key from the shared secret and can encrypt a sample message."),
]

class AdvanceRequest(BaseModel):
    session_id: str | None = None

class MessageRequest(BaseModel):
    session_id: str
    message: str = "Hello over SecureTunnel!"

def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")

def new_tls_session() -> dict[str, Any]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return {
        "id": str(uuid.uuid4()),
        "step": 0,
        "private_key": private_key,
        "public_pem": public_pem,
        "client_random": secrets.token_bytes(32),
        "server_random": secrets.token_bytes(32),
        "pre_master": None,
        "session_key": None,
        "log": [],
    }

def new_ssh_session() -> dict[str, Any]:
    # Generate fresh DH parameters/keys for each session. 2048-bit parameters
    # are appropriate for a teaching demo, not a production SSH implementation.
    params = dh.generate_parameters(generator=2, key_size=2048)
    server_private = params.generate_private_key()
    client_private = params.generate_private_key()
    shared_server = server_private.exchange(client_private.public_key())
    shared_client = client_private.exchange(server_private.public_key())
    assert shared_server == shared_client
    host_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    host_public_pem = host_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return {
        "id": str(uuid.uuid4()),
        "step": 0,
        "params": params,
        "server_private": server_private,
        "client_private": client_private,
        "shared_secret": shared_server,
        "host_public_pem": host_public_pem,
        "session_key": None,
        "log": [],
    }

@app.get("/")
def root():
    return {"name": "SecureTunnel API", "status": "ok", "docs": "/docs"}

@app.post("/api/tls/start")
def tls_start():
    session = new_tls_session()
    tls_sessions[session["id"]] = session
    return {"session_id": session["id"], "step": 0, "total_steps": len(TLS_STEPS), "message": "TLS simulation ready."}

@app.post("/api/tls/next")
def tls_next(req: AdvanceRequest):
    if not req.session_id or req.session_id not in tls_sessions:
        raise HTTPException(404, "TLS session not found. Start a new simulation.")
    s = tls_sessions[req.session_id]
    if s["step"] >= len(TLS_STEPS):
        return {"session_id": s["id"], "step": s["step"], "total_steps": len(TLS_STEPS), "complete": True, "event": None}
    n = s["step"] + 1
    event: dict[str, Any] = {"number": n, "title": TLS_STEPS[n-1][0], "explanation": TLS_STEPS[n-1][1]}
    if n == 1:
        event.update({"from": "Client", "to": "Server", "details": {"supported_cipher_suites": ["TLS_AES_128_GCM_SHA256 (illustrative)", "TLS_AES_256_GCM_SHA384 (illustrative)"], "client_random": b64(s["client_random"])[:24] + "..."}})
    elif n == 2:
        event.update({"from": "Server", "to": "Client", "details": {"selected_suite": "AES-256-GCM (educational abstraction)", "public_key_type": "RSA-2048", "public_key_pem": s["public_pem"]}})
    elif n == 3:
        pre = secrets.token_bytes(48)
        encrypted = s["private_key"].public_key().encrypt(pre, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        decrypted = s["private_key"].decrypt(encrypted, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        assert pre == decrypted
        s["pre_master"] = pre
        event.update({"from": "Client", "to": "Server", "details": {"pre_master_secret": b64(pre), "encrypted_pre_master_secret": b64(encrypted), "crypto": "RSA-OAEP encrypt/decrypt verified"}})
    elif n == 4:
        if s["pre_master"] is None:
            raise HTTPException(400, "Advance through Client Key Exchange first.")
        material = s["pre_master"] + s["client_random"] + s["server_random"]
        s["session_key"] = hashlib.sha256(material).digest()
        event.update({"from": "Both", "to": "Local derivation", "details": {"derivation": "SHA-256(pre-master || client_random || server_random)", "session_key_fingerprint": hashlib.sha256(s["session_key"]).hexdigest()[:24], "note": "A fingerprint is shown, not the raw session key."}})
    elif n == 5:
        if s["session_key"] is None:
            raise HTTPException(400, "Generate the session key first.")
        aes = AESGCM(s["session_key"])
        nonce_c = secrets.token_bytes(12)
        nonce_s = secrets.token_bytes(12)
        c = aes.encrypt(nonce_c, b"client finished", b"TLS demo")
        v = aes.decrypt(nonce_c, c, b"TLS demo").decode()
        server_cipher = aes.encrypt(nonce_s, b"server finished", b"TLS demo")
        server_v = aes.decrypt(nonce_s, server_cipher, b"TLS demo").decode()
        event.update({"from": "Client + Server", "to": "Each other", "details": {"client_finished_verified": v, "server_finished_verified": server_v, "algorithm": "AES-GCM authenticated encryption"}})
    s["step"] = n
    s["log"].append(event)
    return {"session_id": s["id"], "step": n, "total_steps": len(TLS_STEPS), "complete": n == len(TLS_STEPS), "event": event}

@app.post("/api/tls/message")
def tls_message(req: MessageRequest):
    s = tls_sessions.get(req.session_id)
    if not s or not s.get("session_key"):
        raise HTTPException(400, "Complete the TLS handshake first.")
    aes = AESGCM(s["session_key"])
    nonce = secrets.token_bytes(12)
    cipher = aes.encrypt(nonce, req.message.encode(), b"SecureTunnel sample")
    plain = aes.decrypt(nonce, cipher, b"SecureTunnel sample").decode()
    return {"nonce": b64(nonce), "ciphertext": b64(cipher), "decrypted_message": plain, "algorithm": "AES-GCM"}

@app.post("/api/ssh/start")
def ssh_start():
    s = new_ssh_session()
    ssh_sessions[s["id"]] = s
    return {"session_id": s["id"], "step": 0, "total_steps": len(SSH_STEPS), "message": "SSH simulation ready."}

@app.post("/api/ssh/next")
def ssh_next(req: AdvanceRequest):
    if not req.session_id or req.session_id not in ssh_sessions:
        raise HTTPException(404, "SSH session not found. Start a new simulation.")
    s = ssh_sessions[req.session_id]
    if s["step"] >= len(SSH_STEPS):
        return {"session_id": s["id"], "step": s["step"], "total_steps": len(SSH_STEPS), "complete": True, "event": None}
    n = s["step"] + 1
    event: dict[str, Any] = {"number": n, "title": SSH_STEPS[n-1][0], "explanation": SSH_STEPS[n-1][1]}
    if n == 1:
        event.update({"from": "Client ↔ Server", "to": "Protocol negotiation", "details": {"client_version": "SSH-2.0-SecureTunnelClient", "server_version": "SSH-2.0-SecureTunnelServer"}})
    elif n == 2:
        params = s["params"].parameter_numbers()
        client_pub = s["client_private"].public_key().public_numbers().y
        server_pub = s["server_private"].public_key().public_numbers().y
        event.update({"from": "Client ↔ Server", "to": "Diffie–Hellman exchange", "details": {"group_p_bits": params.p.bit_length(), "generator": params.g, "client_public_value": str(client_pub)[:48] + "...", "server_public_value": str(server_pub)[:48] + "...", "shared_secret_fingerprint": hashlib.sha256(s["shared_secret"]).hexdigest()[:24]}})
    elif n == 3:
        event.update({"from": "Server", "to": "Client", "details": {"host_public_key_type": "RSA-2048 (demo)", "host_public_key_pem": s["host_public_pem"], "warning": "This demo displays a host key but does not implement a known_hosts trust check."}})
    elif n == 4:
        event.update({"from": "Client", "to": "Server", "details": {"method": "Simulated public-key authentication", "result": "Accepted for demonstration only", "note": "No password is collected or checked."}})
    elif n == 5:
        s["session_key"] = hashlib.sha256(b"SecureTunnel SSH demo key" + s["shared_secret"]).digest()
        event.update({"from": "Both", "to": "Secure channel", "details": {"session_key_fingerprint": hashlib.sha256(s["session_key"]).hexdigest()[:24], "cipher": "AES-256-GCM", "note": "Simplified derivation; real SSH uses negotiated KDFs and packet protection."}})
    s["step"] = n
    s["log"].append(event)
    return {"session_id": s["id"], "step": n, "total_steps": len(SSH_STEPS), "complete": n == len(SSH_STEPS), "event": event}

@app.post("/api/ssh/message")
def ssh_message(req: MessageRequest):
    s = ssh_sessions.get(req.session_id)
    if not s or not s.get("session_key"):
        raise HTTPException(400, "Complete the SSH handshake first.")
    aes = AESGCM(s["session_key"])
    nonce = secrets.token_bytes(12)
    cipher = aes.encrypt(nonce, req.message.encode(), b"SecureTunnel SSH sample")
    plain = aes.decrypt(nonce, cipher, b"SecureTunnel SSH sample").decode()
    return {"nonce": b64(nonce), "ciphertext": b64(cipher), "decrypted_message": plain, "algorithm": "AES-GCM"}

@app.get("/api/ipsec/{mode}")
def ipsec(mode: str):
    if mode not in {"transport", "tunnel"}:
        raise HTTPException(404, "Mode must be transport or tunnel.")
    if mode == "transport":
        return {
            "mode": mode,
            "description": "Transport mode protects the IP payload while retaining the original IP header for routing.",
            "packet": ["Original IP header (visible)", "ESP header", "Encrypted payload + ESP trailer", "ESP authentication/tag"],
            "encrypted": "Transport payload (not the original IP header)",
        }
    return {
        "mode": mode,
        "description": "Tunnel mode protects the entire original IP packet and wraps it in a new outer IP header.",
        "packet": ["New outer IP header (visible)", "ESP header", "Encrypted original IP header + payload + ESP trailer", "ESP authentication/tag"],
        "encrypted": "Entire original IP packet (inner header and payload)",
    }
