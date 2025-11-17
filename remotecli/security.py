import json
import os
from pathlib import Path
from cryptography.fernet import Fernet
import bcrypt
import jwt
import uuid
from datetime import datetime, timedelta
import hmac
import hashlib
import base64
from .config import KEY_PATH, ensure_app_dirs

JWT_ALG = "HS256"
JWT_EXP_MINUTES = int(os.getenv("SEHCS_JWT_EXP_MINUTES", "60"))
JWT_SECRET_ENV = "SEHCS_JWT_SECRET"
JWT_ISSUER = os.getenv("SEHCS_JWT_ISSUER", "sehcs")
JWT_AUDIENCE = os.getenv("SEHCS_JWT_AUDIENCE", "sehcs-clients")

def _load_or_create_key():
    ensure_app_dirs()
    if not KEY_PATH.exists():
        key = Fernet.generate_key()
        KEY_PATH.write_bytes(key)
        KEY_PATH.chmod(0o600)
    else:
        key = KEY_PATH.read_bytes()
    return key

def get_fernet():
    key = _load_or_create_key()
    return Fernet(key)

def encrypt_dict(data: dict) -> bytes:
    f = get_fernet()
    payload = json.dumps(data).encode("utf-8")
    return f.encrypt(payload)

def decrypt_dict(token: bytes) -> dict:
    f = get_fernet()
    payload = f.decrypt(token)
    return json.loads(payload.decode("utf-8"))

def hash_password(plain: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(plain.encode("utf-8"), salt).decode("utf-8")

def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))

def _jwt_secret() -> str:
    env = os.getenv(JWT_SECRET_ENV)
    if env:
        return env
    key = _load_or_create_key()
    digest = hashlib.sha256(key).digest()
    return base64.urlsafe_b64encode(digest).decode("utf-8")

def make_jwt(username: str, role: str) -> str:
    now = datetime.utcnow()
    payload = {
        "sub": username,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=JWT_EXP_MINUTES)).timestamp()),
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(payload, _jwt_secret(), algorithm=JWT_ALG)

def make_jwt_with_extra(username: str, role: str, extra: dict) -> str:
    now = datetime.utcnow()
    payload = {
        "sub": username,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=JWT_EXP_MINUTES)).timestamp()),
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "jti": uuid.uuid4().hex,
    }
    payload.update(extra or {})
    return jwt.encode(payload, _jwt_secret(), algorithm=JWT_ALG)

def verify_jwt(token: str) -> dict:
    return jwt.decode(
        token,
        _jwt_secret(),
        algorithms=[JWT_ALG],
        audience=JWT_AUDIENCE,
        issuer=JWT_ISSUER,
    )

def hmac_sign(content: str, secret: bytes) -> str:
    mac = hmac.new(secret, content.encode("utf-8"), hashlib.sha256).digest()
    return base64.b64encode(mac).decode("utf-8")

def hmac_verify(content: str, signature_b64: str, secret: bytes) -> bool:
    try:
        sig = base64.b64decode(signature_b64.encode("utf-8"))
    except Exception:
        return False
    mac = hmac.new(secret, content.encode("utf-8"), hashlib.sha256).digest()
    return hmac.compare_digest(sig, mac)

def sign_policy_with_active_key(content: str):
    from .storage import get_active_policy_key, get_policy_key_secret
    key = get_active_policy_key()
    if not key:
        return None, None
    key_id, _ = key
    secret = get_policy_key_secret(key_id)
    sig = hmac_sign(content, secret)
    return key_id, sig

def verify_policy_signature(content: str, signature_b64: str, key_id: str) -> bool:
    from .storage import get_policy_key_secret
    secret = get_policy_key_secret(key_id)
    if not secret:
        return False
    return hmac_verify(content, signature_b64, secret)