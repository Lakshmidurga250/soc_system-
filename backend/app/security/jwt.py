"""Authentication tokens and password hashing helpers."""
from datetime import datetime, timedelta, timezone
from typing import Any, Dict
import jwt
from pwdlib import PasswordHash
from ..core.config import settings

pwd_hash = PasswordHash.recommended()

def hash_password(plain_password: str) -> str:
    return pwd_hash.hash(plain_password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_hash.verify(plain_password, hashed_password)

def create_access_token(user_id: str, role: str, extra_claims: Dict[str, Any] | None = None, expires_delta: timedelta | None = None) -> str:
    now = datetime.now(timezone.utc)
    if expires_delta:
        expires = now + expires_delta
    else:
        expires = now + timedelta(minutes=settings.jwt_access_token_expire_minutes)
    payload = {
        "sub": user_id,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int(expires.timestamp()),
        **(extra_claims or {})
    }
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)

def decode_access_token(token: str) -> Dict[str, Any]:
    try:
        return jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
    except jwt.PyJWTError as exc:
        raise ValueError(f"Invalid authentication token: {exc}") from exc
