"""API Dependencies for Authentication, Database Sessions, and RBAC."""
from typing import Callable, Sequence
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from ..core.database import get_db
from ..models import User
from ..security.jwt import decode_access_token
from ..security.rbac import Role, Permission, has_permission

security_scheme = HTTPBearer(auto_error=False)

def current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(security_scheme),
    db: Session = Depends(get_db)
) -> User:
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = decode_access_token(credentials.credentials)
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")
        user = db.get(User, user_id)
        if not user or not user.is_active:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User account is inactive or not found")
        return user
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc))

def require_roles(*allowed_roles: str) -> Callable:
    def dependency(user: User = Depends(current_user)) -> User:
        if user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Operation requires one of roles: {', '.join(allowed_roles)}. Current role: {user.role}",
            )
        return user
    return dependency

def require_permission(perm: Permission) -> Callable:
    def dependency(user: User = Depends(current_user)) -> User:
        if not has_permission(user.role, perm):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing required permission: {perm.value}",
            )
        return user
    return dependency
