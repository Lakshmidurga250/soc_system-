from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from ..core.database import get_db
from ..core.security import decode_token
from ..models import User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")
def current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    try: subject=decode_token(token).get("sub")
    except Exception: raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")
    user=db.get(User,subject)
    if not user or not user.is_active: raise HTTPException(status_code=401,detail="Account unavailable")
    return user
def require_roles(*roles: str):
    def guard(user: User = Depends(current_user)) -> User:
        if user.role not in roles: raise HTTPException(status_code=403,detail="Insufficient permission")
        return user
    return guard
