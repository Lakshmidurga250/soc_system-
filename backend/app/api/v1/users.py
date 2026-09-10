"""Admin User Management API endpoints."""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import or_
from sqlalchemy.orm import Session
from ...core.database import get_db
from ...models import User, LoginHistory
from ...schemas.domain import UserDetailOut, UserRoleUpdate, UserStatusUpdate
from ...security.jwt import hash_password
from ...services.audit import audit
from ..deps import current_user, require_roles

router = APIRouter(prefix="/users", tags=["Admin User Management"])


@router.get("", response_model=List[UserDetailOut])
def list_users(
    q: Optional[str] = Query(None, description="Search by name, username, or email"),
    role: Optional[str] = Query(None, description="Filter by role"),
    is_active: Optional[bool] = Query(None, description="Filter by active status"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    user: User = Depends(require_roles("ADMIN")),
    db: Session = Depends(get_db)
):
    """List registered users with search, role filters, and pagination (Admin only)."""
    query = db.query(User)

    if q:
        search_pattern = f"%{q.strip()}%"
        query = query.filter(
            or_(
                User.full_name.ilike(search_pattern),
                User.username.ilike(search_pattern),
                User.email.ilike(search_pattern)
            )
        )

    if role:
        query = query.filter(User.role == role.upper())

    if is_active is not None:
        query = query.filter(User.is_active == is_active)

    users = query.order_by(User.created_at.desc()).offset(skip).limit(limit).all()
    return users


@router.get("/{user_id}", response_model=UserDetailOut)
def get_user(
    user_id: str,
    user: User = Depends(require_roles("ADMIN")),
    db: Session = Depends(get_db)
):
    """Get single user profile details by ID (Admin only)."""
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    return target


@router.patch("/{user_id}/role", response_model=UserDetailOut)
def update_user_role(
    user_id: str,
    payload: UserRoleUpdate,
    user: User = Depends(require_roles("ADMIN")),
    db: Session = Depends(get_db)
):
    """Change the role of a user (ADMIN, SOC_ANALYST, VIEWER) (Admin only)."""
    valid_roles = ["ADMIN", "SOC_ANALYST", "VIEWER"]
    role = payload.role.upper().strip()
    if role not in valid_roles:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid role. Must be one of: {', '.join(valid_roles)}"
        )

    target = db.get(User, user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    # Prevent demoting self if sole admin
    if target.id == user.id and role != "ADMIN":
        admin_count = db.query(User).filter(User.role == "ADMIN", User.is_active == True).count()
        if admin_count <= 1:
            raise HTTPException(status_code=400, detail="Cannot demote the sole active administrator account.")

    old_role = target.role
    target.role = role
    audit(db, "USER_ROLE_CHANGED", f"user:{target.id} role {old_role}->{role}", user.id)
    db.commit()
    db.refresh(target)
    return target


@router.patch("/{user_id}/status", response_model=UserDetailOut)
def update_user_status(
    user_id: str,
    payload: UserStatusUpdate,
    user: User = Depends(require_roles("ADMIN")),
    db: Session = Depends(get_db)
):
    """Activate or deactivate a user account (Admin only)."""
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    if target.id == user.id and not payload.is_active:
        raise HTTPException(status_code=400, detail="Administrators cannot deactivate their own active account.")

    old_status = target.is_active
    target.is_active = payload.is_active
    audit(
        db,
        "USER_STATUS_CHANGED",
        f"user:{target.id} active:{old_status}->{target.is_active}",
        user.id
    )
    db.commit()
    db.refresh(target)
    return target


@router.post("/{user_id}/admin-reset-password")
def admin_reset_password(
    user_id: str,
    payload: dict,
    user: User = Depends(require_roles("ADMIN")),
    db: Session = Depends(get_db)
):
    """Admin-triggered direct password reset for a user."""
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    new_password = payload.get("new_password")
    if not new_password or len(new_password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters long.")

    target.password_hash = hash_password(new_password)
    target.failed_login_count = 0
    audit(db, "ADMIN_PASSWORD_RESET", f"user:{target.id} by admin:{user.id}", user.id)
    db.commit()
    return {"status": "SUCCESS", "detail": f"Password for {target.username or target.email} has been reset."}


@router.delete("/{user_id}")
def delete_user(
    user_id: str,
    user: User = Depends(require_roles("ADMIN")),
    db: Session = Depends(get_db)
):
    """Delete a user account (Admin only)."""
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    if target.id == user.id:
        raise HTTPException(status_code=400, detail="You cannot delete your own account.")

    username_email = target.username or target.email
    db.delete(target)
    audit(db, "USER_DELETED", f"user:{user_id} ({username_email})", user.id)
    db.commit()
    return {"status": "SUCCESS", "detail": f"User {username_email} was deleted successfully."}
