"""Authentication and Identity endpoints for Multi-User SentinelAI SOC Platform."""
import re
import secrets
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import or_
from sqlalchemy.orm import Session
from ...core.database import get_db
from ...models import User, LoginHistory
from ...schemas.domain import (
    RegisterRequest,
    LoginRequest,
    TokenResponse,
    UserOut,
    UserDetailOut,
    ProfileUpdateRequest,
    PasswordChangeRequest,
    ForgotPasswordRequest,
    ResetPasswordRequest,
)
from ...security.jwt import create_access_token, hash_password, verify_password
from ...services.audit import audit
from ..deps import current_user

router = APIRouter(prefix="/auth", tags=["Authentication"])

USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_\-\.]{3,64}$")


@router.post("/signup", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
def signup(payload: RegisterRequest, db: Session = Depends(get_db)):
    """Register a new user account with unique email and username validation."""
    clean_username = payload.username.strip().lower()
    clean_email = payload.email.strip().lower()

    if not USERNAME_REGEX.match(clean_username):
        raise HTTPException(
            status_code=400,
            detail="Username must be 3-64 characters and contain only letters, numbers, hyphens, underscores, or periods."
        )

    # Check for duplicate email
    if db.query(User).filter(User.email.ilike(clean_email)).first():
        raise HTTPException(status_code=409, detail="An account with this email address already exists.")

    # Check for duplicate username
    if db.query(User).filter(User.username.ilike(clean_username)).first():
        raise HTTPException(status_code=409, detail="This username is already taken. Please choose another.")

    # Safe role assignment: prevent direct privilege escalation to ADMIN on open signup
    role = "SOC_ANALYST"
    if payload.role_requested in ["SOC_ANALYST", "VIEWER"]:
        role = payload.role_requested

    user = User(
        full_name=payload.full_name.strip(),
        username=clean_username,
        email=clean_email,
        password_hash=hash_password(payload.password),
        role=role,
        is_active=True
    )
    db.add(user)
    db.flush()
    audit(db, "USER_REGISTERED", f"user:{user.id} ({user.username})", user.id)
    db.commit()
    db.refresh(user)

    token = create_access_token(user.id, user.role, extra_claims={"username": user.username, "email": user.email})
    return {"access_token": token, "user": user}


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    """Authenticate via email or username, with remember-me session persistence and audit tracking."""
    identifier = (payload.identifier or payload.email or "").strip().lower()
    if not identifier:
        raise HTTPException(status_code=400, detail="Please provide your username or email address.")

    user = db.query(User).filter(
        or_(
            User.email.ilike(identifier),
            User.username.ilike(identifier)
        )
    ).first()

    if not user or not verify_password(payload.password, user.password_hash):
        if user:
            user.failed_login_count = (user.failed_login_count or 0) + 1
        db.add(LoginHistory(email_attempted=identifier, status="FAILURE"))
        audit(db, "LOGIN_FAILED", f"identifier:{identifier}", user.id if user else None, result="FAILURE")
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid username/email or password.")

    if not user.is_active:
        audit(db, "LOGIN_DEACTIVATED_ATTEMPT", f"user:{user.id}", user.id, result="FAILURE")
        db.commit()
        raise HTTPException(
            status_code=403,
            detail="Your account has been deactivated. Please contact a SOC Administrator."
        )

    user.failed_login_count = 0
    user.last_login_at = datetime.now(timezone.utc)
    db.add(LoginHistory(user_id=user.id, email_attempted=user.email, status="SUCCESS"))
    audit(db, "LOGIN_SUCCESS", f"user:{user.id} ({user.username or user.email})", user.id)
    db.commit()

    # Determine token lifetime based on remember_me
    expires_delta = timedelta(days=30) if payload.remember_me else timedelta(hours=24)
    token = create_access_token(
        user.id,
        user.role,
        extra_claims={"username": user.username, "email": user.email},
        expires_delta=expires_delta
    )
    return {"access_token": token, "user": user}


@router.get("/me", response_model=UserDetailOut)
def me(user: User = Depends(current_user)):
    """Return the profile and role details of the currently authenticated user."""
    return user


@router.patch("/profile", response_model=UserDetailOut)
def update_profile(payload: ProfileUpdateRequest, user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Update user personal profile details and UI preferences."""
    if payload.full_name is not None and payload.full_name.strip():
        user.full_name = payload.full_name.strip()

    if payload.email is not None and payload.email.strip():
        clean_email = payload.email.strip().lower()
        if clean_email != user.email.lower():
            existing = db.query(User).filter(User.email.ilike(clean_email), User.id != user.id).first()
            if existing:
                raise HTTPException(status_code=409, detail="Email is already used by another account.")
            user.email = clean_email

    if payload.username is not None and payload.username.strip():
        clean_username = payload.username.strip().lower()
        if not USERNAME_REGEX.match(clean_username):
            raise HTTPException(status_code=400, detail="Invalid username format.")
        if clean_username != (user.username or "").lower():
            existing = db.query(User).filter(User.username.ilike(clean_username), User.id != user.id).first()
            if existing:
                raise HTTPException(status_code=409, detail="Username is already taken.")
            user.username = clean_username

    if payload.settings_json is not None:
        user.settings_json = payload.settings_json

    audit(db, "PROFILE_UPDATED", f"user:{user.id}", user.id)
    db.commit()
    db.refresh(user)
    return user


@router.post("/change-password")
def change_password(payload: PasswordChangeRequest, user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Allow an authenticated user to change their account password securely."""
    if not verify_password(payload.current_password, user.password_hash):
        raise HTTPException(status_code=400, detail="Current password does not match our records.")

    if len(payload.new_password) < 8:
        raise HTTPException(status_code=400, detail="New password must be at least 8 characters long.")

    user.password_hash = hash_password(payload.new_password)
    audit(db, "PASSWORD_CHANGED", f"user:{user.id}", user.id)
    db.commit()
    return {"status": "SUCCESS", "detail": "Password updated successfully."}


@router.post("/forgot-password")
def forgot_password(payload: ForgotPasswordRequest, db: Session = Depends(get_db)):
    """Generate a password reset token for an account identifier."""
    identifier = payload.identifier.strip().lower()
    user = db.query(User).filter(
        or_(
            User.email.ilike(identifier),
            User.username.ilike(identifier)
        )
    ).first()

    if not user:
        # Standard security practice: do not leak whether user exists, but give informative response
        return {
            "status": "PROCESSED",
            "detail": "If an account matching the provided identifier exists, a reset token has been generated.",
            "reset_token": None
        }

    reset_token = secrets.token_urlsafe(32)
    user.reset_token = reset_token
    user.reset_token_expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
    audit(db, "PASSWORD_RESET_REQUESTED", f"user:{user.id}", user.id)
    db.commit()

    return {
        "status": "PROCESSED",
        "detail": "Reset token generated successfully (valid for 1 hour).",
        "reset_token": reset_token,
        "username": user.username,
        "email": user.email
    }


@router.post("/reset-password")
def reset_password(payload: ResetPasswordRequest, db: Session = Depends(get_db)):
    """Reset password using a valid, non-expired password reset token."""
    now = datetime.now(timezone.utc)
    user = db.query(User).filter(
        User.reset_token == payload.token,
        User.reset_token_expires_at > now
    ).first()

    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired password reset token.")

    if len(payload.new_password) < 8:
        raise HTTPException(status_code=400, detail="New password must be at least 8 characters long.")

    user.password_hash = hash_password(payload.new_password)
    user.reset_token = None
    user.reset_token_expires_at = None
    user.failed_login_count = 0
    audit(db, "PASSWORD_RESET_SUCCESS", f"user:{user.id}", user.id)
    db.commit()

    return {"status": "SUCCESS", "detail": "Password has been reset successfully. You can now log in."}


@router.post("/logout")
def logout(user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Terminate the active user session and record audit trace."""
    audit(db, "LOGOUT_SUCCESS", f"user:{user.id}", user.id)
    db.commit()
    return {"status": "LOGGED_OUT", "detail": "Session terminated successfully"}
