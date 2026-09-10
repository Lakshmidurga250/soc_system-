"""Comprehensive Test Suite for Multi-User Authentication and Access Governance."""
import uuid
import pytest
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.core.database import Base, engine, SessionLocal, init_db
from backend.app.models import User, AuditLog
from backend.app.core.security import hash_password
from backend.app.services.detection import seed_rules


@pytest.fixture(autouse=True)
def setup_test_db():
    init_db()
    db = SessionLocal()
    try:
        seed_rules(db)
        admin = db.query(User).filter_by(email="admin@sentinelai.local").first()
        if not admin:
            db.add(User(
                full_name="SentinelAI Administrator",
                username="admin",
                email="admin@sentinelai.local",
                password_hash=hash_password("SentinelDemo!2026"),
                role="ADMIN"
            ))
        else:
            if not admin.username:
                admin.username = "admin"
        db.commit()
    finally:
        db.close()


def test_user_registration_and_validation():
    with TestClient(app) as client:
        unique_suffix = uuid.uuid4().hex[:6]
        username = f"analyst_{unique_suffix}"
        email = f"analyst_{unique_suffix}@soc.local"

        # 1. Successful user registration
        payload = {
            "full_name": "Test Analyst",
            "username": username,
            "email": email,
            "password": "StrongPassword!123",
            "role_requested": "SOC_ANALYST"
        }
        res = client.post("/api/v1/auth/signup", json=payload)
        assert res.status_code == 201, res.text
        data = res.json()
        assert "access_token" in data
        assert data["user"]["username"] == username
        assert data["user"]["email"] == email
        assert data["user"]["role"] == "SOC_ANALYST"

        # 2. Duplicate username check
        dup_user_res = client.post("/api/v1/auth/signup", json={
            "full_name": "Duplicate User",
            "username": username,
            "email": f"other_{unique_suffix}@soc.local",
            "password": "StrongPassword!123",
            "role_requested": "SOC_ANALYST"
        })
        assert dup_user_res.status_code == 409
        assert "username is already taken" in dup_user_res.text.lower()

        # 3. Duplicate email check
        dup_email_res = client.post("/api/v1/auth/signup", json={
            "full_name": "Duplicate Email",
            "username": f"other_user_{unique_suffix}",
            "email": email,
            "password": "StrongPassword!123",
            "role_requested": "SOC_ANALYST"
        })
        assert dup_email_res.status_code == 409
        assert "email address already exists" in dup_email_res.text.lower()

        # 4. Disallow self-assignment of ADMIN on open registration
        admin_attempt = client.post("/api/v1/auth/signup", json={
            "full_name": "Malicious User",
            "username": f"hacker_{unique_suffix}",
            "email": f"hacker_{unique_suffix}@soc.local",
            "password": "StrongPassword!123",
            "role_requested": "ADMIN"
        })
        assert admin_attempt.status_code == 201
        assert admin_attempt.json()["user"]["role"] == "SOC_ANALYST"


def test_dual_identifier_and_remember_me_login():
    with TestClient(app) as client:
        unique_suffix = uuid.uuid4().hex[:6]
        username = f"analyst_dual_{unique_suffix}"
        email = f"dual_{unique_suffix}@soc.local"
        password = "SecurePassword#2026"

        # Register user
        reg_res = client.post("/api/v1/auth/signup", json={
            "full_name": "Dual Login Analyst",
            "username": username,
            "email": email,
            "password": password
        })
        assert reg_res.status_code == 201

        # Login via Username
        login_by_username = client.post("/api/v1/auth/login", json={
            "identifier": username,
            "password": password,
            "remember_me": False
        })
        assert login_by_username.status_code == 200
        assert "access_token" in login_by_username.json()
        assert login_by_username.json()["user"]["username"] == username

        # Login via Email with remember_me=True
        login_by_email = client.post("/api/v1/auth/login", json={
            "identifier": email,
            "password": password,
            "remember_me": True
        })
        assert login_by_email.status_code == 200
        assert "access_token" in login_by_email.json()

        # Invalid password returns 401
        invalid_login = client.post("/api/v1/auth/login", json={
            "identifier": username,
            "password": "WrongPassword!999"
        })
        assert invalid_login.status_code == 401


def test_profile_update_and_password_change():
    with TestClient(app) as client:
        unique_suffix = uuid.uuid4().hex[:6]
        username = f"user_prof_{unique_suffix}"
        email = f"prof_{unique_suffix}@soc.local"
        password = "InitialPassword#1"

        reg_res = client.post("/api/v1/auth/signup", json={
            "full_name": "Profile Analyst",
            "username": username,
            "email": email,
            "password": password
        })
        token = reg_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Update profile
        new_name = "Updated Profile Analyst"
        new_username = f"updated_usr_{unique_suffix}"
        patch_res = client.patch("/api/v1/auth/profile", json={
            "full_name": new_name,
            "username": new_username
        }, headers=headers)
        assert patch_res.status_code == 200
        assert patch_res.json()["full_name"] == new_name
        assert patch_res.json()["username"] == new_username

        # Change password
        new_password = "BrandNewPassword#2026"
        change_res = client.post("/api/v1/auth/change-password", json={
            "current_password": password,
            "new_password": new_password
        }, headers=headers)
        assert change_res.status_code == 200

        # Login with old password should fail
        fail_old = client.post("/api/v1/auth/login", json={
            "identifier": new_username,
            "password": password
        })
        assert fail_old.status_code == 401

        # Login with new password succeeds
        pass_new = client.post("/api/v1/auth/login", json={
            "identifier": new_username,
            "password": new_password
        })
        assert pass_new.status_code == 200


def test_forgot_and_reset_password_flow():
    with TestClient(app) as client:
        unique_suffix = uuid.uuid4().hex[:6]
        username = f"forgot_usr_{unique_suffix}"
        email = f"forgot_{unique_suffix}@soc.local"
        initial_pwd = "InitialPassword#100"

        client.post("/api/v1/auth/signup", json={
            "full_name": "Forgot Pass User",
            "username": username,
            "email": email,
            "password": initial_pwd
        })

        # Request forgot password token
        forgot_res = client.post("/api/v1/auth/forgot-password", json={"identifier": username})
        assert forgot_res.status_code == 200
        reset_token = forgot_res.json().get("reset_token")
        assert reset_token is not None

        # Reset password with token
        new_pwd = "RecoveredPassword#999"
        reset_res = client.post("/api/v1/auth/reset-password", json={
            "token": reset_token,
            "new_password": new_pwd
        })
        assert reset_res.status_code == 200

        # Authenticate with newly reset password
        login_res = client.post("/api/v1/auth/login", json={
            "identifier": email,
            "password": new_pwd
        })
        assert login_res.status_code == 200


def test_admin_user_governance_and_rbac():
    with TestClient(app) as client:
        # 1. Admin login
        admin_login = client.post("/api/v1/auth/login", json={
            "identifier": "admin",
            "password": "SentinelDemo!2026"
        })
        assert admin_login.status_code == 200
        admin_token = admin_login.json()["access_token"]
        admin_headers = {"Authorization": f"Bearer {admin_token}"}

        # 2. Register a standard user
        unique_suffix = uuid.uuid4().hex[:6]
        username = f"target_usr_{unique_suffix}"
        email = f"target_{unique_suffix}@soc.local"
        user_pwd = "TargetUserPassword#1"

        reg_res = client.post("/api/v1/auth/signup", json={
            "full_name": "Target User",
            "username": username,
            "email": email,
            "password": user_pwd
        })
        user_token = reg_res.json()["access_token"]
        user_id = reg_res.json()["user"]["id"]
        user_headers = {"Authorization": f"Bearer {user_token}"}

        # 3. Standard user cannot access admin /users endpoint (403)
        forbidden_res = client.get("/api/v1/users", headers=user_headers)
        assert forbidden_res.status_code == 403

        # 4. Admin can list and search users
        list_res = client.get(f"/api/v1/users?q={username}", headers=admin_headers)
        assert list_res.status_code == 200
        items = list_res.json()
        assert len(items) >= 1
        assert items[0]["username"] == username

        # 5. Admin updates role to VIEWER
        role_res = client.patch(f"/api/v1/users/{user_id}/role", json={"role": "VIEWER"}, headers=admin_headers)
        assert role_res.status_code == 200
        assert role_res.json()["role"] == "VIEWER"

        # 6. Admin deactivates user
        status_res = client.patch(f"/api/v1/users/{user_id}/status", json={"is_active": False}, headers=admin_headers)
        assert status_res.status_code == 200
        assert status_res.json()["is_active"] is False

        # Deactivated user login rejected with 403
        deactivated_login = client.post("/api/v1/auth/login", json={
            "identifier": username,
            "password": user_pwd
        })
        assert deactivated_login.status_code == 403
        assert "deactivated" in deactivated_login.text.lower()

        # 7. Admin reactivates user
        reactivate_res = client.patch(f"/api/v1/users/{user_id}/status", json={"is_active": True}, headers=admin_headers)
        assert reactivate_res.status_code == 200
        assert reactivate_res.json()["is_active"] is True

        # 8. Admin direct password reset
        admin_reset_pwd = "AdminSetPassword#2026"
        admin_pass_res = client.post(
            f"/api/v1/users/{user_id}/admin-reset-password",
            json={"new_password": admin_reset_pwd},
            headers=admin_headers
        )
        assert admin_pass_res.status_code == 200

        # Login with admin-set password
        rel_res = client.post("/api/v1/auth/login", json={
            "identifier": username,
            "password": admin_reset_pwd
        })
        assert rel_res.status_code == 200


def test_logout_and_audit_trail():
    with TestClient(app) as client:
        # Login
        login_res = client.post("/api/v1/auth/login", json={
            "identifier": "admin",
            "password": "SentinelDemo!2026"
        })
        token = login_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Logout
        logout_res = client.post("/api/v1/auth/logout", headers=headers)
        assert logout_res.status_code == 200
        assert logout_res.json()["status"] == "LOGGED_OUT"

        # Verify audit entries
        audit_res = client.get("/api/v1/audit", headers=headers)
        assert audit_res.status_code == 200
        actions = [log["action"] for log in audit_res.json()["items"]]
        assert "LOGOUT_SUCCESS" in actions or "LOGIN_SUCCESS" in actions
