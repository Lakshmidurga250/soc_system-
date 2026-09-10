from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from .api.router import router
from .core.config import settings
from .core.database import Base, SessionLocal, engine
from .models import User
from .services.detection import seed_rules
from .core.security import hash_password

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(engine)
    
    # Auto-migrate SQLite columns if table already existed without new auth fields
    with engine.connect() as conn:
        try:
            result = conn.exec_driver_sql("PRAGMA table_info(users)")
            existing_cols = {row[1] for row in result.fetchall()}
            if "username" not in existing_cols:
                conn.exec_driver_sql("ALTER TABLE users ADD COLUMN username VARCHAR(64)")
            if "reset_token" not in existing_cols:
                conn.exec_driver_sql("ALTER TABLE users ADD COLUMN reset_token VARCHAR(128)")
            if "reset_token_expires_at" not in existing_cols:
                conn.exec_driver_sql("ALTER TABLE users ADD COLUMN reset_token_expires_at DATETIME")
            conn.commit()
        except Exception:
            pass

    db = SessionLocal()
    try:
        seed_rules(db)
        admin_user = db.query(User).filter_by(email="admin@sentinelai.local").first()
        if not admin_user:
            db.add(User(
                full_name="SentinelAI Administrator",
                username="admin",
                email="admin@sentinelai.local",
                password_hash=hash_password("SentinelDemo!2026"),
                role="ADMIN"
            ))
        else:
            if not admin_user.username:
                admin_user.username = "admin"
        db.commit()
    finally:
        db.close()
    yield

app = FastAPI(title="SentinelAI API", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins.split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(router)

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

@app.get("/", response_class=HTMLResponse, tags=["Operations Control Center"])
@app.get("/dashboard", response_class=HTMLResponse, tags=["Operations Control Center"])
def get_soc_workspace():
    index_path = STATIC_DIR / "index.html"
    if index_path.exists():
        with open(index_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h1>SentinelAI SOC Platform</h1><p>API online at /api/v1</p>")
