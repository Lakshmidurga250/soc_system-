from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .api.router import router
from .core.config import settings
from .core.database import Base, SessionLocal, engine
from .models import User
from .services.detection import seed_rules
from .core.security import hash_password

@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(engine)
    db=SessionLocal()
    try:
        seed_rules(db)
        if not db.query(User).filter_by(email="admin@sentinelai.local").first(): db.add(User(full_name="SentinelAI Administrator",email="admin@sentinelai.local",password_hash=hash_password("SentinelDemo!2026"),role="ADMIN"))
        db.commit()
    finally: db.close()
    yield

app=FastAPI(title="SentinelAI API",version="0.1.0",lifespan=lifespan)
app.add_middleware(CORSMiddleware,allow_origins=settings.cors_origins.split(","),allow_credentials=True,allow_methods=["*"],allow_headers=["*"])
app.include_router(router)
