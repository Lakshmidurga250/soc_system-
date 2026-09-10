"""SentinelAI Central Application Configuration."""
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent.parent
STORAGE_DIR = BASE_DIR / "storage"
ML_MODELS_DIR = BASE_DIR / "ml_models"
DATASETS_DIR = BASE_DIR / "datasets"

class Settings(BaseSettings):
    app_name: str = "SentinelAI Autonomous SOC Assistant"
    app_version: str = "1.0.0"
    environment: str = "production"
    debug: bool = False
    
    # Database
    database_url: str = f"sqlite:///{BASE_DIR}/sentinelai.db"
    
    # Security & JWT
    jwt_secret_key: str = "sentinelai_local_secret_key_2026_super_secure_enterprise"
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 1440  # 24 hours
    
    # Ingestion Limits
    upload_max_bytes: int = 100 * 1024 * 1024  # 100 MB
    max_batch_records: int = 100000
    
    # CORS
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173,http://localhost:8000,http://127.0.0.1:8000,*"
    
    # ML Models
    ml_models_dir: str = str(ML_MODELS_DIR)
    datasets_dir: str = str(DATASETS_DIR)
    
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
