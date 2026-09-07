from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "SentinelAI"
    database_url: str = "sqlite:///./database/sentinelai.db"
    jwt_secret: str = "change-this-local-development-secret-before-deployment"
    jwt_algorithm: str = "HS256"
    access_token_minutes: int = 480
    upload_max_bytes: int = 10 * 1024 * 1024
    cors_origins: str = "http://localhost:5173"
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    def ensure_paths(self) -> None:
        Path("database").mkdir(exist_ok=True)
        Path("ml_models").mkdir(exist_ok=True)


settings = Settings()
