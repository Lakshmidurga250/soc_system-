"""Database Engine, Session, and Base Model definitions."""
from collections.abc import Generator
from sqlalchemy import create_engine, event
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from .config import settings

engine = create_engine(
    settings.database_url,
    connect_args={"check_same_thread": False},
    pool_pre_ping=True,
    echo=settings.debug,
)

# Enable SQLite foreign keys & WAL mode for performance
@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def init_db():
    """Create all tables and perform non-destructive column auto-migrations."""
    Base.metadata.create_all(engine)
    with engine.connect() as conn:
        try:
            result = conn.exec_driver_sql("PRAGMA table_info(users)")
            existing_cols = {row[1] for row in result.fetchall()}
            if existing_cols:
                if "username" not in existing_cols:
                    conn.exec_driver_sql("ALTER TABLE users ADD COLUMN username VARCHAR(64)")
                if "reset_token" not in existing_cols:
                    conn.exec_driver_sql("ALTER TABLE users ADD COLUMN reset_token VARCHAR(128)")
                if "reset_token_expires_at" not in existing_cols:
                    conn.exec_driver_sql("ALTER TABLE users ADD COLUMN reset_token_expires_at DATETIME")
                conn.commit()
        except Exception:
            pass


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
