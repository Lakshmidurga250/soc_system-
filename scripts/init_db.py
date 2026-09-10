"""Database Initialization Script."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.app.core.database import Base, engine, SessionLocal
from backend.app.models import User, DetectionRule, ThreatIndicator
from backend.app.security.jwt import hash_password
from backend.app.engines.detection_engine import seed_default_rules

def init_database():
    print("[INFO] Creating database tables with SQLite WAL mode...")
    Base.metadata.create_all(bind=engine)
    print("[SUCCESS] All tables created successfully.")

    db = SessionLocal()
    try:
        # Seed default admin
        admin = db.query(User).filter_by(email="admin@sentinelai.local").first()
        if not admin:
            admin = User(
                full_name="SentinelAI Lead Administrator",
                email="admin@sentinelai.local",
                password_hash=hash_password("SentinelDemo!2026"),
                role="ADMIN",
                is_active=True,
            )
            db.add(admin)
            print("[INFO] Seeded default administrator account: admin@sentinelai.local")

        # Seed detection rules
        seed_default_rules(db)
        print("[INFO] Seeded default detection rules.")

        # Seed initial threat indicators
        if not db.query(ThreatIndicator).first():
            iocs = [
                ThreatIndicator(indicator="198.51.100.44", indicator_type="IP", risk_level="HIGH", description="Known Brute-Force Origin Scanner", source="Local Threat Feed"),
                ThreatIndicator(indicator="203.0.113.88", indicator_type="IP", risk_level="CRITICAL", description="Cobalt Strike C2 Node", source="Local Threat Feed"),
                ThreatIndicator(indicator="malicious-payload.xyz", indicator_type="DOMAIN", risk_level="HIGH", description="Credential Phishing Domain", source="Local Threat Feed"),
            ]
            db.add_all(iocs)
            print("[INFO] Seeded default Threat Indicators.")

        db.commit()
    finally:
        db.close()

    print("[SUCCESS] Database initialization completed.")

if __name__ == "__main__":
    init_database()
