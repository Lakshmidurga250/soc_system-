"""Synthetic Cybersecurity Telemetry Dataset Generator."""
from pathlib import Path
import random
import pandas as pd

DATASET_DIR = Path(__file__).resolve().parent.parent / "datasets" / "generated"

def generate_datasets():
    DATASET_DIR.mkdir(parents=True, exist_ok=True)
    rng = random.Random(42)

    users = ["admin", "alice.smith", "bob.jones", "charlie.root", "svc_backup", "dave.analyst"]
    ips = ["192.168.1.50", "192.168.1.105", "10.0.4.12", "198.51.100.44", "203.0.113.88"]
    hosts = ["CORP-DC01", "CORP-WKST04", "CORP-APP02", "CORP-DB01"]

    records = []
    for i in range(5000):
        is_attack = (rng.random() < 0.12)
        u = rng.choice(users)
        ip = "198.51.100.44" if is_attack else rng.choice(ips)
        status = "FAILURE" if is_attack else ("SUCCESS" if rng.random() > 0.05 else "FAILURE")
        sev = "CRITICAL" if is_attack and rng.random() > 0.5 else ("HIGH" if is_attack else "LOW")
        evt_type = "login" if not is_attack else rng.choice(["login", "port_probe", "process_spawn"])

        records.append({
            "timestamp": f"2026-09-10T{(i % 24):02d}:{(i % 60):02d}:00Z",
            "source_ip": ip,
            "username": u,
            "hostname": rng.choice(hosts),
            "event_type": evt_type,
            "status": status,
            "severity": sev,
            "action": "authenticate" if evt_type == "login" else "execute",
            "resource": "/admin" if is_attack else "/dashboard",
            "synthetic": True,
        })

    df = pd.DataFrame(records)
    out_csv = DATASET_DIR / "synthetic_security_telemetry.csv"
    df.to_csv(out_csv, index=False)
    print(f"[SUCCESS] Generated {len(df)} synthetic security events at: {out_csv}")

if __name__ == "__main__":
    generate_datasets()
