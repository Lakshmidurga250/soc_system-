"""Simulation Lab Engine for generating safe, synthetic multi-scenario telemetry."""
from datetime import datetime, timedelta, timezone
import random
from typing import List
from sqlalchemy.orm import Session
from ..models import SecurityEvent, SimulationRun
from .detection_engine import detection_engine
from .feature_engine import feature_engine

USERS = ["admin", "alice.smith", "bob.jones", "charlie.root", "svc_backup", "dave.analyst", "eva.dev"]
INTERNAL_IPS = ["10.0.4.12", "10.0.4.15", "10.0.8.22", "192.168.1.50", "192.168.1.105"]
ATTACKER_IPS = ["198.51.100.44", "203.0.113.88", "192.0.2.199", "185.220.101.5"]
HOSTS = ["CORP-DC01", "CORP-WKST04", "CORP-APP02", "CORP-DB01", "CORP-WEB01"]

class SimulationEngine:
    def run_scenario(self, db: Session, scenario: str = "brute_force", count: int = 25, seed: int = 42) -> SimulationRun:
        rng = random.Random(seed)
        run = SimulationRun(scenario=scenario, seed=seed, requested_count=count)
        db.add(run)
        db.flush()

        events: List[SecurityEvent] = []
        base_time = datetime.now(timezone.utc) - timedelta(seconds=count * 3)

        attacker_ip = rng.choice(ATTACKER_IPS)
        target_user = rng.choice(USERS)
        target_host = rng.choice(HOSTS)

        for i in range(count):
            t = base_time + timedelta(seconds=i * 2)

            if scenario == "brute_force":
                is_last = (i == count - 1)
                evt = SecurityEvent(
                    timestamp=t,
                    source="simulation_lab",
                    source_ip=attacker_ip,
                    destination_ip=rng.choice(INTERNAL_IPS),
                    username=target_user,
                    hostname=target_host,
                    event_type="login",
                    category="authentication",
                    action="authenticate",
                    status="SUCCESS" if is_last else "FAILURE",
                    resource="/auth/login",
                    severity="HIGH" if not is_last else "CRITICAL",
                    raw_message=f"SIMULATED: Failed password authentication attempt #{i+1} for user '{target_user}' from {attacker_ip}",
                    synthetic=True,
                    metadata_json={"simulation_run": run.id, "scenario": scenario, "iteration": i + 1},
                )
            elif scenario == "port_scan":
                port_num = 20 + (i * 7) % 1000
                evt = SecurityEvent(
                    timestamp=t,
                    source="simulation_lab",
                    source_ip=attacker_ip,
                    destination_ip=rng.choice(INTERNAL_IPS),
                    hostname=target_host,
                    event_type="firewall_drop",
                    category="network",
                    action="DROP",
                    status="FAILURE",
                    port=port_num,
                    protocol="TCP",
                    severity="HIGH",
                    raw_message=f"SIMULATED: Firewall dropped incoming probe to port {port_num} from {attacker_ip}",
                    synthetic=True,
                    metadata_json={"simulation_run": run.id, "scenario": scenario},
                )
            elif scenario == "privilege_escalation":
                evt = SecurityEvent(
                    timestamp=t,
                    source="simulation_lab",
                    source_ip=rng.choice(INTERNAL_IPS),
                    username=target_user,
                    hostname=target_host,
                    event_type="process_spawn",
                    category="process_execution",
                    action="execute",
                    status="SUCCESS",
                    resource="powershell.exe -enc SW52b2tlLU1pbWlrYXR6",
                    severity="CRITICAL",
                    raw_message=f"SIMULATED: Elevated command interpreter spawned by '{target_user}' on {target_host}",
                    synthetic=True,
                    metadata_json={"simulation_run": run.id, "scenario": scenario},
                )
            else:  # mixed
                is_attack = (i % 4 == 0)
                evt = SecurityEvent(
                    timestamp=t,
                    source="simulation_lab",
                    source_ip=attacker_ip if is_attack else rng.choice(INTERNAL_IPS),
                    username=target_user if is_attack else rng.choice(USERS),
                    hostname=target_host,
                    event_type="http_get" if is_attack else "login",
                    category="web" if is_attack else "authentication",
                    action="GET" if is_attack else "authenticate",
                    status="FAILURE" if is_attack else "SUCCESS",
                    resource="/admin/secrets" if is_attack else "/dashboard",
                    severity="HIGH" if is_attack else "LOW",
                    raw_message=f"SIMULATED: Telemetry event ({scenario})",
                    synthetic=True,
                    metadata_json={"simulation_run": run.id, "scenario": scenario},
                )

            db.add(evt)
            events.append(evt)

        db.flush()
        run.generated_count = len(events)

        # Run feature extraction and rule detection
        for evt in events:
            feature_engine.extract_features(db, evt)
            detection_engine.evaluate_event(db, evt)

        return run

simulation_engine = SimulationEngine()
