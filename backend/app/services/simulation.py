from datetime import datetime, timedelta
from random import Random
from ..models import SecurityEvent, SimulationRun

def generate(db, scenario: str, count: int, seed: int) -> SimulationRun:
    rng=Random(seed); run=SimulationRun(scenario=scenario,seed=seed,requested_count=count); db.add(run); db.flush()
    users=["alice","bob","charlie","dana"]; ips=["10.0.0.12","10.0.0.18","192.168.1.20","203.0.113.77"]
    for i in range(count):
        anomalous = scenario in ("brute_force","mixed") and (scenario=="brute_force" or i > count*.72)
        burst = scenario=="request_burst" and i > count*.55
        user=rng.choice(users); ip="203.0.113.77" if anomalous else rng.choice(ips[:3])
        status="FAILURE" if anomalous else "SUCCESS"; resource="/admin/secrets" if scenario=="sensitive_access" or (anomalous and i%7==0) else "/portal"
        e=SecurityEvent(timestamp=datetime.utcnow()-timedelta(seconds=count-i),source="simulator",source_ip=ip,username=user,hostname="demo-workstation",event_type="login" if not burst else "http_request",category="authentication" if not burst else "web",action="authenticate" if not burst else "GET",status=status,resource=resource,severity="HIGH" if anomalous else "LOW",raw_message="SYNTHETIC EVENT: generated solely for local demonstration",synthetic=True,metadata_json={"simulation_run":run.id,"scenario":scenario})
        db.add(e)
    run.generated_count=count
    return run
