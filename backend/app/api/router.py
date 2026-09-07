from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select, desc
from sqlalchemy.orm import Session
from ..core.database import get_db
from ..core.security import create_token, hash_password, verify_password
from ..models import Alert, ApprovalRequest, AuditLog, DetectionRule, Incident, Investigation, ResponseAction, SecurityEvent, ThreatIndicator, User
from ..schemas.domain import *
from ..services.audit import audit
from ..services.detection import run_rules
from ..services.simulation import generate
from .deps import current_user, require_roles

router=APIRouter(prefix="/api/v1")

@router.post("/auth/signup",response_model=TokenResponse)
def signup(payload:RegisterRequest,db:Session=Depends(get_db)):
    if db.scalar(select(User).where(User.email==str(payload.email))): raise HTTPException(409,"Email already registered")
    user=User(full_name=payload.full_name,email=str(payload.email),password_hash=hash_password(payload.password)); db.add(user); db.flush(); audit(db,"USER_REGISTERED",f"user:{user.id}",user.id); db.commit(); db.refresh(user)
    return {"access_token":create_token(user.id,user.role),"user":user}
@router.post("/auth/login",response_model=TokenResponse)
def login(payload:LoginRequest,db:Session=Depends(get_db)):
    user=db.scalar(select(User).where(User.email==str(payload.email)))
    if not user or not verify_password(payload.password,user.password_hash):
        if user: user.failed_login_count+=1; audit(db,"LOGIN",f"email:{payload.email}",user.id,"FAILED"); db.commit()
        raise HTTPException(401,"Incorrect email or password")
    user.failed_login_count=0; user.last_login_at=datetime.utcnow(); audit(db,"LOGIN",f"user:{user.id}",user.id); db.commit()
    return {"access_token":create_token(user.id,user.role),"user":user}
@router.get("/auth/me",response_model=UserOut)
def me(user:User=Depends(current_user)): return user

@router.get("/dashboard")
def dashboard(db:Session=Depends(get_db),user:User=Depends(current_user)):
    count=lambda q: db.scalar(q) or 0
    events=count(select(func.count()).select_from(SecurityEvent)); alerts=count(select(func.count()).select_from(Alert).where(Alert.status.not_in(["RESOLVED","FALSE_POSITIVE","CLOSED"]))); incidents=count(select(func.count()).select_from(Incident).where(Incident.status=="OPEN"))
    by_severity=dict(db.execute(select(Alert.severity,func.count()).group_by(Alert.severity)).all())
    by_status=dict(db.execute(select(Incident.status,func.count()).group_by(Incident.status)).all())
    return {"kpis":{"total_events":events,"active_alerts":alerts,"open_incidents":incidents,"critical_incidents":count(select(func.count()).select_from(Incident).where(Incident.severity=="CRITICAL")),"anomalies_detected":count(select(func.count()).select_from(Alert).where(Alert.detection_method=="ML")),"investigations_running":count(select(func.count()).select_from(Investigation).where(Investigation.status=="RUNNING"))},"alerts_by_severity":by_severity,"incidents_by_status":by_status,"recent_alerts":[{"id":a.id,"title":a.title,"severity":a.severity,"created_at":a.created_at} for a in db.scalars(select(Alert).order_by(desc(Alert.created_at)).limit(10))]}

@router.post("/events",response_model=EventOut)
def create_event(payload:EventCreate,db:Session=Depends(get_db),user:User=Depends(current_user)):
    event=SecurityEvent(**payload.model_dump(exclude={"timestamp"}),timestamp=payload.timestamp or datetime.utcnow()); db.add(event); db.flush(); alerts=run_rules(db,event); audit(db,"EVENT_INGESTED",f"event:{event.id}",user.id,alerts_created=len(alerts)); db.commit(); db.refresh(event); return event
@router.get("/events")
def list_events(page:int=1,page_size:int=50,severity:str|None=None,q:str|None=None,db:Session=Depends(get_db),user:User=Depends(current_user)):
    stmt=select(SecurityEvent); count_stmt=select(func.count()).select_from(SecurityEvent)
    if severity: stmt=stmt.where(SecurityEvent.severity==severity.upper()); count_stmt=count_stmt.where(SecurityEvent.severity==severity.upper())
    if q: stmt=stmt.where(SecurityEvent.raw_message.contains(q) | SecurityEvent.source_ip.contains(q) | SecurityEvent.username.contains(q)); count_stmt=count_stmt.where(SecurityEvent.raw_message.contains(q) | SecurityEvent.source_ip.contains(q) | SecurityEvent.username.contains(q))
    total=db.scalar(count_stmt) or 0; items=db.scalars(stmt.order_by(desc(SecurityEvent.timestamp)).offset((page-1)*min(page_size,100)).limit(min(page_size,100))).all(); return {"items":[EventOut.model_validate(x).model_dump() for x in items],"total":total,"page":page,"page_size":min(page_size,100)}

@router.get("/alerts")
def list_alerts(page:int=1,status:str|None=None,db:Session=Depends(get_db),user:User=Depends(current_user)):
    stmt=select(Alert); stmt=stmt.where(Alert.status==status) if status else stmt; items=db.scalars(stmt.order_by(desc(Alert.created_at)).offset((page-1)*50).limit(50)).all(); return {"items":[{"id":x.id,"title":x.title,"severity":x.severity,"risk_score":x.risk_score,"confidence_score":x.confidence_score,"status":x.status,"created_at":x.created_at,"explanation":x.explanation} for x in items]}
@router.patch("/alerts/{alert_id}")
def update_alert(alert_id:str,payload:StatusUpdate,db:Session=Depends(get_db),user:User=Depends(current_user)):
    alert=db.get(Alert,alert_id)
    if not alert: raise HTTPException(404,"Alert not found")
    alert.status=payload.status; alert.notes.append({"author":user.id,"note":payload.note,"at":datetime.utcnow().isoformat()}); audit(db,"ALERT_UPDATED",f"alert:{alert.id}",user.id,status=payload.status); db.commit(); return {"id":alert.id,"status":alert.status}

@router.post("/incidents/from-alert/{alert_id}")
def create_incident(alert_id:str,db:Session=Depends(get_db),user:User=Depends(current_user)):
    alert=db.get(Alert,alert_id)
    if not alert: raise HTTPException(404,"Alert not found")
    incident=Incident(title=f"Incident: {alert.title}",description=alert.description,severity=alert.severity,risk_score=alert.risk_score,confidence=alert.confidence_score,alert_ids=[alert.id]); db.add(incident); alert.status="ESCALATED"; audit(db,"INCIDENT_CREATED",f"incident:{incident.id}",user.id,alert_id=alert.id); db.commit(); return {"id":incident.id,"status":incident.status}
@router.get("/incidents")
def list_incidents(db:Session=Depends(get_db),user:User=Depends(current_user)):
    return {"items":[{"id":x.id,"title":x.title,"severity":x.severity,"risk_score":x.risk_score,"status":x.status,"created_at":x.created_at} for x in db.scalars(select(Incident).order_by(desc(Incident.created_at))).all()]}
@router.post("/incidents/{incident_id}/investigate")
def investigate(incident_id:str,db:Session=Depends(get_db),user:User=Depends(current_user)):
    incident=db.get(Incident,incident_id)
    if not incident: raise HTTPException(404,"Incident not found")
    alerts=[db.get(Alert,i) for i in incident.alert_ids]; ids={eid for a in alerts if a for eid in a.event_ids}; roots=[db.get(SecurityEvent,i) for i in ids]; entities={v for e in roots if e for v in (e.source_ip,e.username,e.hostname) if v}
    candidates=db.scalars(select(SecurityEvent).order_by(desc(SecurityEvent.timestamp)).limit(1000)).all()
    ranked=[]
    for e in candidates:
        relevance=sum(1 for v in (e.source_ip,e.username,e.hostname) if v in entities)*30 + (20 if e.id in ids else 0) + {"CRITICAL":20,"HIGH":15,"MEDIUM":8}.get(e.severity,2)
        if relevance: ranked.append((relevance,e))
    ranked.sort(key=lambda x:x[0],reverse=True); selected=ranked[:200]
    investigation=Investigation(incident_id=incident.id,status="COMPLETED",summary=f"Investigated {len(candidates)} candidates around {len(entities)} incident entities; selected {len(selected)} relevant evidence items.",evidence=[{"event_id":e.id,"timestamp":e.timestamp.isoformat(),"event_type":e.event_type,"source_ip":e.source_ip,"relevance":s} for s,e in selected],timeline=[{"at":e.timestamp.isoformat(),"event_id":e.id,"description":f"{e.event_type} from {e.source_ip}"} for s,e in selected],statistics={"candidate_events":len(candidates),"selected_evidence":len(selected),"reduction_ratio":round(1-len(selected)/max(1,len(candidates)),3)})
    db.add(investigation); incident.status="INVESTIGATING"; audit(db,"INVESTIGATION_COMPLETED",f"incident:{incident.id}",user.id,selected=len(selected)); db.commit(); return {"id":investigation.id,"summary":investigation.summary,"statistics":investigation.statistics}
@router.get("/investigations/{investigation_id}")
def get_investigation(investigation_id:str,db:Session=Depends(get_db),user:User=Depends(current_user)):
    item=db.get(Investigation,investigation_id)
    if not item: raise HTTPException(404,"Investigation not found")
    return {"id":item.id,"status":item.status,"summary":item.summary,"evidence":item.evidence,"timeline":item.timeline,"statistics":item.statistics}

@router.get("/detection/rules")
def rules(db:Session=Depends(get_db),user:User=Depends(current_user)): return {"items":[{"id":x.id,"name":x.name,"description":x.description,"config":x.config,"severity":x.severity,"enabled":x.enabled,"execution_count":x.execution_count,"match_count":x.match_count} for x in db.scalars(select(DetectionRule)).all()]}
@router.post("/detection/rules")
def create_rule(payload:RuleCreate,db:Session=Depends(get_db),user:User=Depends(require_roles("ADMIN","SOC_ANALYST"))):
    item=DetectionRule(**payload.model_dump()); db.add(item); audit(db,"RULE_CREATED",f"rule:{item.id}",user.id); db.commit(); return {"id":item.id}
@router.patch("/detection/rules/{rule_id}")
def patch_rule(rule_id:str,payload:RuleCreate,db:Session=Depends(get_db),user:User=Depends(require_roles("ADMIN","SOC_ANALYST"))):
    item=db.get(DetectionRule,rule_id)
    if not item: raise HTTPException(404,"Rule not found")
    for key,value in payload.model_dump().items(): setattr(item,key,value)
    audit(db,"RULE_UPDATED",f"rule:{item.id}",user.id); db.commit(); return {"id":item.id}

@router.get("/intelligence/indicators")
def indicators(db:Session=Depends(get_db),user:User=Depends(current_user)): return {"items":[{"id":x.id,"indicator":x.indicator,"indicator_type":x.indicator_type,"risk_level":x.risk_level,"description":x.description,"status":x.status} for x in db.scalars(select(ThreatIndicator).order_by(desc(ThreatIndicator.created_at))).all()]}
@router.post("/intelligence/indicators")
def indicator(payload:IndicatorCreate,db:Session=Depends(get_db),user:User=Depends(require_roles("ADMIN","SOC_ANALYST"))):
    if db.scalar(select(ThreatIndicator).where(ThreatIndicator.indicator==payload.indicator)): raise HTTPException(409,"Indicator already exists")
    item=ThreatIndicator(**payload.model_dump()); db.add(item); audit(db,"INDICATOR_CREATED",f"indicator:{item.id}",user.id); db.commit(); return {"id":item.id}

@router.post("/response/actions")
def response(payload:ResponseRequest,db:Session=Depends(get_db),user:User=Depends(require_roles("ADMIN","SOC_ANALYST"))):
    action=ResponseAction(incident_id=payload.incident_id,action_type=payload.action_type,mode=payload.mode,payload=payload.payload,status="PENDING" if payload.mode=="APPROVAL_REQUIRED" else "EXECUTED",executed_by=user.id if payload.mode!="APPROVAL_REQUIRED" else None); db.add(action); db.flush(); result={"id":action.id,"status":action.status}
    if payload.mode=="APPROVAL_REQUIRED": request=ApprovalRequest(response_action_id=action.id,reason=payload.reason); db.add(request); result["approval_id"]=request.id
    audit(db,"RESPONSE_REQUESTED",f"action:{action.id}",user.id,mode=payload.mode); db.commit(); return result
@router.get("/approvals")
def approvals(db:Session=Depends(get_db),user:User=Depends(current_user)): return {"items":[{"id":x.id,"response_action_id":x.response_action_id,"reason":x.reason,"status":x.status,"created_at":x.created_at} for x in db.scalars(select(ApprovalRequest).where(ApprovalRequest.status=="PENDING")).all()]}
@router.post("/approvals/{approval_id}/decision")
def decide(approval_id:str,payload:ApprovalDecision,db:Session=Depends(get_db),user:User=Depends(require_roles("ADMIN","SOC_ANALYST"))):
    req=db.get(ApprovalRequest,approval_id)
    if not req or req.status!="PENDING": raise HTTPException(404,"Pending approval not found")
    req.status="APPROVED" if payload.approved else "REJECTED"; req.decision_by=user.id; req.decision_note=payload.note; action=db.get(ResponseAction,req.response_action_id); action.status="EXECUTED" if payload.approved else "REJECTED"; action.executed_by=user.id if payload.approved else None; audit(db,"APPROVAL_DECISION",f"approval:{req.id}",user.id,decision=req.status); db.commit(); return {"status":req.status}

@router.post("/simulation/run")
def simulate(payload:SimulationRequest,db:Session=Depends(get_db),user:User=Depends(require_roles("ADMIN","SOC_ANALYST"))):
    run=generate(db,payload.scenario,payload.count,payload.seed); db.flush(); events=db.scalars(select(SecurityEvent).where(SecurityEvent.metadata_json["simulation_run"].as_string()==run.id)).all()
    alerts=[]
    for event in events: alerts.extend(run_rules(db,event))
    audit(db,"SIMULATION_RUN",f"simulation:{run.id}",user.id,events=run.generated_count,alerts=len(alerts)); db.commit(); return {"id":run.id,"generated":run.generated_count,"alerts_created":len(alerts),"synthetic":True}
@router.get("/audit")
def audit_log(db:Session=Depends(get_db),user:User=Depends(require_roles("ADMIN","SOC_ANALYST"))): return {"items":[{"id":x.id,"action":x.action,"resource":x.resource,"result":x.result,"timestamp":x.timestamp,"metadata":x.metadata_json} for x in db.scalars(select(AuditLog).order_by(desc(AuditLog.timestamp)).limit(250)).all()]}
@router.get("/health")
def health(db:Session=Depends(get_db)): db.execute(select(func.count()).select_from(User)); return {"status":"healthy","components":{"backend":"healthy","database":"healthy","detection_engine":"healthy","ml_engine":"not_trained","simulation":"ready"}}
