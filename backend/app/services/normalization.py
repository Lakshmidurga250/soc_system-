from datetime import datetime, timezone
from typing import Any
from ..parsers.base_parser import ParsedRecord, ParserError

ALIASES={"source_ip":("source_ip","src_ip","ip","client_ip","remote_addr"),"destination_ip":("destination_ip","dst_ip","server_ip"),"username":("username","user","account","user_name"),"hostname":("hostname","host","computer","device"),"event_type":("event_type","type","event","activity"),"category":("category","log_type","event_category"),"status":("status","outcome","result"),"resource":("resource","path","url","target"),"timestamp":("timestamp","time","date","event_time"),"raw_message":("raw_message","message","raw","description")}
VALID_SEVERITIES={"LOW","MEDIUM","HIGH","CRITICAL"}
def _value(raw:dict,field:str,default:Any=None):
    for key in ALIASES.get(field,(field,)):
        value=raw.get(key)
        if value not in (None,""): return value
    return raw.get(field,default)
def _timestamp(value:Any)->datetime:
    if not value: return datetime.now(timezone.utc).replace(tzinfo=None)
    if isinstance(value,datetime): return value.replace(tzinfo=None)
    try: return datetime.fromisoformat(str(value).replace("Z","+00:00")).replace(tzinfo=None)
    except ValueError: raise ParserError(f"Invalid timestamp: {value}")
def normalize(record:ParsedRecord,source:str) -> dict:
    raw=record.values; event_type=str(_value(raw,"event_type","")).strip()
    if not event_type: raise ParserError("Missing required field: event_type (or type/event/activity)")
    severity=str(raw.get("severity","LOW")).upper()
    if severity not in VALID_SEVERITIES: severity="LOW"
    known={name for aliases in ALIASES.values() for name in aliases}|{"action","protocol","port","user_agent","device_id","severity","event_id"}
    try: port=int(raw["port"]) if raw.get("port") not in (None,"") else None
    except (ValueError,TypeError): raise ParserError("port must be a whole number")
    return {"timestamp":_timestamp(_value(raw,"timestamp")),"source":source,"source_ip":str(_value(raw,"source_ip","")) or None,"destination_ip":str(_value(raw,"destination_ip","")) or None,"username":str(_value(raw,"username","")) or None,"hostname":str(_value(raw,"hostname","")) or None,"device_id":raw.get("device_id"),"event_type":event_type,"category":str(_value(raw,"category","uncategorized")),"action":raw.get("action"),"status":str(_value(raw,"status","")) or None,"resource":str(_value(raw,"resource","")) or None,"protocol":raw.get("protocol"),"port":port,"user_agent":raw.get("user_agent"),"severity":severity,"raw_message":str(_value(raw,"raw_message","")) or None,"metadata_json":{"ingestion_row":record.row_number,"unmapped":{str(k):v for k,v in raw.items() if k not in known}}}
