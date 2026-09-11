"""Bounded, parameterized reads and safe representations of the shared event data."""
import json
from datetime import datetime, timezone

CATEGORIES = {
"SQL_INJECTION":("WAF-001","SQL Injection"),"XSS":("WAF-002","Cross-Site Scripting"),
"COMMAND_INJECTION":("WAF-003","Command Injection"),"DIRECTORY_TRAVERSAL":("WAF-004","Directory Traversal"),
"BRUTE_FORCE":("WAF-005","Brute Force"),"MALICIOUS_FILE_UPLOAD":("WAF-006","Malicious File Upload")}

def safe_event(row, detail=False):
    event=dict(row)
    output={key:event.get(key) for key in ("id","incident_id","timestamp","source_ip","method","path",
        "attack_category","category_name","category_code","severity","threat_score","decision","response_status")}
    output.update(country=None,country_code=None,latitude=None,longitude=None)
    try:output['matched_rules']=json.loads(event.get('matched_rules') or '[]')
    except (ValueError,TypeError):output['matched_rules']=[]
    if detail:
        try:
            rules=json.loads(event.get("matched_rules") or "[]")
            evidence=json.loads(event.get("evidence") or "[]")
        except (ValueError,TypeError):
            rules,evidence=[],[]
        output["matched_rules"]=rules if isinstance(rules,list) else []
        allowed={"rule_id","field","reason","file_size","limit","failed_attempt_count","time_window","block_duration","retry_after"}
        output["evidence"]=[{k:v for k,v in item.items() if k in allowed} for item in evidence if isinstance(item,dict)] if isinstance(evidence,list) else []
        output["user_agent"]="[omitted by WAF privacy policy]"
    return output

class EventService:
    def __init__(self,store):
        self.store=store

    def ready(self):
        if self.store.postgres:
            return True
        with self.store.connect() as db:
            return bool(db.execute("SELECT 1 FROM sqlite_master WHERE name='security_events'").fetchone())

    def filters(self, args):
        clauses,values=[],[]
        for key,column in (("source_ip","e.source_ip"),("category","e.attack_category"),("severity","e.severity"),
                           ("action","e.decision"),("method","e.method")):
            value=args.get(key,"").strip()
            if value:
                if len(value)>100:
                    raise ValueError("Filter is too long")
                if key=="category" and value in CATEGORIES:
                    clauses.append("EXISTS(SELECT 1 FROM event_categories ec WHERE ec.event_id=e.id AND ec.category=?)")
                else:
                    clauses.append(column+"=?")
                values.append(value)
        for key,column in (("incident_id","e.incident_id"),("path","e.path")):
            value=args.get(key,"").strip()
            if value:
                if len(value)>250:
                    raise ValueError("Filter is too long")
                clauses.append(column+" LIKE ? ESCAPE '\\'")
                values.append("%"+value.replace("\\","\\\\").replace("%","\\%").replace("_","\\_")+"%")
        if args.get('rule'):
            if len(args['rule'])>100:raise ValueError('Rule filter is too long')
            if self.store.postgres:
                clauses.append("EXISTS(SELECT 1 FROM jsonb_array_elements_text(COALESCE(e.matched_rules,'[]')::jsonb) rules(value) WHERE rules.value=?)")
            else:
                clauses.append("EXISTS(SELECT 1 FROM json_each(CASE WHEN json_valid(e.matched_rules) THEN e.matched_rules ELSE '[]' END) rules WHERE rules.value=?)")
            values.append(args['rule'])
        for key,operator in (("start",">="),("end","<=")):
            if args.get(key):
                try:
                    value=datetime.fromisoformat(args[key].replace("Z","+00:00"))
                    value=value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
                except ValueError:
                    raise ValueError("Use an ISO date/time")
                clauses.append("e.timestamp"+operator+"?")
                values.append(value.isoformat())
        return (" WHERE "+" AND ".join(clauses) if clauses else ""),values

    def list(self,args,limit=25):
        page=max(1,int(args.get("page",1)))
        if page>1000000:
            raise ValueError("Page out of range")
        if not self.ready():
            return {"items":[],"page":page,"pages":1,"total":0}
        where,values=self.filters(args)
        with self.store.connect() as db:
            count=db.execute("SELECT COUNT(*) FROM security_events e"+where,values).fetchone()[0]
            rows=db.execute("SELECT e.* FROM security_events e"+where+" ORDER BY e.id DESC LIMIT ? OFFSET ?",
                            (*values,limit,(page-1)*limit)).fetchall()
        return {"items":[safe_event(r) for r in rows],"page":page,"pages":max(1,(count+limit-1)//limit),"total":count}

    def detail(self,incident):
        if not self.ready():
            return None
        with self.store.connect() as db:
            row=db.execute("SELECT * FROM security_events WHERE incident_id=? ORDER BY id DESC LIMIT 1",(incident,)).fetchone()
            if not row:
                return None
            result=safe_event(row,True)
            alert=db.execute("SELECT id,acknowledged FROM security_alerts WHERE event_id=?",(row["id"],)).fetchone()
            result["alert"]=dict(alert) if alert else None
            result['ip_policies']=self.store.policy(row['source_ip'])
            return result

    def export(self,args):
        """Page export reads in small transactions. Bounded to 10,000 rows per export."""
        where,values=self.filters(args)
        if not self.ready():
            return []
        with self.store.connect() as db:
            rows=db.execute("SELECT e.* FROM security_events e"+where+" ORDER BY e.id DESC LIMIT 10000",values).fetchall()
        return [safe_event(row) for row in rows]
