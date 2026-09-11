from datetime import datetime, timedelta, timezone
from .event_service import CATEGORIES
from .time_range import time_range, ScopedQueries

ATTACK="EXISTS(SELECT 1 FROM event_categories c WHERE c.event_id=e.id)"

class DashboardService:
    def __init__(self,store,events):
        self.store,self.events=store,events

    def summary(self):
        with self.store.connect() as db:
            counts={"total_requests":0,"allowed_requests":0,"blocked_requests":0,"rate_limited_requests":0,
                    "total_attacks":0,"critical_attacks":0,"high_attacks":0}
            if self.events.ready():
                row=db.execute(f"""SELECT COUNT(*) total_requests,
                    COALESCE(SUM(CASE WHEN decision='ALLOW' THEN 1 ELSE 0 END),0) allowed_requests,
                    COALESCE(SUM(CASE WHEN decision='BLOCK' THEN 1 ELSE 0 END),0) blocked_requests,
                    COALESCE(SUM(CASE WHEN decision='RATE_LIMIT' THEN 1 ELSE 0 END),0) rate_limited_requests,
                    COALESCE(SUM(CASE WHEN {ATTACK} THEN 1 ELSE 0 END),0) total_attacks,
                    COALESCE(SUM(CASE WHEN severity='CRITICAL' AND {ATTACK} THEN 1 ELSE 0 END),0) critical_attacks,
                    COALESCE(SUM(CASE WHEN severity='HIGH' AND {ATTACK} THEN 1 ELSE 0 END),0) high_attacks
                    FROM security_events e""").fetchone()
                counts.update(dict(row))
            counts["active_alerts"]=db.execute("SELECT COUNT(*) FROM security_alerts WHERE acknowledged=0").fetchone()[0]
        counts["temporary_blocks"]=sum(p["kind"]=="temporary" for p in self.store.policies())
        return counts

    def analytics(self,args=None):
        interval=time_range(args) if args else None
        categories=[{"category":c,"code":code,"name":name,"count":0,"blocked":0,"average_score":0,
                     "percentage":0,"top_ip":None,"top_path":None} for c,(code,name) in CATEGORIES.items()]
        top_ips,top_paths,severity,actions=[],[],{},{}
        if not self.events.ready():
            return dict(categories=categories,top_ips=top_ips,top_paths=top_paths,severity=severity,actions=actions)
        with self.store.connect() as db:
            if interval:db=ScopedQueries(db,*interval)
            total=db.execute(f"SELECT COUNT(*) FROM security_events e WHERE {ATTACK}").fetchone()[0]
            for item in categories:
                row=db.execute("""SELECT COUNT(*) n,COALESCE(SUM(CASE WHEN e.decision IN ('BLOCK','RATE_LIMIT') THEN 1 ELSE 0 END),0) blocked,
                    COALESCE(AVG(e.threat_score),0) average_score FROM event_categories c
                    JOIN security_events e ON e.id=c.event_id WHERE c.category=?""",(item["category"],)).fetchone()
                item.update(count=row["n"],blocked=row["blocked"],average_score=round(float(row["average_score"]),1),
                            percentage=round(row["n"]*100/total,1) if total else 0)
                for column,out in (("source_ip","top_ip"),("path","top_path")):
                    best=db.execute(f"""SELECT e.{column},COUNT(*) n FROM event_categories c JOIN security_events e
                      ON e.id=c.event_id WHERE c.category=? GROUP BY e.{column} ORDER BY n DESC LIMIT 1""",(item["category"],)).fetchone()
                    item[out]=best[0] if best else None
            for column,target in (("source_ip",top_ips),("path",top_paths)):
                rows=db.execute(f"""SELECT {column},COUNT(*) attacks,SUM(CASE WHEN decision IN ('BLOCK','RATE_LIMIT') THEN 1 ELSE 0 END) blocked,
                    MAX(timestamp) last_seen FROM security_events e WHERE {ATTACK}
                    GROUP BY {column} ORDER BY attacks DESC LIMIT 8""").fetchall()
                target.extend(dict(r) for r in rows)
            for item in top_ips:
                primary=db.execute(f"""SELECT attack_category,COUNT(*) n FROM security_events e WHERE source_ip=? AND {ATTACK}
                    GROUP BY attack_category ORDER BY n DESC LIMIT 1""",(item["source_ip"],)).fetchone()
                item["primary_category"]=primary[0] if primary else None
                policies=self.store.policy(item["source_ip"])
                item["status"]="Blacklisted" if any(p["kind"]=="blacklist" for p in policies) else "Temporarily blocked" if any(p["kind"]=="temporary" for p in policies) else "Whitelisted" if policies else "Normal"
                item.update(country=None,country_code=None,latitude=None,longitude=None)
            severity=dict(db.execute(f"SELECT severity,COUNT(*) FROM security_events e WHERE {ATTACK} GROUP BY severity").fetchall())
            actions=dict(db.execute("SELECT decision,COUNT(*) FROM security_events GROUP BY decision").fetchall())
        return dict(categories=categories,top_ips=top_ips,top_paths=top_paths,severity=severity,actions=actions)

    def timeline(self,args=None):
        start,end=time_range(args or {},default='1h')
        step=max(1,(end-start).total_seconds()/60)
        buckets={}
        if self.events.ready():
            with self.store.connect() as db:
                epoch = "EXTRACT(EPOCH FROM CAST(timestamp AS timestamptz))" if self.store.postgres else "CAST(strftime('%s',timestamp) AS INTEGER)"
                bucket = f"CAST(FLOOR(({epoch}-?)/?) AS INTEGER)" if self.store.postgres else f"CAST(({epoch}-?)/? AS INTEGER)"
                for row in db.execute(f"""SELECT {bucket} bucket,
                    SUM(CASE WHEN {ATTACK} THEN 1 ELSE 0 END) attacks,SUM(CASE WHEN decision IN ('BLOCK','RATE_LIMIT') THEN 1 ELSE 0 END) blocked,SUM(CASE WHEN decision='ALLOW' THEN 1 ELSE 0 END) allowed
                    FROM security_events e WHERE timestamp>=? AND timestamp<? GROUP BY bucket""",(start.timestamp(),step,start.isoformat(),end.isoformat())):
                    buckets[row['bucket']]=dict(row)
        return [dict(minute=(start+timedelta(seconds=i*step)).strftime('%Y-%m-%dT%H:%M'),
            **{k:buckets.get(i,{}).get(k,0) for k in ('attacks','blocked','allowed')}) for i in range(60)]
