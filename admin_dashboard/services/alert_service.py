class AlertService:
    def __init__(self,store):
        self.store=store

    def list(self,page=1,active=False):
        page=max(1,int(page))
        where=" WHERE acknowledged=0" if active else ""
        with self.store.connect() as db:
            total=db.execute("SELECT COUNT(*) FROM security_alerts"+where).fetchone()[0]
            rows=db.execute("SELECT * FROM security_alerts"+where+" ORDER BY id DESC LIMIT 25 OFFSET ?",((page-1)*25,)).fetchall()
        return {"items":[dict(r) for r in rows],"page":page,"pages":max(1,(total+24)//25),"total":total}

    def acknowledge(self,identifier,actor):
        self.store.acknowledge(identifier,actor)
