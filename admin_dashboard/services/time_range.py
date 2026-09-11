from datetime import datetime,timedelta,timezone

def time_range(args,default='24h'):
    period=args.get('period',default)
    end=datetime.now(timezone.utc).replace(second=0,microsecond=0)+timedelta(minutes=1)
    if period in ('1h','24h','7d','30d'):
        return end-timedelta(hours={'1h':1,'24h':24,'7d':168,'30d':720}[period]),end
    if period!='custom':raise ValueError('Unknown time period')
    def parse(key):
        try:
            value=datetime.fromisoformat(args.get(key,'').replace('Z','+00:00'))
            return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
        except ValueError:raise ValueError('Custom range requires ISO start and end')
    start,end=parse('start'),parse('end')
    if not timedelta(0)<end-start<=timedelta(days=31):raise ValueError('Range must be positive and at most 31 days')
    return start,end

class ScopedQueries:
    def __init__(self,db,start,end):self.db,self.start,self.end=db,start,end
    def execute(self,sql,values=()):
        return self.db.execute('WITH filtered_events AS (SELECT * FROM security_events WHERE timestamp>=? AND timestamp<?) '+
            sql.replace('security_events','filtered_events'),(self.start.isoformat(),self.end.isoformat(),*values))
