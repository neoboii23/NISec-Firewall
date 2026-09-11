"""Offline-only, bounded source map. Coordinates are never inferred or invented."""
import ipaddress
import json
import math
import time
from pathlib import Path
from .dashboard_service import ATTACK

class GeoService:
    def __init__(self,store,events,database=None):
        self.store,self.events=store,events
        self.database=Path(database) if database else None
        if not store.postgres:
            with store.connect() as db:
                db.execute('CREATE TABLE IF NOT EXISTS geo_cache (ip TEXT PRIMARY KEY, data TEXT NOT NULL, checked_at REAL NOT NULL, version TEXT NOT NULL)')

    def locate(self,ip):
        empty=dict(country=None,country_code=None,city=None,latitude=None,longitude=None)
        try:address=ipaddress.ip_address(ip)
        except ValueError:return empty | {'location':'Invalid address'}
        if not address.is_global:return empty | {'location':'Internal / Lab Network' if address.is_private or address.is_loopback else 'Reserved / non-public address'}
        if not self.database or not self.database.is_file():return empty | {'location':'GeoIP unavailable'}
        version=str(self.database.stat().st_mtime_ns)
        with self.store.connect() as db:
            cached=db.execute('SELECT * FROM geo_cache WHERE ip=? AND version=? AND checked_at>?',(ip,version,time.time()-86400)).fetchone()
        if cached:return json.loads(cached['data'])
        try:
            import maxminddb
            with maxminddb.open_database(str(self.database)) as reader:record=reader.get(ip) or {}
            country=record.get('country',{})
            coordinates=record.get('location',{})
            lat,lon=coordinates.get('latitude'),coordinates.get('longitude')
            if not all(isinstance(v,(int,float)) and math.isfinite(v) for v in (lat,lon)) or not (-90<=lat<=90 and -180<=lon<=180):lat=lon=None
            result=dict(country=country.get('names',{}).get('en'),country_code=country.get('iso_code'),
                        city=record.get('city',{}).get('names',{}).get('en'),latitude=lat,longitude=lon)
            result['location']=result['country'] or 'Location unavailable'
        except (ImportError,OSError,ValueError):return empty | {'location':'GeoIP unavailable'}
        with self.store.connect() as db:
            db.execute('DELETE FROM geo_cache WHERE checked_at<?',(time.time()-86400,))
            db.execute('INSERT INTO geo_cache VALUES (?,?,?,?) ON CONFLICT(ip) DO UPDATE SET data=excluded.data,checked_at=excluded.checked_at,version=excluded.version',(ip,json.dumps(result),time.time(),version))
        return result

    def sources(self):
        if not self.events.ready():return []
        with self.store.connect() as db:
            rows=db.execute(f'''SELECT source_ip,COUNT(*) attempts,SUM(CASE WHEN decision IN ('BLOCK','RATE_LIMIT') THEN 1 ELSE 0 END) blocked,
                MAX(timestamp) last_seen FROM security_events e WHERE {ATTACK} GROUP BY source_ip ORDER BY attempts DESC LIMIT 100''').fetchall()
            results=[]
            for row in rows:
                last=db.execute(f'''SELECT attack_category,severity,matched_rules FROM security_events e
                    WHERE source_ip=? AND {ATTACK} ORDER BY id DESC LIMIT 1''',(row['source_ip'],)).fetchone()
                item=dict(row)|dict(last)
                try:item['matched_rules']=json.loads(item['matched_rules'] or '[]')
                except ValueError:item['matched_rules']=[]
                results.append(item)
        return [r | self.locate(r['source_ip']) for r in results]
