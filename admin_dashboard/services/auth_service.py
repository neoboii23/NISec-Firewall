import time
from werkzeug.security import generate_password_hash, check_password_hash

class AuthService:
    def __init__(self, store):
        self.store = store
        self.dummy = generate_password_hash("unused authentication fallback")

    def provision(self, username, password, role='ADMIN'):
        if not username or len(username)>80 or len(password)<12:
            raise ValueError("Choose a username and a password of at least 12 characters")
        if role not in ('ADMIN','VIEWER'):raise ValueError('Unsupported role')
        with self.store.connect() as db:
            db.execute("INSERT INTO dashboard_admins(username,password_hash,role) VALUES (?,?,?) ON CONFLICT DO NOTHING",(username,generate_password_hash(password),role))

    def authenticate(self, ip, username, password):
        now=time.time()
        with self.store.connect() as db:
            db.execute("DELETE FROM admin_login_limits WHERE window_start<? AND until<?",(now-300,now))
            rate=db.execute("SELECT * FROM admin_login_limits WHERE ip=?",(ip,)).fetchone()
            if rate and rate["until"]>now:
                return False
            user=db.execute("SELECT password_hash FROM dashboard_admins WHERE username=?",(username,)).fetchone()
        valid=check_password_hash(user[0] if user else self.dummy,password)
        with self.store.connect() as db:
            if user and valid:
                db.execute("DELETE FROM admin_login_limits WHERE ip=?",(ip,))
                self.store.audit(db,username,'login','dashboard')
                return True
            count=rate["failures"]+1 if rate and now-rate["window_start"]<300 else 1
            start=rate["window_start"] if rate and now-rate["window_start"]<300 else now
            db.execute("INSERT INTO admin_login_limits VALUES (?,?,?,?) ON CONFLICT(ip) DO UPDATE SET failures=excluded.failures,window_start=excluded.window_start,until=excluded.until",(ip,count,start,now+300 if count>=5 else 0))
        return False

    def role(self,username):
        with self.store.connect() as db:
            row=db.execute('SELECT role FROM dashboard_admins WHERE username=?',(username,)).fetchone()
            return row[0] if row else None

    def exists(self, username):
        with self.store.connect() as db:
            return bool(db.execute("SELECT 1 FROM dashboard_admins WHERE username=?",(username,)).fetchone())
