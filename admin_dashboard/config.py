import os
from pathlib import Path
from datetime import timedelta
from waf.management.settings import database_url

ROOT = Path(__file__).resolve().parents[1]

class Config:
    DATABASE_PATH = Path(os.getenv("WAF_DATABASE_PATH", ROOT/"waf/database/waf.db"))
    DATABASE_URL = database_url('security')
    RULES_DIR = ROOT/"waf/rules"
    ATTACK_CONFIG = ROOT/"waf/config/attack_detection.json"
    WAF_URL = os.getenv("DASHBOARD_WAF_URL","http://127.0.0.1:8080")
    HOST = os.getenv("DASHBOARD_HOST","127.0.0.1")
    PORT = int(os.getenv("DASHBOARD_PORT","9000"))
    SESSION_COOKIE_NAME = "waf_admin_session"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Strict"
    SESSION_COOKIE_SECURE = os.getenv("DASHBOARD_HTTPS","false").lower()=="true"
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    SESSION_REFRESH_EACH_REQUEST = False
    MAX_CONTENT_LENGTH = 16384
    TRUSTED_HOSTS = ["127.0.0.1","localhost","[::1]"]
    ADMIN_USERNAME = os.getenv("DASHBOARD_ADMIN_USERNAME","admin")
    ADMIN_PASSWORD = os.getenv("DASHBOARD_ADMIN_PASSWORD")
    GEOIP_DATABASE = os.getenv('GEOIP_DATABASE')
    EVALUATION_PATH = ROOT/'evaluation_results/evaluation.json'
