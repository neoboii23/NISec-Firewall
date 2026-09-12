"""Configuration for the isolated vulnerable-application laboratory."""
import os
from pathlib import Path
from waf.management.settings import database_url

BASE_DIR = Path(__file__).resolve().parent
IS_VERCEL = os.environ.get("VERCEL") == "1"
RUNTIME_DIR = Path(os.environ.get("RUNTIME_DIR", "/tmp/origine" if IS_VERCEL else BASE_DIR))
SHOP_DATABASE_URI = database_url('shop')

if IS_VERCEL and not SHOP_DATABASE_URI:
    raise RuntimeError("SHOP_DATABASE_URL must be set in Vercel project environment variables.")


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "change-this-lab-secret")
    SQLALCHEMY_DATABASE_URI = SHOP_DATABASE_URI or f"sqlite:///{BASE_DIR / 'database.db'}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True, "pool_recycle": 280}
    MAX_CONTENT_LENGTH = 2 * 1024 * 1024
    UPLOAD_FOLDER = Path(os.environ.get("UPLOAD_FOLDER", RUNTIME_DIR / "uploads"))
    LAB_FILES_FOLDER = Path(os.environ.get("LAB_FILES_FOLDER", RUNTIME_DIR / "lab_files"))
    LOG_FOLDER = Path(os.environ.get("LOG_FOLDER", RUNTIME_DIR / "logs"))
    LAB_MODE = os.environ.get("LAB_MODE", "false" if IS_VERCEL else "true").lower() == "true"
    VULNERABLE_MODE = os.environ.get("VULNERABLE_MODE", "false").lower() == "true"
    HOST = os.environ.get("FLASK_HOST", "127.0.0.1")
    PORT = int(os.environ.get("FLASK_PORT", "5000"))
    PREFERRED_URL_SCHEME = "https" if IS_VERCEL else "http"
