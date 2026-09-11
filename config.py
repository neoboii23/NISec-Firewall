"""Configuration for the isolated vulnerable-application laboratory."""
import os
from pathlib import Path
from waf.management.settings import database_url

BASE_DIR = Path(__file__).resolve().parent


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "change-this-lab-secret")
    SQLALCHEMY_DATABASE_URI = database_url('shop') or f"sqlite:///{BASE_DIR / 'database.db'}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAX_CONTENT_LENGTH = 2 * 1024 * 1024
    UPLOAD_FOLDER = BASE_DIR / "uploads"
    LAB_FILES_FOLDER = BASE_DIR / "lab_files"
    LOG_FOLDER = BASE_DIR / "logs"
    LAB_MODE = os.environ.get("LAB_MODE", "true").lower() == "true"
    VULNERABLE_MODE = os.environ.get("VULNERABLE_MODE", "false").lower() == "true"
    HOST = os.environ.get("FLASK_HOST", "127.0.0.1")
    PORT = int(os.environ.get("FLASK_PORT", "5000"))
