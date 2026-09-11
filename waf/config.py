"""Central configuration for the standalone WAF reverse proxy."""
from __future__ import annotations
import os
from pathlib import Path
from management.settings import database_url

BASE_DIR = Path(__file__).resolve().parent


class Config:
    WAF_HOST = os.getenv("WAF_HOST", "127.0.0.1")
    WAF_PORT = int(os.getenv("WAF_PORT", "8080"))
    BACKEND_HOST = os.getenv("BACKEND_HOST", "127.0.0.1")
    BACKEND_PORT = int(os.getenv("BACKEND_PORT", "5000"))
    BACKEND_URL = os.getenv("BACKEND_URL", f"http://{BACKEND_HOST}:{BACKEND_PORT}")
    TRUST_PROXY_HEADERS = os.getenv("TRUST_PROXY_HEADERS", "false").lower() == "true"
    DETECTION_ENABLED = os.getenv("DETECTION_ENABLED", "true").lower() == "true"
    MAX_BODY_SIZE = int(os.getenv("MAX_BODY_SIZE", 2 * 1024 * 1024))
    MAX_URL_LENGTH = int(os.getenv("MAX_URL_LENGTH", 4096))
    MAX_HEADER_SIZE = int(os.getenv("MAX_HEADER_SIZE", 16384))
    RATE_LIMIT_ENABLED = os.getenv("RATE_LIMIT_ENABLED", "true").lower() == "true"
    RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", 100))
    RATE_LIMIT_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW", 60))
    LOG_ONLY_SCORE = int(os.getenv("LOG_ONLY_SCORE", 4))
    BLOCK_SCORE = int(os.getenv("BLOCK_SCORE", 7))
    ENCODED_INPUT_BONUS = int(os.getenv("ENCODED_INPUT_BONUS", 2))
    RULES_DIR = BASE_DIR / "rules"
    ATTACK_CONFIG = Path(os.getenv("ATTACK_CONFIG", BASE_DIR / "config" / "attack_detection.json"))
    LOG_DIR = BASE_DIR / "logs"
    DATABASE_PATH = BASE_DIR / "database" / "waf.db"
    DATABASE_URL = database_url('security')
