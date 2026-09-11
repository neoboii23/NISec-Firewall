"""JSON logging uses exactly the same redacted event as the database."""
import json
import logging
from pathlib import Path
from database.models import event_payload

def create_security_logger(log_dir: Path):
    log_dir.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("waf.security." + str(log_dir))
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if not logger.handlers:
        handler = logging.FileHandler(log_dir / "security.log", encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
    return logger

def log_security(logger, context, result, status):
    logger.info(json.dumps(event_payload(context, result, status), ensure_ascii=False))
