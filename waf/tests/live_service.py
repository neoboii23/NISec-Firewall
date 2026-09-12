"""Subprocess-only live integration server; all test data stays in a temp directory."""
import json
import os
import sys
from pathlib import Path
from werkzeug.serving import make_server

role, work, port, backend = sys.argv[1:]
work = Path(work)
project = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(project if role in ("backend", "dashboard") else project/"waf"))

if role == "backend":
    from config import Config
    Config.SQLALCHEMY_DATABASE_URI = "sqlite:///" + str(work/"backend.db")
    Config.SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True, "pool_recycle": 280}
    Config.UPLOAD_FOLDER = work/"uploads"
    Config.LAB_FILES_FOLDER = work/"lab_files"
    Config.LOG_FOLDER = work/"backend_logs"
    Config.VULNERABLE_MODE = True
    from app import app
    from seed import seed_database
    seed_database()
    from flask import request
    @app.before_request
    def record_arrival():
        with (work/"arrivals.jsonl").open("a", encoding="utf-8") as log:
            log.write(json.dumps({"method":request.method,"path":request.path}) + "\n")
elif role == "waf":
    from app import create_app
    app = create_app({"BACKEND_URL":backend, "DATABASE_PATH":work/"waf.db",
                      "LOG_DIR":work/"waf_logs", "RATE_LIMIT_ENABLED":False})
else:
    from admin_dashboard.app import create_app
    app = create_app({"WAF_URL":backend, "DATABASE_PATH":work/"waf.db",
                      "ADMIN_PASSWORD":"Dashboard-integration-password!", "PORT":int(port)})
    app.extensions['auth'].provision('viewer','Viewer-integration-password!','VIEWER')

server = make_server("127.0.0.1", int(port), app, threaded=True)
app.config["PORT"] = server.server_port
(work/(role + "_ready.json")).write_text(json.dumps({"port":server.server_port,"pid":os.getpid()}), encoding="utf-8")
server.serve_forever()
