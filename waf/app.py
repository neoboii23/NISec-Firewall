"""Phase 3 proxy extended with the six Phase 4 attack detectors."""
import json
import logging
import hmac
import time
from pathlib import Path
from urllib.parse import urlsplit
from datetime import datetime, timezone, timedelta
from management.runtime import RuntimePolicy
from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import BadRequest, RequestEntityTooLarge
from config import Config
from database.models import SecurityEventStore
from engine.decision import DetectionResult, Match, decide
from engine.inspector import inspect_request
from engine.normalizer import Normalizer
from engine.rate_limit import RateLimiter
from engine.rule_engine import RuleEngine
from waf_logging.security_logger import create_security_logger, log_security
from waf_logging.access_logger import create_access_logger
from proxy import backend_available, forward

SUPPORTED_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]

def create_app(overrides=None):
    app = Flask(__name__, static_folder=None)
    app.config.from_object(Config)
    app.config.update(overrides or {})
    if overrides and 'DATABASE_PATH' in overrides and 'DATABASE_URL' not in overrides:
        app.config['DATABASE_URL'] = None
    app.config["MAX_CONTENT_LENGTH"] = app.config["MAX_BODY_SIZE"]
    app.config["MAX_FORM_PARTS"] = 100
    settings = json.loads(Path(app.config["ATTACK_CONFIG"]).read_text(encoding="utf-8"))
    engine = RuleEngine(Path(app.config["RULES_DIR"]), Normalizer(settings["normalization_passes"]),
                        app.config["ENCODED_INPUT_BONUS"], settings)
    events = SecurityEventStore(app.config.get('DATABASE_URL') or app.config["DATABASE_PATH"])
    management = events.management
    management_token = management.secret("management_token")
    runtime = RuntimePolicy(management,dict(rate_enabled=app.config['RATE_LIMIT_ENABLED'],
        rate_requests=app.config['RATE_LIMIT_REQUESTS'],rate_window=app.config['RATE_LIMIT_WINDOW'],
        brute_failures=settings['brute_force']['max_failures'],brute_window=settings['brute_force']['window_seconds'],
        brute_block=settings['brute_force']['block_seconds'],block_score=app.config['BLOCK_SCORE']))
    command_cursor = 0
    limiter = RateLimiter(app.config["RATE_LIMIT_REQUESTS"], app.config["RATE_LIMIT_WINDOW"])
    security_logger = create_security_logger(Path(app.config["LOG_DIR"]))
    access_logger = create_access_logger(Path(app.config["LOG_DIR"]))
    # Werkzeug's default access output includes full query strings (potential secrets).
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    app.extensions.update(attack_engine=engine, security_events=events)

    def synchronize():
        nonlocal command_cursor
        engine.rule_overrides, engine.detector_overrides = management.states()
        engine.rule_configs=management.rule_configurations()
        values=runtime.read()
        app.config.update(RATE_LIMIT_ENABLED=values['rate_enabled'],BLOCK_SCORE=values['block_score'])
        limiter.configure(values['rate_requests'],values['rate_window'])
        with engine.pipeline.brute_force.lock:
            engine.pipeline.brute_force.policy.update(max_failures=values['brute_failures'],
                window_seconds=values['brute_window'],block_seconds=values['brute_block'])
        for command in management.commands(command_cursor):
            engine.pipeline.brute_force.unblock_ip(command["ip"])
            command_cursor = command["id"]

    @app.before_request
    def protect_management():
        if request.path.startswith("/internal/"):
            token = request.headers.get("Authorization", "")
            if request.remote_addr not in ("127.0.0.1", "::1") or not hmac.compare_digest(token, "Bearer " + management_token):
                return jsonify(error="Unauthorized"), 401

    @app.get("/internal/status")
    def internal_status():
        synchronize()
        backend = urlsplit(app.config["BACKEND_URL"])
        return jsonify(service="WAF", status="online", backend="online" if backend_available(app.config["BACKEND_URL"]) else "offline",
            backend_host=backend.hostname, backend_port=backend.port or (443 if backend.scheme == "https" else 80),
            enabled_rules=sum(engine.rule_enabled(rule) for rule in engine.rules),
            detection_enabled=app.config["DETECTION_ENABLED"], prevention_enabled=True,
            rate_limiting_enabled=app.config["RATE_LIMIT_ENABLED"], temporary_blocking_enabled=True,
            brute_force=engine.pipeline.brute_force.snapshot(), rate_limits=limiter.snapshot(),runtime_policy=runtime.read())

    def record(context, result, status):
        if any(m.action=='ALERT' for m in result.matches):result.metadata['alert_requested']=True
        events.record(context, result, status)
        if result.decision=='BLOCK' and any(m.action=='TEMPORARY_BLOCK' for m in result.matches):
            management.set_ip(context.client_ip,'temporary','Rule temporary-block action','WAF',
                duration=runtime.read()['auto_block'],source='automatic',incident_id=result.incident_id,attack_category=result.category)
        policy=runtime.read()
        if policy['auto_enabled'] and result.decision=='BLOCK' and result.score>=policy['auto_min_score']:
            since=(datetime.now(timezone.utc)-timedelta(seconds=policy['auto_window'])).isoformat()
            for category in set(m.category for m in result.matches) & set(policy['auto_categories']):
                if category=='BRUTE_FORCE':continue  # Already response-confirmed below.
                with management.connect() as db:
                    count=db.execute('''SELECT COUNT(*) FROM security_events e JOIN event_categories c ON c.event_id=e.id
                        WHERE e.source_ip=? AND e.timestamp>=? AND c.category=? AND e.decision='BLOCK' AND e.threat_score>=?''',
                        (context.client_ip,since,category,policy['auto_min_score'])).fetchone()[0]
                if count>=policy['auto_threshold']:
                    management.set_ip(context.client_ip,'temporary','Repeated '+category,'WAF',
                        duration=policy['auto_block'],incident_id=result.incident_id,source='automatic',attack_category=category)
                    break
        if result.metadata.get("authentication_outcome") == "failure":
            for match in result.matches:
                if match.category == "BRUTE_FORCE" and match.action not in ("LOG","ALERT"):
                    management.set_ip(context.client_ip, "temporary", "Repeated failed logins", "WAF",
                        duration=match.evidence.get("block_duration", 600), incident_id=result.incident_id, scope="login",
                        source="automatic",attack_category="BRUTE_FORCE")
        log_security(security_logger, context, result, status)
        access_logger.info(json.dumps({"timestamp": result.timestamp, "incident_id": result.incident_id,
            "source_ip": context.client_ip, "method": context.method, "path": context.path,
            "status": status, "decision": result.decision}))

    def block(context, result, status):
        record(context, result, status)
        response = app.make_response((render_template("blocked.html", incident_id=result.incident_id,
            severity=result.severity, message="The Web Application Firewall detected suspicious activity.",
            category=result.category_name), status))
        if status == 429:
            response.headers["Retry-After"] = str(result.metadata.get("retry_after") or max((m.evidence.get("retry_after", 60) for m in result.matches), default=60))
        return response

    @app.get("/health")
    def health():
        context = inspect_request(request, app.config["TRUST_PROXY_HEADERS"], metadata_only=True)
        record(context, DetectionResult(), 200)
        return jsonify(status="ok", service="WAF", backend="available" if backend_available(app.config["BACKEND_URL"]) else "unavailable")

    @app.get("/status")
    def status():
        context = inspect_request(request, app.config["TRUST_PROXY_HEADERS"], metadata_only=True)
        record(context, DetectionResult(), 200)
        return jsonify(status="ok", rules_loaded=len(engine.rules), events=events.counts(), attack_counts=events.attack_counts())

    @app.route("/", defaults={"path": ""}, methods=SUPPORTED_METHODS)
    @app.route("/<path:path>", methods=SUPPORTED_METHODS)
    def proxy_request(path):
        context = inspect_request(request, app.config["TRUST_PROXY_HEADERS"], metadata_only=True)
        try:
            synchronize()
            # Hard transport limits apply even to explicitly trusted sources.
            if context.content_length > app.config["MAX_BODY_SIZE"]:
                raise RequestEntityTooLarge()
            if len(request.full_path) > app.config["MAX_URL_LENGTH"]:
                return block(context, DetectionResult(decision="BLOCK", severity="HIGH", category="PROTOCOL"), 414)
            if sum(len(k) + len(v) for k, v in context.headers.items()) > app.config["MAX_HEADER_SIZE"]:
                return block(context, DetectionResult(decision="BLOCK", severity="HIGH", category="PROTOCOL"), 431)
            policies=management.policy(context.client_ip)
            trust=next((p["trust_mode"] for p in policies if p["kind"]=="whitelist"),"NORMAL")
            for policy in sorted(policies, key=lambda p: p["kind"] != "blacklist"):
                if policy["kind"] == "whitelist":
                    continue
                if trust=="FULL_BYPASS" or (policy["kind"]=="blacklist" and trust=="BLACKLIST_BYPASS"):
                    continue
                if policy["scope"] == "login" and not engine.pipeline.brute_force.is_login(context):
                    continue
                if policy["scope"] == "login" and (not engine.detector_enabled("brute_force") or not engine.rule_enabled(engine.by_id["WAF-005-BRUTE-001"])):
                    continue
                status_code = 403 if policy["kind"] == "blacklist" else 429
                result = DetectionResult(decision="BLOCK" if status_code == 403 else "RATE_LIMIT", severity="HIGH", category="IP_POLICY")
                result.metadata = {"policy": policy["kind"], "reason": policy["reason"],
                                   "retry_after":max(1,int(policy["expires_at"]-time.time())+1) if policy["expires_at"] else 60}
                return block(context, result, status_code)
            if app.config["RATE_LIMIT_ENABLED"] and trust not in ("RATE_LIMIT_BYPASS","FULL_BYPASS") and not limiter.allowed(context.client_ip):
                return block(context, DetectionResult(decision="RATE_LIMIT", severity="MEDIUM", category="RATE_LIMIT",
                    metadata={'retry_after':limiter.retry_after(context.client_ip)}), 429)
            context = inspect_request(request, app.config["TRUST_PROXY_HEADERS"], settings["file_upload"]["inspection_max_bytes"])
            result = engine.inspect(context) if app.config["DETECTION_ENABLED"] and trust!="FULL_BYPASS" else DetectionResult()
            if trust!="NORMAL":
                result.metadata["trust_mode"]=trust
            status_code = decide(result, app.config["BLOCK_SCORE"])
            if status_code:
                return block(context, result, status_code)
            response = forward(app.config["BACKEND_URL"], path)
            if app.config["DETECTION_ENABLED"] and trust!="FULL_BYPASS":
                # Threshold event is recorded on the final forwarded failure. NEXT request gets 429.
                result = engine.pipeline.observe_response(context, response.status_code, response.headers, result)
            response.headers.pop(settings["brute_force"]["response_header"], None)
            record(context, result, response.status_code)
            return response
        except RequestEntityTooLarge:
            result = DetectionResult(decision="BLOCK", severity="HIGH", category="PROTOCOL")
            if context.content_type.startswith("multipart/") and engine.detector_enabled("file_upload"):
                match = engine.make_match("WAF-006-UPLOAD-005", "body.size", details={"limit": app.config["MAX_BODY_SIZE"]})
                if match:
                    from engine.scoring import build_result
                    result = build_result([match], False, 0)
                    decide(result)
            return block(context, result, 413)
        except (BadRequest, ValueError, RecursionError):
            return block(context, DetectionResult(decision="BLOCK", severity="MEDIUM", category="PROTOCOL"), 400)
        except Exception:
            # Do not log exception text that may embed submitted values.
            app.logger.error("Request processing failed; internal diagnostic required")
            return block(context, DetectionResult(decision="BLOCK", severity="HIGH", category="INTERNAL"), 503)

    @app.errorhandler(405)
    def unsupported(error):
        context = inspect_request(request, app.config["TRUST_PROXY_HEADERS"], metadata_only=True)
        return block(context, DetectionResult(decision="BLOCK", severity="MEDIUM", category="PROTOCOL"), 405)
    return app

app = create_app()

if __name__ == "__main__":
    app.run(host=app.config["WAF_HOST"], port=app.config["WAF_PORT"], debug=False)
