"""Independent admin service. Run: python -m admin_dashboard.app"""
import csv
import io
import json
import secrets
import hmac
import sys
from pathlib import Path

if __package__ in (None,""):
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
    __package__="admin_dashboard"

from flask import Flask, abort, flash, g, jsonify, redirect, render_template, request, session, url_for, Response
from werkzeug.exceptions import HTTPException
from .config import Config
from waf.management.store import ManagementStore
from waf.management.runtime import RuntimePolicy
from .services.auth_service import AuthService
from .services.event_service import EventService, CATEGORIES
from .services.dashboard_service import DashboardService
from .services.alert_service import AlertService
from .services.rule_service import RuleService
from .services.ip_service import IPService
from .services.system_service import SystemService
from .services.geo_service import GeoService
from .services.evaluation_service import EvaluationService

def create_app(overrides=None):
    app=Flask(__name__)
    app.config.from_object(Config)
    app.config.update(overrides or {})
    if overrides and 'DATABASE_PATH' in overrides and 'DATABASE_URL' not in overrides:
        app.config['DATABASE_URL'] = None
    store=ManagementStore(app.config.get('DATABASE_URL') or app.config["DATABASE_PATH"])
    app.secret_key=store.secret("dashboard_secret")
    auth=AuthService(store)
    password=app.config.pop("ADMIN_PASSWORD",None)
    if password:
        auth.provision(app.config["ADMIN_USERNAME"],password)
    events=EventService(store)
    overview=DashboardService(store,events)
    alerts=AlertService(store)
    rules=RuleService(store,Path(app.config["RULES_DIR"]),Path(app.config["ATTACK_CONFIG"]))
    ips=IPService(store)
    geo=GeoService(store,events,app.config['GEOIP_DATABASE'])
    evaluation=EvaluationService(app.config['EVALUATION_PATH'])
    runtime=RuntimePolicy(store)
    system=SystemService(store,app.config["WAF_URL"],app.config["PORT"])
    app.extensions.update(management=store,auth=auth,events=events,overview=overview,system=system)

    def csrf():
        if "csrf" not in session:
            session["csrf"]=secrets.token_hex(32)
        return session["csrf"]

    def json_object():
        data = request.get_json()
        if not isinstance(data, dict):
            raise ValueError("Request body must be a JSON object")
        return data

    @app.before_request
    def protect():
        g.admin=session.get("admin")
        g.role=auth.role(g.admin) if g.admin else None
        if request.endpoint=="static":
            return
        if request.endpoint!="login" and (not g.admin or not auth.exists(g.admin)):
            if request.path.startswith("/api/"):
                return jsonify(error="Authentication required"),401
            return redirect(url_for("login"))
        if request.method not in ("GET","HEAD","OPTIONS"):
            if request.endpoint not in ('login','logout') and g.role!='ADMIN':abort(403)
            submitted=request.headers.get("X-CSRF-Token") or request.form.get("csrf","")
            expected=session.get("csrf","")
            if not expected or not hmac.compare_digest(submitted,expected):
                abort(403,description="Your form expired. Reload the page and try again.")

    @app.after_request
    def headers(response):
        response.headers.update({
            "Cache-Control":"no-store",
            "X-Content-Type-Options":"nosniff",
            "Referrer-Policy":"same-origin",
            "X-Frame-Options":"DENY",
            "Content-Security-Policy":"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'none'; form-action 'self'"
        })
        return response

    @app.context_processor
    def common():
        return {"csrf_token":csrf,"categories":CATEGORIES,"admin":session.get("admin"),"role":getattr(g,'role',None)}

    @app.route("/login",methods=["GET","POST"])
    def login():
        if request.method=="POST":
            name=request.form.get("username","").strip()
            password=request.form.get("password","")
            if len(name)<=80 and len(password)<=1024 and auth.authenticate(request.remote_addr or "unknown",name,password):
                session.clear()
                session["admin"]=name
                session.permanent=True
                csrf()
                return redirect(url_for("dashboard"))
            flash("Unable to sign in. Check your credentials or try again later.","error")
        return render_template("login.html")

    @app.post("/logout")
    def logout():
        with store.connect() as db:store.audit(db,g.admin,'logout','dashboard')
        session.clear()
        return redirect(url_for("login"))

    @app.get("/")
    @app.get("/dashboard")
    def dashboard():
        return render_template("dashboard.html",title="Security overview",active="overview")

    @app.get("/events")
    @app.get("/logs")
    def event_list():
        data=events.list(request.args)
        return render_template("events.html",title="Traffic & logs",active="events",data=data)

    @app.get('/live-traffic')
    def live_traffic():
        return render_template('events.html',title='Live traffic',active='live',data=events.list(request.args))

    @app.get("/events/<incident_id>")
    @app.get("/logs/<incident_id>")
    def event_detail(incident_id):
        event=events.detail(incident_id)
        if not event:
            abort(404)
        return render_template("event_detail.html",title="Incident detail",active="events",event=event)

    @app.get("/attacks")
    @app.get("/analytics")
    def attacks():
        return render_template("attacks.html",title="Attack analytics",active="attacks")

    @app.get("/alerts")
    def alert_list():
        return render_template("alerts.html",title="Security alerts",active="alerts")

    @app.get("/rules")
    def rule_list():
        return render_template("rules.html",title="Rule management",active="rules")

    @app.get("/ip-management")
    def ip_list():
        return render_template("ip_management.html",title="IP management",active="ip")

    @app.get("/system")
    def system_page():
        return render_template("system.html",title="System status",active="system")

    @app.get('/rate-limits')
    def rate_page():
        return render_template('rate_limits.html',title='Rate limiting',active='rates',policy=runtime.read())

    @app.get('/settings')
    def settings_page():
        return render_template('settings.html',title='Admin settings',active='settings')

    @app.get('/evaluation')
    def evaluation_page():
        return render_template('evaluation.html',title='Evaluation',active='evaluation')

    @app.get('/api/evaluation')
    def evaluation_api():
        return jsonify(evaluation.read())

    @app.get('/attack-map')
    def map_page():
        return render_template('attack_map.html',title='Attack source map',active='map')

    @app.get('/api/attack-map')
    def map_api():
        return jsonify(sources=geo.sources())

    @app.get('/api/rate-limits')
    def rate_api():
        status=system.status()
        return jsonify(policy=status.get('runtime_policy',runtime.read()),entries=status.get('rate_limits',[]),status=status['status'])

    @app.put('/api/rate-limits')
    def rate_update():
        return jsonify(policy=runtime.update(json_object(),g.admin),ok=True)

    @app.get("/api/dashboard/summary")
    def summary_api():
        return jsonify(overview.summary())

    @app.get("/api/events/recent")
    def events_api():
        return jsonify(events.list(request.args))

    @app.get("/api/attacks/stats")
    def attacks_api():
        return jsonify(overview.analytics(request.args))

    @app.get("/api/charts/attacks")
    def timeline_api():
        return jsonify(overview.timeline(request.args))

    @app.get("/api/alerts")
    @app.get("/api/alerts/recent")
    def alerts_api():
        return jsonify(alerts.list(request.args.get("page",1),request.args.get("active")=="true"))

    @app.post("/api/alerts/<int:identifier>/acknowledge")
    def acknowledge(identifier):
        alerts.acknowledge(identifier,g.admin)
        return jsonify(ok=True)

    @app.get("/api/rules")
    def rules_api():
        return jsonify(rules.inventory())

    @app.put("/api/rules/<identifier>")
    def update_rule(identifier):
        data=json_object()
        rules.update("rule",identifier,data.get("enabled"),g.admin)
        return jsonify(ok=True,message="Saved. The WAF applies this state on its next request.")

    @app.put("/api/detectors/<identifier>")
    def update_detector(identifier):
        data=json_object()
        rules.update("detector",identifier,data.get("enabled"),g.admin)
        return jsonify(ok=True,message="Saved. The WAF applies this state on its next request.")

    @app.put('/api/rules/<identifier>/configuration')
    def rule_configuration(identifier):
        rules.configure(identifier,json_object(),g.admin)
        return jsonify(ok=True)

    @app.get('/api/audit')
    def audit_api():
        page=max(1,min(1000000,int(request.args.get('page',1))))
        with store.connect() as db:
            rows=db.execute('SELECT * FROM management_audit ORDER BY id DESC LIMIT 25 OFFSET ?',((page-1)*25,)).fetchall()
        return jsonify(items=[dict(r) for r in rows],page=page)

    @app.get("/api/ip/blocked")
    def ip_api():
        return jsonify(ips.list(request.args.get("ip",""),request.args.get("kind","")))

    @app.post("/api/ip")
    def change_ip():
        ips.change(json_object(),g.admin)
        return jsonify(ok=True,message="IP policy saved. It takes effect on the next WAF request.")

    @app.get("/api/system/status")
    @app.get("/api/status")
    def system_api():
        return jsonify(system.status())

    @app.get("/api/events/export")
    def export_api():
        rows=events.export(request.args)
        kind=request.args.get("format","csv")
        if kind=="json":
            return Response(json.dumps(rows),mimetype="application/json",
                            headers={"Content-Disposition":"attachment; filename=security-events.json"})
        if kind!="csv":
            raise ValueError("Export format must be csv or json")
        output=io.StringIO(newline="")
        keys=["timestamp","incident_id","source_ip","method","path","category_name","severity","matched_rules","threat_score","decision","response_status"]
        writer=csv.writer(output)
        writer.writerow(keys)
        for row in rows:
            values=[]
            for key in keys:
                value=str(row.get(key) or "")
                if value.startswith(("=","+","-","@","\t","\r","\n")):
                    value="'"+value
                values.append(value)
            writer.writerow(values)
        return Response(output.getvalue(),mimetype="text/csv",
                        headers={"Content-Disposition":"attachment; filename=security-events.csv"})

    @app.errorhandler(ValueError)
    def invalid(error):
        if request.path.startswith("/api/"):
            return jsonify(error=str(error)),400
        return render_template("error.html",title="Invalid input",message="Check the submitted filters or values."),400

    @app.errorhandler(HTTPException)
    def http_error(error):
        if request.path.startswith("/api/"):
            return jsonify(error=error.name),error.code
        return render_template("error.html",title=error.name,message=error.description),error.code

    @app.errorhandler(Exception)
    def server_error(error):
        app.logger.error("Dashboard operation failed (%s)",type(error).__name__)
        if request.path.startswith("/api/"):
            return jsonify(error="Operation unavailable. Try again."),503
        return render_template("error.html",title="Service unavailable",message="Please try again shortly."),503
    return app

if __name__=="__main__":
    app=create_app()
    app.run(host=app.config["HOST"],port=app.config["PORT"],debug=False)
