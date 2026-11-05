"""Веб-интерфейс TrafficLens (Flask)."""
from __future__ import annotations

import hmac
import io
import json
import logging
import os
import re
import secrets
import tempfile
import time
from functools import wraps
from pathlib import Path

from flask import Flask, Response, abort, jsonify, redirect, request, send_file, session, url_for

from . import feeds, ioc_store, pipeline, render, runner, worker
from .config import Config
from .config import load as load_config
from .db import DB
from .i18n import SUPPORTED, bundle as i18n_bundle, norm as i18n_norm

log = logging.getLogger("trafficlens.web")
JOB_RE = re.compile(r"^[0-9]{8}-[0-9]{6}-[0-9a-f]{4}$")
CUSTOM_RE = re.compile(r"^[a-zA-Z0-9_\-]{1,40}$")
ALLOWED_EXT = (".pcap", ".pcapng", ".cap", ".dmp", ".pcap.gz", ".pcapng.gz", ".cap.gz")


PBKDF2_ITERATIONS = 200_000
_login_failures: dict[str, list[float]] = {}
LOGIN_MAX_FAILURES = 5
LOGIN_WINDOW_SEC = 600


def hash_password(password: str, iterations: int = PBKDF2_ITERATIONS) -> str:
    """PBKDF2-SHA256 -> 'pbkdf2$<iterations>$<salt_hex>$<hash_hex>'. Для записи в auth.password_hash."""
    import hashlib

    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"pbkdf2${iterations}${salt.hex()}${dk.hex()}"


def _check_password(candidate: str, cfg: Config) -> bool:
    stored = (cfg["auth"].get("password_hash") or "").strip()
    if stored:
        import hashlib

        try:
            scheme, iters, salt_hex, hash_hex = stored.split("$")
            if scheme != "pbkdf2":
                return False
            dk = hashlib.pbkdf2_hmac("sha256", candidate.encode(), bytes.fromhex(salt_hex), int(iters))
            return secrets.compare_digest(dk.hex(), hash_hex)
        except (ValueError, TypeError):
            return False
    expected = cfg["auth"].get("password") or ""
    return bool(expected) and secrets.compare_digest(candidate.encode(), expected.encode())


def _login_throttled(ip: str) -> bool:
    now = time.time()
    fails = [t for t in _login_failures.get(ip, []) if now - t < LOGIN_WINDOW_SEC]
    _login_failures[ip] = fails
    return len(fails) >= LOGIN_MAX_FAILURES


def _public_job(j: dict | None) -> dict | None:
    if j is None:
        return None
    j = dict(j)
    j["pcap_path"] = Path(j["pcap_path"]).name
    return j


def create_app(cfg: Config | None = None, start_workers: bool = True) -> Flask:
    cfg = cfg or load_config()
    db = DB(cfg.db_path)
    app = Flask(__name__, static_folder=str(render.STATIC), template_folder=str(render.PKG / "templates"))
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = bool(cfg["auth"].get("cookie_secure", False))
    app.config["MAX_CONTENT_LENGTH"] = int(cfg["max_upload_mb"]) * 1024 * 1024
    app.secret_key = _secret(cfg)
    app.jinja_env.filters.update(render.get_env().filters)
    app.jinja_env.globals.update(render.get_env().globals)
    app.extensions["tl"] = {"cfg": cfg, "db": db}
    if start_workers:
        worker.start(cfg, db)

    password = cfg["auth"].get("password") or cfg["auth"].get("password_hash") or ""

    def require_login(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            if password and not session.get("ok"):
                if request.path.startswith("/api/"):
                    return jsonify(error=et("err_auth_required")), 401
                return redirect(url_for("login", next=request.path))
            if request.method == "POST" and request.headers.get("X-Requested-With") != "TrafficLens":
                return jsonify(error="bad request"), 400
            return fn(*a, **kw)
        return wrapper

    def client_lang() -> str:
        q = request.args.get("lang")
        if q in SUPPORTED:
            return q
        return i18n_norm(request.cookies.get("tl_lang"))

    def et(key: str) -> str:
        return i18n_bundle(client_lang()).get(key, key)

    def tpl(name, **kw):
        lang = client_lang()
        return render.get_env().get_template(name).render(auth=bool(password) and bool(session.get("ok")), lang=lang, L=i18n_bundle(lang), **kw)

    def get_job(job_id: str) -> dict:
        if not JOB_RE.match(job_id):
            abort(404)
        j = db.job(job_id)
        if not j:
            abort(404)
        return j

    # ------------------------------------------------------------- вход
    @app.route("/login", methods=["GET", "POST"])
    def login():
        if session.get("ok"):
            return redirect("/")
        lang = client_lang()
        if request.method == "POST":
            ip = request.remote_addr or "unknown"
            if _login_throttled(ip):
                time.sleep(1)
                return tpl("login.html", error=i18n_bundle(lang)["login_throttled"], username=cfg["auth"].get("username", "admin")), 429
            user = (request.form.get("username") or "").strip()
            expected_user = (cfg["auth"].get("username") or "admin").strip()
            if user == expected_user and _check_password(request.form.get("password") or "", cfg):
                _login_failures.pop(ip, None)
                session["ok"] = True
                session["user"] = user
                return redirect("/")
            _login_failures.setdefault(ip, []).append(time.time())
            time.sleep(1)
            return tpl("login.html", error=i18n_bundle(lang)["login_bad"], username=user or expected_user), 403
        return tpl("login.html", username=cfg["auth"].get("username", "admin"))

    @app.post("/logout")
    def logout():
        session.clear()
        return jsonify(ok=True)

    # ------------------------------------------------------------- страницы
    @app.get("/")
    @require_login
    def index():
        return tpl("index.html", page="jobs", jobs=db.jobs(), capture=worker.capture_status(cfg),
                   tools=runner.tool_versions(cfg), max_mb=cfg["max_upload_mb"])

    @app.get("/jobs/<job_id>")
    @require_login
    def job_page(job_id):
        j = get_job(job_id)
        jd = pipeline.job_dir(cfg, job_id)
        if j["status"] == "done" and (jd / "report.json").exists():
            rep = json.loads((jd / "report.json").read_text(encoding="utf-8"))
            return render.render_report(rep, embedded=True, job=j, lang=client_lang())
        logtext = (jd / "job.log").read_text(encoding="utf-8", errors="replace")[-20000:] if (jd / "job.log").exists() else ""
        return tpl("job.html", page="jobs", job=j, log=logtext)

    @app.get("/jobs/<job_id>/report.html")
    @require_login
    def job_report_html(job_id):
        get_job(job_id)
        p = pipeline.job_dir(cfg, job_id) / "report.html"
        if not p.exists():
            abort(404)
        return send_file(p, mimetype="text/html", as_attachment=True, download_name=f"trafficlens-{job_id}.html")

    @app.get("/jobs/<job_id>/report.json")
    @require_login
    def job_report_json(job_id):
        get_job(job_id)
        p = pipeline.job_dir(cfg, job_id) / "report.json"
        if not p.exists():
            abort(404)
        return send_file(p, mimetype="application/json", as_attachment=True, download_name=f"trafficlens-{job_id}.json")

    @app.get("/jobs/<job_id>/log")
    @require_login
    def job_log(job_id):
        get_job(job_id)
        p = pipeline.job_dir(cfg, job_id) / "job.log"
        return Response(p.read_text(encoding="utf-8", errors="replace") if p.exists() else "", mimetype="text/plain; charset=utf-8")

    @app.get("/jobs/<job_id>/pcap")
    @require_login
    def job_pcap(job_id):
        j = get_job(job_id)
        p = Path(j["pcap_path"])
        if not p.exists():
            abort(404)
        return send_file(p, as_attachment=True, download_name=j["filename"])

    @app.get("/jobs/<job_id>/files/<name>")
    @require_login
    def job_file(job_id, name):
        """Извлечённый файл — только в ZIP с паролем «infected», чтобы не запустить случайно."""
        get_job(job_id)
        if "/" in name or name.startswith("."):
            abort(404)
        p = pipeline.job_dir(cfg, job_id) / "zeek" / "extract_files" / name
        if not p.exists():
            abort(404)
        try:
            import pyzipper
        except ImportError:
            return Response("pyzipper не установлен", status=500)
        buf = io.BytesIO()
        with pyzipper.AESZipFile(buf, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zf:
            zf.setpassword(b"infected")
            zf.write(p, arcname=name + ".bin")
        buf.seek(0)
        return send_file(buf, mimetype="application/zip", as_attachment=True, download_name=f"{name}.zip")

    @app.get("/iocs")
    @require_login
    def iocs_page():
        custom = {p.stem: p.read_text(encoding="utf-8", errors="replace") for p in sorted(cfg.custom_ioc_dir.glob("*.txt"))}
        ic = cfg["iocs"]
        sources = [
            {"id": "custom", "name": "Свои списки", "enabled": True, "note": f"{cfg.custom_ioc_dir}/*.txt"},
            {"id": "abusech-urlhaus", "name": "abuse.ch URLhaus", "enabled": ic["abusech"]["enabled"] and ic["abusech"]["urlhaus"], "note": "вредоносные URL"},
            {"id": "abusech-threatfox", "name": "abuse.ch ThreatFox", "enabled": ic["abusech"]["enabled"] and ic["abusech"]["threatfox"], "note": "IP:порт, домены, URL, хэши"},
            {"id": "abusech-feodo", "name": "abuse.ch Feodo Tracker", "enabled": ic["abusech"]["enabled"] and ic["abusech"]["feodo"], "note": "C2 ботнетов"},
            {"id": "abusech-malwarebazaar", "name": "abuse.ch MalwareBazaar", "enabled": ic["abusech"]["enabled"] and ic["abusech"]["malwarebazaar"], "note": "хэши образцов за 48 ч"},
            {"id": "misp", "name": "MISP", "enabled": ic["misp"]["enabled"], "note": ic["misp"]["url"] or "не настроен"},
            {"id": "opencti", "name": "OpenCTI", "enabled": ic["opencti"]["enabled"], "note": ic["opencti"]["url"] or "не настроен"},
        ]
        return tpl("iocs.html", page="iocs", sources=sources, feeds=db.feeds(), stats=ioc_store.stats(db), custom=custom,
                   state=worker.state(), tools=runner.tool_versions(cfg), abusech_key=bool(ic["abusech"]["auth_key"]))

    # ------------------------------------------------------------- API
    @app.post("/api/upload")
    @require_login
    def api_upload():
        files = request.files.getlist("file")
        if not files:
            return jsonify(error=et("err_no_file")), 400
        ids, errors = [], []
        for f in files:
            name = Path(f.filename or "capture.pcap").name
            if not name.lower().endswith(ALLOWED_EXT):
                errors.append(f"{name}: поддерживаются .pcap, .pcapng, .cap (можно .gz)")
                continue
            fd, tmp = tempfile.mkstemp(dir=cfg.data, prefix=".upload-")
            os.close(fd)
            f.save(tmp)
            if not _looks_like_pcap(Path(tmp), name):
                os.unlink(tmp)
                errors.append(f"{name}: это не похоже на PCAP/PCAPNG")
                continue
            ids.append(worker.enqueue_file(cfg, db, Path(tmp), name, "upload", move=True))
        return jsonify(ok=bool(ids), jobs=ids, errors=errors), (200 if ids else 400)

    @app.get("/api/jobs")
    @require_login
    def api_jobs():
        return jsonify(jobs=[_public_job(j) for j in db.jobs()], capture=worker.capture_status(cfg))

    @app.get("/api/jobs/<job_id>")
    @require_login
    def api_job(job_id):
        return jsonify(_public_job(get_job(job_id)))

    @app.post("/api/jobs/<job_id>/rematch")
    @require_login
    def api_rematch(job_id):
        get_job(job_id)
        try:
            return jsonify(ok=True, summary=pipeline.rematch(cfg, db, job_id))
        except FileNotFoundError as e:
            return jsonify(error=str(e)), 400

    @app.post("/api/jobs/<job_id>/rerun")
    @require_login
    def api_rerun(job_id):
        j = get_job(job_id)
        if j["status"] == "running":
            return jsonify(error=et("err_job_running")), 409
        db.update_job(job_id, status="queued", stage="", error="")
        worker.wake.set()
        return jsonify(ok=True)

    @app.post("/api/jobs/<job_id>/delete")
    @require_login
    def api_delete(job_id):
        j = get_job(job_id)
        if j["status"] == "running":
            return jsonify(error=et("err_cant_delete_running")), 409
        pipeline.delete(cfg, db, job_id)
        return jsonify(ok=True)

    @app.post("/api/iocs/update")
    @require_login
    def api_ioc_update():
        if worker.busy("iocs"):
            return jsonify(error=et("err_update_running")), 409
        only = (request.get_json(silent=True) or {}).get("source")
        import threading
        threading.Thread(target=worker.run_ioc_update, args=(cfg, db, only), daemon=True).start()
        return jsonify(ok=True)

    @app.post("/api/rules/update")
    @require_login
    def api_rules_update():
        if worker.busy("rules"):
            return jsonify(error=et("err_rules_running")), 409
        import threading
        threading.Thread(target=worker.run_rules_update, args=(cfg,), daemon=True).start()
        return jsonify(ok=True)

    @app.get("/api/status")
    @require_login
    def api_status():
        return jsonify(state=worker.state(), feeds=db.feeds(), stats=ioc_store.stats(db))

    @app.get("/api/iocs/lookup")
    @require_login
    def api_lookup():
        q = (request.args.get("q") or "").strip()[:500]
        if not q:
            return jsonify(results=[])
        return jsonify(results=ioc_store.lookup(db, q))

    @app.post("/api/iocs/custom")
    @require_login
    def api_custom_save():
        data = request.get_json(silent=True) or {}
        name = (data.get("name") or "").strip()
        if not CUSTOM_RE.match(name):
            return jsonify(error=et("err_list_name")), 400
        text = data.get("text") or ""
        if len(text) > 5 * 1024 * 1024:
            return jsonify(error=et("err_list_big")), 400
        items, errors = feeds.parse_custom_text(text, name)
        (cfg.custom_ioc_dir / f"{name}.txt").write_text(text, encoding="utf-8")
        worker.run_ioc_update(cfg, db, only="custom")
        return jsonify(ok=True, count=len(items), errors=errors[:50])

    @app.post("/api/iocs/custom/<name>/delete")
    @require_login
    def api_custom_delete(name):
        if not CUSTOM_RE.match(name):
            abort(404)
        (cfg.custom_ioc_dir / f"{name}.txt").unlink(missing_ok=True)
        worker.run_ioc_update(cfg, db, only="custom")
        return jsonify(ok=True)

    @app.get("/healthz")
    def healthz():
        return jsonify(ok=True)

    @app.after_request
    def security_headers(resp):
        lang = request.args.get("lang")
        if lang in SUPPORTED:
            resp.set_cookie("tl_lang", lang, max_age=365 * 86400, samesite="Lax")
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'"
        return resp

    return app


def _secret(cfg: Config) -> bytes:
    p = cfg.data / ".secret_key"
    if not p.exists():
        p.write_bytes(secrets.token_bytes(32))
        p.chmod(0o600)
    return p.read_bytes()


def _looks_like_pcap(p: Path, name: str) -> bool:
    with p.open("rb") as fh:
        head = fh.read(4)
    if name.lower().endswith(".gz"):
        return head[:2] == b"\x1f\x8b"
    return head in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a")
