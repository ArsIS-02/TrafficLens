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

from flask import Flask, Response, abort, after_this_request, jsonify, redirect, request, send_file, session, url_for

from . import asn, exports, feeds, gelf, hostcard, ioc_store, killchain, listfeeds, markup, pipeline, render, runner, worker
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


def _filter_jobs(jobs: list[dict], flt: dict) -> list[dict]:
    """Фильтры списка задач на главной: verdict / src / дата создания (dfrom..dto, ISO date)."""
    import datetime as dt

    def _day(s: str):
        try:
            return dt.date.fromisoformat(s) if s else None
        except ValueError:
            return None

    d0, d1 = _day(flt.get("dfrom", "")), _day(flt.get("dto", ""))
    out = []
    for j in jobs:
        s = j.get("summary") or {}
        v = s.get("verdict")
        v = v.get("level") if isinstance(v, dict) else v
        if flt.get("verdict") and v != flt["verdict"]:
            continue
        if flt.get("src") and j.get("source") != flt["src"]:
            continue
        if d0 or d1:
            d = dt.datetime.fromtimestamp(j.get("created") or 0).date()
            if d0 and d < d0 or d1 and d > d1:
                continue
        out.append(j)
    return out


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


def _backfill_sightings(cfg: Config, db: DB) -> None:
    """Разовое наполнение таблицы sightings по готовым отчётам (после обновления)."""
    try:
        if db.sightings_count():
            return
        n = 0
        for j in db.jobs(limit=10000):
            if j["status"] != "done":
                continue
            rp = pipeline.job_dir(cfg, j["id"]) / "report.json"
            try:
                rep = json.loads(rp.read_text(encoding="utf-8"))
            except (ValueError, OSError):
                continue
            db.set_sightings(j["id"], rep.get("ioc_hits") or [])
            n += 1
        if n:
            log.info("sightings: восстановлены наблюдения по %d задачам", n)
    except Exception:  # noqa: BLE001 — бэкфилл не должен ронять старт приложения
        log.exception("sightings backfill")


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
        gelf.start_heartbeat(cfg, db)   # пульс сервиса: молчание ловит Graylog
    _backfill_sightings(cfg, db)

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
        q = (request.args.get("q") or "").strip()[:200]
        flt = {k: (request.args.get(k) or "").strip() for k in ("verdict", "src", "dfrom", "dto")}
        jobs = pipeline.search_jobs(cfg, db, q) if q else db.jobs()
        if any(flt.values()):
            jobs = _filter_jobs(jobs, flt)
        return tpl("index.html", page="jobs", jobs=jobs, q=q, flt=flt, capture=worker.capture_status(cfg),
                   tools=runner.tool_versions(cfg), max_mb=cfg["max_upload_mb"],
                   retro=_retro_rows(db.retro_hits(unacked=True, limit=20)), retro_jobs=db.retro_unacked_jobs())

    def _retro_rows(rows: list[dict]) -> list[dict]:
        names: dict[str, str] = {}
        for r in rows:
            if r["job_id"] not in names:
                j = db.job(r["job_id"])
                names[r["job_id"]] = j["filename"] if j else r["job_id"]
            r["filename"] = names[r["job_id"]]
        return rows

    @app.get("/jobs/<job_id>")
    @require_login
    def job_page(job_id):
        j = get_job(job_id)
        jd = pipeline.job_dir(cfg, job_id)
        if j["status"] == "done" and (jd / "report.json").exists():
            rep = json.loads((jd / "report.json").read_text(encoding="utf-8"))
            j["retro"] = db.retro_hits(job_id=job_id)
            hits = rep.get("ioc_hits") or []
            elsewhere = db.sightings_elsewhere(
                [(h.get("type", ""), h.get("value", "")) for h in hits], job_id) if hits else {}
            ids = {e["job_id"] for lst in elsewhere.values() for e in lst}
            jobnames = {i: (db.job(i) or {}).get("filename", i) for i in ids}
            return render.render_report(rep, embedded=True, job=j, lang=client_lang(),
                                        elsewhere=elsewhere, jobnames=jobnames)
        logtext = (jd / "job.log").read_text(encoding="utf-8", errors="replace")[-20000:] if (jd / "job.log").exists() else ""
        return tpl("job.html", page="jobs", job=j, log=logtext)

    @app.get("/jobs/<job_id>/host/<ip>")
    @require_login
    def host_page(job_id, ip):
        j = get_job(job_id)
        if not re.match(r"^[0-9A-Fa-f.:]{3,45}$", ip):
            abort(404)
        card = hostcard.build(cfg, j, ip)
        if card is None:
            abort(404)
        return tpl("host.html", page="jobs", job=j, c=card)

    @app.get("/jobs/<job_id>/chain")
    @require_login
    def chain_page(job_id):
        j = get_job(job_id)
        p = pipeline.job_dir(cfg, job_id) / "report.json"
        if not p.exists():
            abort(404)
        rep = json.loads(p.read_text(encoding="utf-8"))
        return tpl("chain.html", page="jobs", job=j, ch=killchain.build(rep))

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

    @app.get("/jobs/<job_id>/report.pdf")
    @require_login
    def job_report_pdf(job_id):
        get_job(job_id)
        p = pipeline.job_dir(cfg, job_id) / "report.json"
        if not p.exists():
            abort(404)
        rep = json.loads(p.read_text(encoding="utf-8"))
        try:
            from .pdf import render_pdf
            data = render_pdf(rep, lang=client_lang())
        except ImportError:
            return Response("reportlab не установлен", status=500)
        return send_file(io.BytesIO(data), mimetype="application/pdf", as_attachment=True,
                         download_name=f"trafficlens-{job_id}.pdf")

    @app.get("/jobs/<job_id>/export/<what>.csv")
    @require_login
    def job_export_csv(job_id, what):
        get_job(job_id)
        if what not in exports.KINDS:
            abort(404)
        p = pipeline.job_dir(cfg, job_id) / "report.json"
        if not p.exists():
            abort(404)
        rep = json.loads(p.read_text(encoding="utf-8"))
        data = exports.build_csv(rep, what, lang=client_lang())
        if data is None:
            abort(404)
        return send_file(io.BytesIO(data), mimetype="text/csv; charset=utf-8", as_attachment=True,
                         download_name=f"trafficlens-{job_id}-{what}.csv")

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

    @app.get("/jobs/<job_id>/files.zip")
    @require_login
    def job_files_zip(job_id):
        """Все извлечённые файлы одним ZIP с паролем «infected» (кнопка в панели «Файлы»)."""
        j = get_job(job_id)
        d = pipeline.job_dir(cfg, job_id) / "zeek" / "extract_files"
        names = sorted(p.name for p in d.iterdir() if p.is_file() and not p.name.startswith(".")) if d.exists() else []
        if not names:
            abort(404)
        try:
            import pyzipper
        except ImportError:
            return Response("pyzipper не установлен", status=500)
        tmp = tempfile.NamedTemporaryFile(prefix="tlzip_", suffix=".zip", delete=False)
        tmp_path = tmp.name
        try:
            with pyzipper.AESZipFile(tmp, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zf:
                zf.setpassword(b"infected")
                for n in names:
                    zf.write(d / n, arcname=n + ".bin")
        except Exception:
            tmp.close()
            os.unlink(tmp_path)
            raise
        tmp.close()
        base = re.sub(r"[^\w.\-]+", "_", j.get("filename") or job_id)

        @after_this_request
        def _cleanup(resp):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            return resp

        return send_file(tmp_path, mimetype="application/zip", as_attachment=True,
                         download_name=f"{base}-files.zip")

    @app.get("/iocs")
    @require_login
    def iocs_page():
        custom = {p.stem: p.read_text(encoding="utf-8", errors="replace") for p in sorted(cfg.custom_ioc_dir.glob("*.txt"))}
        ic = cfg["iocs"]
        sources = [
            {"id": "custom", "name": et("src_custom"), "enabled": True, "note": f"{cfg.custom_ioc_dir}/*.txt"},
            {"id": "abusech-urlhaus", "name": "abuse.ch URLhaus", "enabled": ic["abusech"]["enabled"] and ic["abusech"]["urlhaus"], "note": et("note_urlhaus")},
            {"id": "abusech-threatfox", "name": "abuse.ch ThreatFox", "enabled": ic["abusech"]["enabled"] and ic["abusech"]["threatfox"], "note": et("note_threatfox")},
            {"id": "abusech-feodo", "name": "abuse.ch Feodo Tracker", "enabled": ic["abusech"]["enabled"] and ic["abusech"]["feodo"], "note": et("note_feodo")},
            {"id": "abusech-malwarebazaar", "name": "abuse.ch MalwareBazaar", "enabled": ic["abusech"]["enabled"] and ic["abusech"]["malwarebazaar"], "note": et("note_bazaar")},
            {"id": "spamhaus-drop", "name": "Spamhaus DROP", "enabled": bool((ic.get("public") or {}).get("spamhaus_drop")), "note": et("note_spamhaus")},
            {"id": "et-compromised", "name": "ET compromised IPs", "enabled": bool((ic.get("public") or {}).get("et_compromised")), "note": et("note_et_compromised")},
            {"id": "tor-exits", "name": "Tor exit nodes", "enabled": bool((ic.get("public") or {}).get("tor_exits")), "note": et("note_tor")},
            {"id": "misp", "name": "MISP", "enabled": ic["misp"]["enabled"], "note": ic["misp"]["url"] or et("note_not_configured")},
            {"id": "opencti", "name": "OpenCTI", "enabled": ic["opencti"]["enabled"], "note": ic["opencti"]["url"] or et("note_not_configured")},
        ]
        return tpl("iocs.html", page="iocs", sources=sources, feeds=db.feeds(), stats=ioc_store.stats(db), custom=custom,
                   state=worker.state(), tools=runner.tool_versions(cfg), abusech_key=bool(ic["abusech"]["auth_key"]),
                   rule_sources=runner.rule_sources(cfg), allow=db.allowlist(),
                   lists=listfeeds.all_feeds(cfg), list_source=listfeeds.source_name,
                   retro_status=db.kv_get("retro_status") or {}, retro_cfg=cfg.get("retro") or {},
                   gelf_cfg=cfg.get("gelf") or {}, gelf_status=db.kv_get("gelf_status") or {},
                   asn_status=asn.status(cfg), asn_last=db.kv_get("asn_status") or {},
                   export_on=bool((cfg.get("export") or {}).get("token")))

    @app.get("/help")
    @require_login
    def help_page():
        return tpl("help.html", page="help")

    # ------------------------------------------------------------- API
    @app.post("/api/upload")
    @require_login
    def api_upload():
        files = request.files.getlist("file")
        if not files:
            return jsonify(error=et("err_no_file")), 400
        bpf = (request.form.get("bpf") or "").strip()[:500]

        def _ts(key: str) -> float | None:
            v = (request.form.get(key) or "").strip()
            if not v:
                return None
            try:
                return float(v)
            except ValueError:
                return None

        ts_from, ts_to = _ts("t_from"), _ts("t_to")
        if ts_from is not None and ts_to is not None and ts_from >= ts_to:
            return jsonify(error=et("err_filter_window")), 400
        ids, errors = [], []
        for f in files:
            name = Path(f.filename or "capture.pcap").name
            if not name.lower().endswith(ALLOWED_EXT):
                errors.append(et("err_bad_ext").format(name=name))
                continue
            fd, tmp = tempfile.mkstemp(dir=cfg.data, prefix=".upload-")
            os.close(fd)
            f.save(tmp)
            if not _looks_like_pcap(Path(tmp), name):
                os.unlink(tmp)
                errors.append(et("err_not_pcap").format(name=name))
                continue
            try:
                ids.append(worker.enqueue_file(cfg, db, Path(tmp), name, "upload", move=True,
                                               bpf=bpf, ts_from=ts_from, ts_to=ts_to))
            except ValueError as e:
                Path(tmp).unlink(missing_ok=True)
                errors.append(et("err_bpf").format(name=name, err=str(e)[:200]))
        return jsonify(ok=bool(ids), jobs=ids, errors=errors), (200 if ids else 400)

    @app.get("/api/jobs")
    @require_login
    def api_jobs():
        return jsonify(jobs=[_public_job(j) for j in db.jobs()], capture=worker.capture_status(cfg))

    @app.post("/api/jobs/<job_id>/marks")
    @require_login
    def api_mark(job_id):
        """Разметка находки аналитиком; после изменения отчёт пересобирается (пересчёт score)."""
        j = get_job(job_id)
        data = request.get_json(silent=True) or {}
        kind = data.get("kind")
        key = (data.get("key") or "")[:300]
        status = data.get("status")
        note = (data.get("note") or "")[:300]
        if kind not in markup.KINDS or not key or status not in markup.STATUSES:
            return jsonify(error=et("err_bad_mark")), 400
        db.set_mark(job_id, kind, key, status, note)
        summary = None
        if j["status"] == "done":
            try:
                summary = pipeline.rematch(cfg, db, job_id)
            except FileNotFoundError:
                pass
        return jsonify(ok=True, summary=summary)

    @app.post("/api/allowlist")
    @require_login
    def api_allowlist():
        """Глобальный allowlist: add/del; с job_id — сразу пересобрать этот отчёт."""
        data = request.get_json(silent=True) or {}
        kind = data.get("kind")
        key = (data.get("key") or "")[:300]
        action = data.get("action")
        if kind not in markup.KINDS or not key or action not in ("add", "del"):
            return jsonify(error=et("err_bad_mark")), 400
        if action == "add":
            db.allow_add(kind, key, (data.get("note") or "")[:300])
        else:
            db.allow_del(kind, key)
        summary = None
        job_id = data.get("job_id") or ""
        if job_id and JOB_RE.match(job_id):
            j = db.job(job_id)
            if j and j["status"] == "done":
                try:
                    summary = pipeline.rematch(cfg, db, job_id)
                except FileNotFoundError:
                    pass
        return jsonify(ok=True, summary=summary, allowlist=len(db.allowlist()))

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

    @app.post("/api/jobs/<job_id>/export-iocs")
    @require_login
    def api_job_export_iocs(job_id):
        """Кнопка «в свои IOC»: находки задачи → from-reports.txt, переиндексация и ретропроверка."""
        j = get_job(job_id)
        if j["status"] != "done":
            return jsonify(error=et("err_job_not_done")), 409
        rp = pipeline.job_dir(cfg, job_id) / "report.json"
        rep = json.loads(rp.read_text(encoding="utf-8"))
        res = feeds.add_job_iocs_to_custom(cfg, j, rep)
        if res["added"]:
            import threading
            threading.Thread(target=worker.run_ioc_update, args=(cfg, db, "custom"), daemon=True).start()
        return jsonify(ok=True, **res)

    @app.post("/api/asn/update")
    @require_login
    def api_asn_update():
        """Кнопка «Обновить базу ASN»: скачивание iptoasn в фоне."""
        if worker.busy("asn"):
            return jsonify(error=et("err_update_running")), 409
        import threading
        threading.Thread(target=worker.run_asn_update, args=(cfg, db), daemon=True).start()
        return jsonify(ok=True)

    @app.post("/api/rules/update")
    @require_login
    def api_rules_update():
        if worker.busy("rules"):
            return jsonify(error=et("err_rules_running")), 409
        import threading
        threading.Thread(target=worker.run_rules_update, args=(cfg,), daemon=True).start()
        return jsonify(ok=True)

    @app.post("/api/rules/sources")
    @require_login
    def api_rulesrc_add():
        data = request.get_json(silent=True) or {}
        url = (data.get("url") or "").strip()[:500]
        note = (data.get("note") or "").strip()[:200]
        if not re.match(r"^https?://\S+$", url):
            return jsonify(error=et("err_bad_url")), 400
        srcs = runner.rule_sources(cfg)
        if any(s["url"] == url for s in srcs):
            return jsonify(error=et("err_src_exists")), 400
        srcs.append({"url": url, "note": note})
        runner.save_rule_sources(cfg, srcs)
        return jsonify(ok=True, count=len(srcs))

    @app.post("/api/rules/sources/delete")
    @require_login
    def api_rulesrc_del():
        data = request.get_json(silent=True) or {}
        url = (data.get("url") or "").strip()
        runner.save_rule_sources(cfg, [s for s in runner.rule_sources(cfg) if s["url"] != url])
        return jsonify(ok=True)

    # ------------------------------------------------------------- открытые списки угроз
    def _bg_update(source: str) -> None:
        import threading
        threading.Thread(target=worker.run_ioc_update, args=(cfg, db, source), daemon=True).start()

    @app.post("/api/iocs/lists/toggle")
    @require_login
    def api_lists_toggle():
        data = request.get_json(silent=True) or {}
        fid = str(data.get("id") or "")
        feed = next((f for f in listfeeds.all_feeds(cfg) if f["id"] == fid), None)
        if not feed:
            return jsonify(error=et("err_list_unknown")), 404
        if feed.get("locked"):
            return jsonify(error=et("err_list_locked")), 409
        on = bool(data.get("enabled"))
        listfeeds.set_enabled(cfg, fid, on)
        if on:
            _bg_update(listfeeds.source_name(fid))
        else:
            db.delete_source(listfeeds.source_name(fid))   # индикаторы выключенного списка не должны срабатывать
        return jsonify(ok=True)

    @app.post("/api/iocs/lists")
    @require_login
    def api_lists_add():
        data = request.get_json(silent=True) or {}
        url = (data.get("url") or "").strip()[:500]
        name = (data.get("name") or "").strip()[:80]
        typ = data.get("type") or None
        if not re.match(r"^https?://\S+$", url):
            return jsonify(error=et("err_bad_url")), 400
        if typ not in listfeeds.TYPES:
            return jsonify(error=et("err_list_type")), 400
        if any(f["url"] == url for f in listfeeds.all_feeds(cfg)):
            return jsonify(error=et("err_src_exists")), 400
        try:
            conf = int(data.get("conf") or 60)
        except (TypeError, ValueError):
            conf = 60
        item = listfeeds.add_custom(cfg, name, url, typ, conf)
        _bg_update(listfeeds.source_name(item["id"]))
        return jsonify(ok=True, id=item["id"])

    @app.post("/api/iocs/lists/delete")
    @require_login
    def api_lists_delete():
        fid = str((request.get_json(silent=True) or {}).get("id") or "")
        if not listfeeds.delete_custom(cfg, fid):
            return jsonify(error=et("err_list_unknown")), 404
        db.delete_source(listfeeds.source_name(fid))
        return jsonify(ok=True)

    # ------------------------------------------------------------- ретропроверка
    @app.post("/api/retro/run")
    @require_login
    def api_retro_run():
        if "retro" in worker.state()["busy"]:
            return jsonify(error=et("err_retro_running")), 409
        full = bool((request.get_json(silent=True) or {}).get("full"))
        import threading
        threading.Thread(target=worker.run_retro, args=(cfg, db, full), daemon=True).start()
        return jsonify(ok=True)

    @app.post("/api/retro/ack")
    @require_login
    def api_retro_ack():
        jid = (request.get_json(silent=True) or {}).get("job") or None
        if jid and not JOB_RE.match(str(jid)):
            abort(404)
        db.retro_ack(jid)
        return jsonify(ok=True)

    @app.get("/api/status")
    @require_login
    def api_status():
        return jsonify(state=worker.state(), feeds=db.feeds(), stats=ioc_store.stats(db),
                       retro=db.kv_get("retro_status") or {})

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

    # ------------------------------------------------------------- выгрузка IOC для Graylog
    @app.get("/export/iocs.csv")
    def export_iocs():
        """CSV для lookup table Graylog (адаптер «DSV File from HTTP»). Доступ — по токену, без сессии."""
        token = (cfg.get("export") or {}).get("token") or ""
        given = request.args.get("token") or request.headers.get("X-TrafficLens-Token") or ""
        if not token:
            abort(404)
        if not hmac.compare_digest(given, token):
            time.sleep(0.5)
            abort(403)
        types = {t for t in (request.args.get("types") or "").split(",") if t} or None
        try:
            min_conf = int(request.args.get("min_conf", (cfg.get("export") or {}).get("min_conf", 50)))
        except ValueError:
            min_conf = 50
        header = request.args.get("header", "1") not in ("0", "no", "false")
        body = exports.iocs_csv(db, types=types, min_conf=min_conf, header=header)
        return Response(body, mimetype="text/csv; charset=utf-8",
                        headers={"Cache-Control": "no-store", "Content-Disposition": "inline; filename=trafficlens-iocs.csv"})

    @app.post("/api/gelf/test")
    @require_login
    def api_gelf_test():
        ok, err = gelf.test_message(cfg, db)
        return (jsonify(ok=True), 200) if ok else (jsonify(error=et(err) if err.startswith("gelf_err") else err), 400)

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
