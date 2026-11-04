"""Запуск Zeek и Suricata над PCAP, обновление правил Suricata."""
from __future__ import annotations

import ipaddress
import logging
import os
import shutil
import subprocess
from pathlib import Path

from .config import Config

log = logging.getLogger("trafficlens.runner")
PKG = Path(__file__).parent
ZEEK_SCRIPT = PKG / "zeek" / "trafficlens.zeek"
BAKED_RULES = Path("/opt/trafficlens/rules-baked/suricata.rules")


class ToolError(Exception):
    pass


def _find(cfg_bin: str, name: str, extra: list[str]) -> str | None:
    if cfg_bin:
        return cfg_bin
    found = shutil.which(name)
    if found:
        return found
    for p in extra:
        if os.access(p, os.X_OK):
            return p
    return None


def zeek_bin(cfg: Config) -> str | None:
    return _find(cfg["zeek"]["bin"], "zeek", ["/usr/local/zeek/bin/zeek", "/opt/zeek/bin/zeek"])


def suricata_bin(cfg: Config) -> str | None:
    return _find(cfg["suricata"]["bin"], "suricata", ["/usr/bin/suricata", "/usr/local/bin/suricata"])


def rules_file(cfg: Config) -> Path | None:
    p = cfg.rules_dir / "rules" / "suricata.rules"
    if p.exists() and p.stat().st_size > 0:
        return p
    if BAKED_RULES.exists():
        return BAKED_RULES
    return None


def tool_versions(cfg: Config) -> dict:
    out = {}
    for name, b, arg in (("zeek", zeek_bin(cfg), "--version"), ("suricata", suricata_bin(cfg), "-V")):
        if not b:
            out[name] = None
            continue
        try:
            r = subprocess.run([b, arg], capture_output=True, text=True, timeout=20)
            out[name] = (r.stdout or r.stderr).strip().splitlines()[0][:80]
        except Exception:  # noqa: BLE001
            out[name] = "?"
    rf = rules_file(cfg)
    out["rules"] = None
    if rf:
        try:
            with rf.open("rb") as fh:
                n = sum(1 for line in fh if line[:1] not in (b"#", b"\n"))
            out["rules"] = {"path": str(rf), "count": n, "mtime": rf.stat().st_mtime}
        except OSError:
            pass
    return out


def _zeek_subnet(net: str) -> str:
    n = ipaddress.ip_network(net, strict=False)
    if n.version == 6:
        return f"[{n.network_address}]/{n.prefixlen}"
    return str(n)


def _run(cmd: list[str], cwd: Path, logfile: Path, timeout_min: int) -> int:
    with logfile.open("a", encoding="utf-8") as lf:
        lf.write("$ " + " ".join(cmd) + "\n")
        lf.flush()
        try:
            r = subprocess.run(cmd, cwd=cwd, stdout=lf, stderr=subprocess.STDOUT, timeout=timeout_min * 60)
        except subprocess.TimeoutExpired:
            lf.write(f"!! превышено время ({timeout_min} мин)\n")
            return -1
        lf.write(f"-> код возврата {r.returncode}\n")
        return r.returncode


def run_zeek(cfg: Config, pcap: Path, outdir: Path, logfile: Path) -> None:
    zb = zeek_bin(cfg)
    if not zb:
        raise ToolError("Zeek не найден")
    outdir.mkdir(parents=True, exist_ok=True)
    zc = cfg["zeek"]
    nets = ", ".join(_zeek_subnet(n) for n in cfg["local_nets"])
    params = outdir / "params.zeek"
    params.write_text(
        f"redef Site::local_nets += {{ {nets} }};\n"
        f"redef TrafficLens::extract_enabled = {'T' if zc.get('extract_files', True) else 'F'};\n"
        f"redef FileExtract::default_limit = {int(zc.get('extract_max_mb', 50)) * 1024 * 1024};\n",
        encoding="utf-8",
    )
    rc = _run([zb, "-C", "-r", str(pcap.resolve()), str(ZEEK_SCRIPT), str(params)], outdir, logfile, int(zc.get("timeout_min", 120)))
    if rc != 0 or not (outdir / "conn.log").exists():
        # пустой трафик без соединений — тоже не ошибка, если Zeek отработал
        if rc != 0:
            raise ToolError(f"Zeek завершился с кодом {rc}, см. журнал задачи")


def run_suricata(cfg: Config, pcap: Path, outdir: Path, logfile: Path) -> bool:
    sc = cfg["suricata"]
    if not sc.get("enabled", True):
        return False
    sb = suricata_bin(cfg)
    if not sb:
        with logfile.open("a") as lf:
            lf.write("Suricata не найдена — пропускаю сигнатурный анализ\n")
        return False
    outdir.mkdir(parents=True, exist_ok=True)
    rules = rules_file(cfg)
    if rules is None:
        rules = outdir / "empty.rules"
        rules.write_text("")
    cmd = [sb, "-r", str(pcap.resolve()), "-l", str(outdir), "-k", "none", "-S", str(rules),
           "--set", "app-layer.protocols.tls.ja3-fingerprints=yes",
           "--set", "app-layer.protocols.tls.ja4-fingerprints=yes",
           "--set", "unix-command.enabled=no"]
    if sc.get("config") and Path(sc["config"]).exists():
        cmd[1:1] = ["-c", sc["config"]]
    rc = _run(cmd, outdir, logfile, int(sc.get("timeout_min", 120)))
    if rc != 0:
        with logfile.open("a") as lf:
            lf.write("Suricata завершилась с ошибкой — отчёт будет без сигнатурных срабатываний\n")
        return False
    return True


def update_rules(cfg: Config) -> tuple[bool, str]:
    su = shutil.which("suricata-update")
    if not su:
        return False, "suricata-update не установлен"
    out = cfg.rules_dir / "rules"
    data = cfg.rules_dir / "data"
    out.mkdir(parents=True, exist_ok=True)
    data.mkdir(parents=True, exist_ok=True)
    cmd = [su, "--data-dir", str(data), "--output", str(out), "--no-test", "--no-reload"]
    if Path(cfg["suricata"]["config"]).exists():
        cmd += ["--suricata-conf", cfg["suricata"]["config"]]
    sb = suricata_bin(cfg)
    if sb:
        cmd += ["--suricata", sb]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
    except subprocess.TimeoutExpired:
        return False, "таймаут suricata-update"
    tail = (r.stdout + r.stderr).strip().splitlines()[-3:]
    return r.returncode == 0, " | ".join(tail)[-400:]
