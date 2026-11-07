"""Сопоставление находок TrafficLens с тактиками и техниками MITRE ATT&CK.

Срабатывает при рендере отчёта (render.py), поэтому теги получают и отчёты,
собранные старыми версиями. Названия тактик/техник оставлены на английском —
это стандартная терминология ATT&CK.
"""
from __future__ import annotations

from . import quality

TACTICS = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0004": "Privilege Escalation",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0040": "Impact",
}

TECHNIQUES = {
    "T1040": "Network Sniffing",
    "T1041": "Exfiltration Over C2 Channel",
    "T1046": "Network Service Discovery",
    "T1068": "Exploitation for Privilege Escalation",
    "T1071": "Application Layer Protocol",
    "T1071.004": "DNS",
    "T1105": "Ingress Tool Transfer",
    "T1189": "Drive-by Compromise",
    "T1190": "Exploit Public-Facing Application",
    "T1204": "User Execution",
    "T1498": "Network Denial of Service",
    "T1571": "Non-Standard Port",
    "T1573": "Encrypted Channel",
}

# Категории сигнатур (поле alert.category в eve.json — описания из classification.config
# Emerging Threats) -> [(тактика, техника)]. Ключи в нижнем регистре.
ALERT_TAGS: dict[str, list[tuple[str, str]]] = {
    "a network trojan was detected": [("TA0011", "T1071")],
    "a system trojan was detected": [("TA0011", "T1071")],
    "targeted malicious activity was detected": [("TA0011", "T1071")],
    "potentially bad traffic": [("TA0011", "T1071")],
    "exploit kit activity detected": [("TA0001", "T1189")],
    "attempted information leak": [("TA0010", "T1041")],
    "information leak": [("TA0010", "T1041")],
    "large scale information leak": [("TA0010", "T1041")],
    "potential corporate privacy violation": [("TA0010", "T1041")],
    "successful administrator privilege gain": [("TA0004", "T1068")],
    "attempted administrator privilege gain": [("TA0004", "T1068")],
    "successful user privilege gain": [("TA0004", "T1068")],
    "attempted user privilege gain": [("TA0004", "T1068")],
    "unsuccessful user privilege gain": [("TA0004", "T1068")],
    "executable code was detected": [("TA0002", "T1204")],
    "web application attack": [("TA0001", "T1190")],
    "access to a potentially vulnerable web application": [("TA0001", "T1190")],
    "successful denial of service attack": [("TA0040", "T1498")],
    "attempted denial of service": [("TA0040", "T1498")],
    "detection of a denial of service attack": [("TA0040", "T1498")],
    "network scan": [("TA0007", "T1046")],
    "detection of a network scan": [("TA0007", "T1046")],
    "attempted recon": [("TA0007", "T1046")],
}


def alert_tags(category: str) -> list[tuple[str, str]]:
    """[(тактика, техника)] для категории сигнатуры Suricata; [] если маппинга нет."""
    cat = (category or "").strip().lower()
    if not cat:
        return []
    if cat in ALERT_TAGS:
        return ALERT_TAGS[cat]
    if "scan" in cat:
        return [("TA0007", "T1046")]
    if "trojan" in cat or "malware" in cat:
        return [("TA0011", "T1071")]
    return []


def mitre_summary(rep: dict) -> list[dict]:
    """Сводка по тактикам для отчёта: [{id, name, n, techs: [{id, name, n}]}]."""
    acc: dict[str, dict] = {}

    def add(tactic: str, tech: str, n: int = 1) -> None:
        if tactic not in TACTICS or not n:
            return
        t = acc.setdefault(tactic, {"id": tactic, "name": TACTICS[tactic], "n": 0, "techs": {}})
        t["n"] += n
        if tech:
            te = t["techs"].setdefault(tech, {"id": tech, "name": TECHNIQUES.get(tech, ""), "n": 0})
            te["n"] += n

    for a in rep.get("alerts") or []:
        if quality.alert_is_noise(a.get("signature", "")):
            continue
        for ta, tech in alert_tags(a.get("category", "")):
            add(ta, tech, int(a.get("count") or 1))
    f = rep.get("findings") or {}
    if f.get("beacons"):
        add("TA0011", "T1071", len(f["beacons"]))
    if f.get("large_uploads"):
        add("TA0010", "T1041", len(f["large_uploads"]))
    if f.get("cleartext"):
        add("TA0006", "T1040", len(f["cleartext"]))
    if f.get("cleartext_auth"):
        add("TA0006", "T1040", len(f["cleartext_auth"]))
    if f.get("unusual_ports"):
        add("TA0011", "T1571", len(f["unusual_ports"]))
    # Невалидный сертификат сам по себе — не Encrypted Channel (T1573): тег ставим
    # только сильным находкам (самоподписанный leaf, истёк, чужое имя) и только
    # если с того же хоста есть маячок — тогда это похоже на C2 по TLS.
    beacon_src = {b.get("src") for b in (f.get("beacons") or [])}
    strong_tls = [t for t in quality.tls_strong((rep.get("tls") or {}).get("invalid") or [])
                  if t.get("src") in beacon_src]
    if strong_tls:
        add("TA0011", "T1573", len(strong_tls))
    if (rep.get("dns") or {}).get("suspicious"):
        add("TA0011", "T1071.004", len(rep["dns"]["suspicious"]))
    ioc_files = [x for x in rep.get("files") or [] if x.get("ioc")]
    if ioc_files:
        add("TA0011", "T1105", len(ioc_files))
    if rep.get("ioc_hits"):
        add("TA0011", "T1071", len(rep["ioc_hits"]))

    out = []
    for t in acc.values():
        t["techs"] = sorted(t["techs"].values(), key=lambda x: (-x["n"], x["id"]))
        out.append(t)
    out.sort(key=lambda x: (-x["n"], x["id"]))
    return out
