"""
rule_engine.py — Firewall Rule Storage & Management
=====================================================
Manages firewall rules in a local JSON file (rules.json).

Rule schema:
  {
    "id":         str,     # unique rule ID e.g. FW-0001
    "action":     str,     # BLOCK | ALLOW
    "ip":         str,     # IPv4 address or CIDR
    "reason":     str,     # human-readable reason
    "added_by":   str,     # "manual" | "auto"
    "created_at": str,     # ISO timestamp
    "hits":       int,     # times this rule was triggered
    "active":     bool,
    "geo":        dict,    # geolocation data
    "threat":     str,     # CRITICAL|HIGH|MEDIUM|LOW|SAFE
    "threat_score": int,
  }

Auto-block threat rules — triggers:
  - Same IP seen 5+ times in the activity log
  - Threat score >= 50
"""

import json
import uuid
from pathlib import Path
from datetime import datetime
from typing import Optional
import ip_utils as ipu


RULES_FILE   = Path("rules.json")
ACTIVITY_LOG = Path("activity.log")
MAX_LOG_LINES = 1000


# ── Persistence ────────────────────────────────────────────────────────────────

def _load() -> dict:
    if RULES_FILE.exists():
        try:
            return json.loads(RULES_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"rules": [], "counter": 0}


def _save(data: dict):
    RULES_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _next_id(data: dict) -> str:
    data["counter"] = data.get("counter", 0) + 1
    return f"FW-{data['counter']:04d}"


# ── Core operations ────────────────────────────────────────────────────────────

def add_rule(
    ip: str,
    action: str,
    reason: str = "",
    added_by: str = "manual",
    geo: Optional[dict] = None,
) -> dict:
    """
    Add a new BLOCK or ALLOW rule.
    Returns the created rule dict.
    Raises ValueError for invalid IP or duplicate active rule.
    """
    action = action.upper()
    if action not in ("BLOCK", "ALLOW"):
        raise ValueError("Action must be BLOCK or ALLOW")

    if not ipu.is_valid_ip(ip):
        raise ValueError(f"Invalid IP address or CIDR: {ip}")

    data  = _load()
    rules = data["rules"]

    # Check for existing active rule
    for r in rules:
        if r["ip"] == ip and r["active"]:
            raise ValueError(
                f"An active {r['action']} rule for {ip} already exists (ID: {r['id']}). "
                f"Remove it first with: firewall_manager.py remove --id {r['id']}"
            )

    if geo is None:
        geo = ipu.geolocate(ip)

    score, label = ipu.threat_score(ip, geo)

    rule = {
        "id":           _next_id(data),
        "action":       action,
        "ip":           ip,
        "reason":       reason or f"{action} rule added by {added_by}",
        "added_by":     added_by,
        "created_at":   datetime.now().isoformat(timespec="seconds"),
        "hits":         0,
        "active":       True,
        "geo":          geo,
        "threat":       label,
        "threat_score": score,
    }

    data["rules"].append(rule)
    _save(data)
    _log(f"[{action}] Rule {rule['id']} added for {ip} — {reason}")
    return rule


def remove_rule(rule_id: str) -> dict:
    """Deactivate a rule by ID. Returns the removed rule."""
    data  = _load()
    for rule in data["rules"]:
        if rule["id"] == rule_id and rule["active"]:
            rule["active"]     = False
            rule["removed_at"] = datetime.now().isoformat(timespec="seconds")
            _save(data)
            _log(f"[REMOVE] Rule {rule_id} removed ({rule['ip']})")
            return rule
    raise ValueError(f"No active rule found with ID: {rule_id}")


def get_rules(
    action: Optional[str] = None,
    active_only: bool = True,
) -> list[dict]:
    """Return rules, optionally filtered by action and active status."""
    rules = _load()["rules"]
    if active_only:
        rules = [r for r in rules if r["active"]]
    if action:
        rules = [r for r in rules if r["action"] == action.upper()]
    return sorted(rules, key=lambda r: r["created_at"], reverse=True)


def get_rule_by_ip(ip: str) -> Optional[dict]:
    """Return the active rule for *ip* if one exists."""
    for rule in get_rules(active_only=True):
        if rule["ip"] == ip:
            return rule
    return None


def increment_hits(rule_id: str):
    """Increment the hit counter for a rule."""
    data = _load()
    for rule in data["rules"]:
        if rule["id"] == rule_id:
            rule["hits"] = rule.get("hits", 0) + 1
            break
    _save(data)


def get_stats() -> dict:
    """Return summary statistics for the dashboard."""
    rules  = _load()["rules"]
    active = [r for r in rules if r["active"]]
    return {
        "total_rules":   len(rules),
        "active_rules":  len(active),
        "blocked":       sum(1 for r in active if r["action"] == "BLOCK"),
        "allowed":       sum(1 for r in active if r["action"] == "ALLOW"),
        "auto_blocked":  sum(1 for r in active if r["added_by"] == "auto"),
        "critical_ips":  sum(1 for r in active if r.get("threat") == "CRITICAL"),
    }


# ── Auto-block engine ──────────────────────────────────────────────────────────

# Simulated threat intelligence feed (demo IPs)
KNOWN_THREATS = {
    "185.220.101.1":  "Known Tor exit node",
    "45.155.205.233": "Known C2 server",
    "194.165.16.11":  "Brute-force source",
    "91.108.4.0":     "Port scanner",
    "198.54.117.200": "Credential stuffing source",
    "162.247.74.200": "Malware distribution",
    "77.247.181.165": "Spam/phishing source",
    "199.87.154.255": "Known botnet node",
}

# Simulated live traffic feed for demo
DEMO_TRAFFIC = [
    {"ip": "185.220.101.1",  "hits": 150, "event": "SSH brute force"},
    {"ip": "45.155.205.233", "hits": 87,  "event": "Port scan"},
    {"ip": "194.165.16.11",  "hits": 43,  "event": "HTTP flood"},
    {"ip": "91.108.4.0",     "hits": 210, "event": "SQL injection attempt"},
    {"ip": "10.0.0.5",       "hits": 2,   "event": "Normal traffic"},
    {"ip": "192.168.1.10",   "hits": 1,   "event": "Internal request"},
    {"ip": "198.54.117.200", "hits": 55,  "event": "Credential stuffing"},
    {"ip": "162.247.74.200", "hits": 30,  "event": "Malware beacon"},
]


def run_auto_block(threshold_hits: int = 10, threshold_score: int = 50) -> list[dict]:
    """
    Analyse traffic and auto-block IPs that exceed thresholds.
    Returns list of newly created rules.
    """
    new_rules = []

    for entry in DEMO_TRAFFIC:
        ip   = entry["ip"]
        hits = entry["hits"]

        # Skip private IPs
        if ipu.is_private_ip(ip):
            continue

        # Skip if already has an active rule
        if get_rule_by_ip(ip):
            continue

        geo         = ipu.geolocate(ip)
        score, label = ipu.threat_score(ip, geo, hit_count=hits)

        reason = None
        if ip in KNOWN_THREATS:
            reason = f"Known threat: {KNOWN_THREATS[ip]}"
        elif hits >= threshold_hits:
            reason = f"Excessive hits: {hits} ({entry['event']})"
        elif score >= threshold_score:
            reason = f"High threat score: {score}/100 ({label})"

        if reason:
            try:
                rule = add_rule(ip, "BLOCK", reason=reason, added_by="auto", geo=geo)
                new_rules.append(rule)
            except ValueError:
                pass   # Already blocked

    return new_rules


# ── Activity log ───────────────────────────────────────────────────────────────

def _log(message: str):
    ts   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {message}\n"
    try:
        with open(ACTIVITY_LOG, "a", encoding="utf-8") as f:
            f.write(line)
    except Exception:
        pass


def get_activity_log(lines: int = 20) -> list[str]:
    """Return the last *lines* entries from the activity log."""
    if not ACTIVITY_LOG.exists():
        return []
    try:
        all_lines = ACTIVITY_LOG.read_text(encoding="utf-8").splitlines()
        return all_lines[-lines:]
    except Exception:
        return []
