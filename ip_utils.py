"""
ip_utils.py — IP Validation, Threat Scoring & Geolocation
===========================================================
Provides:
  - IP address validation (IPv4 + CIDR)
  - Private/reserved IP detection
  - Threat score calculation based on behaviour patterns
  - Geolocation via ip-api.com (free, no API key needed)
"""

import re
import socket
import ipaddress
import urllib.request
import urllib.error
import json
from datetime import datetime


# ── IP Validation ──────────────────────────────────────────────────────────────

def is_valid_ip(ip: str) -> bool:
    """Return True if *ip* is a valid IPv4 address or CIDR range."""
    try:
        ipaddress.ip_network(ip, strict=False)
        return True
    except ValueError:
        return False


def is_private_ip(ip: str) -> bool:
    """Return True if *ip* is a private/reserved address."""
    try:
        return ipaddress.ip_address(ip.split("/")[0]).is_private
    except ValueError:
        return False


def is_loopback(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


# ── Geolocation ────────────────────────────────────────────────────────────────

def geolocate(ip: str, timeout: int = 5) -> dict:
    """
    Look up geolocation for *ip* using ip-api.com (free, no key needed).
    Returns a dict with country, city, org, etc.
    Falls back gracefully if offline.
    """
    clean_ip = ip.split("/")[0]
    if is_private_ip(clean_ip) or is_loopback(clean_ip):
        return {"country": "Private", "city": "—", "org": "Local Network",
                "isp": "—", "lat": 0.0, "lon": 0.0, "error": None}

    url = f"http://ip-api.com/json/{clean_ip}?fields=status,country,countryCode,city,org,isp,lat,lon,query"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "FirewallManager/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        if data.get("status") == "success":
            return {
                "country":      data.get("country", "Unknown"),
                "country_code": data.get("countryCode", "??"),
                "city":         data.get("city", "Unknown"),
                "org":          data.get("org", "Unknown"),
                "isp":          data.get("isp", "Unknown"),
                "lat":          data.get("lat", 0.0),
                "lon":          data.get("lon", 0.0),
                "error":        None,
            }
    except Exception as exc:
        pass

    return {"country": "Unknown", "city": "—", "org": "—",
            "isp": "—", "lat": 0.0, "lon": 0.0, "error": "Lookup failed"}


# ── Threat scoring ─────────────────────────────────────────────────────────────

# Known malicious ASN prefixes / org keywords
SUSPICIOUS_ORGS = [
    "tor ", "exit", "vpn", "proxy", "hosting", "cloud", "vps",
    "datacenter", "data center", "amazon", "digitalocean", "linode",
    "vultr", "hetzner", "ovh", "choopa", "psychz",
]

# High-risk country codes (for demonstration — not political judgement)
HIGH_RISK_COUNTRIES = {"CN", "RU", "KP", "IR", "NG", "BR", "IN", "UA"}


def threat_score(ip: str, geo: dict, hit_count: int = 1) -> tuple[int, str]:
    """
    Calculate a threat score (0–100) and label for an IP.

    Returns: (score, label)
    """
    score = 0

    # Hit count contribution
    if hit_count >= 100: score += 30
    elif hit_count >= 50: score += 20
    elif hit_count >= 10: score += 10
    elif hit_count >= 3:  score += 5

    # Geo risk
    cc = geo.get("country_code", "")
    if cc in HIGH_RISK_COUNTRIES:
        score += 20

    # Org / ISP keywords
    org_lower = (geo.get("org", "") + " " + geo.get("isp", "")).lower()
    for keyword in SUSPICIOUS_ORGS:
        if keyword in org_lower:
            score += 15
            break

    # Private IPs are trusted
    if is_private_ip(ip):
        score = 0

    score = min(score, 100)

    if score >= 70: label = "CRITICAL"
    elif score >= 50: label = "HIGH"
    elif score >= 30: label = "MEDIUM"
    elif score >= 10: label = "LOW"
    else:             label = "SAFE"

    return score, label


THREAT_COLORS = {
    "CRITICAL": "#ff4c4c",
    "HIGH":     "#ff8c00",
    "MEDIUM":   "#ffd700",
    "LOW":      "#4fc3f7",
    "SAFE":     "#4caf50",
}


def threat_color(label: str) -> str:
    return THREAT_COLORS.get(label, "#ffffff")
