#!/usr/bin/env python3
"""
Mini-SOAR - Etapa 1: Enriquecimiento automatico de IOCs
Consulta VirusTotal y AbuseIPDB para IPs, hashes y dominios,
y genera un veredicto de severidad para apoyar el triage.

Autor: Nicolas Sotomayor
"""

import os
import re
import sys
import ipaddress
from datetime import datetime, timezone

import requests
from colorama import Fore, Style, init

init(autoreset=True)

VT_API_KEY = os.getenv("VT_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

VT_URL = "https://www.virustotal.com/api/v3"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

HEX_REGEX = re.compile(r"^[a-fA-F0-9]+$")
DOMAIN_REGEX = re.compile(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")

HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}


def _is_valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _hash_algorithm(value):
    if HEX_REGEX.match(value) and len(value) in HASH_LENGTHS:
        return HASH_LENGTHS[len(value)]
    return None


def detect_ioc_type(ioc):
    ioc = ioc.strip()
    if _is_valid_ip(ioc):
        return "ip"
    if _hash_algorithm(ioc):
        return "hash"
    if DOMAIN_REGEX.match(ioc):
        return "domain"
    return "unknown"


def check_virustotal(ioc, ioc_type):
    if not VT_API_KEY:
        return None
    endpoint = {"ip": "ip_addresses", "hash": "files", "domain": "domains"}.get(ioc_type)
    if not endpoint:
        return None
    headers = {"x-apikey": VT_API_KEY}
    url = f"{VT_URL}/{endpoint}/{ioc}"
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code != 200:
            return None
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        return stats
    except requests.RequestException:
        return None


def check_abuseipdb(ip):
    if not ABUSEIPDB_API_KEY:
        return None
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        resp = requests.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=15)
        if resp.status_code != 200:
            return None
        return resp.json()["data"]
    except requests.RequestException:
        return None


def score_verdict(vt_stats, abuse_data):
    if vt_stats is None and abuse_data is None:
        return "SIN DATOS", Fore.LIGHTBLACK_EX

    score = 0
    if vt_stats:
        score += vt_stats.get("malicious", 0) * 10
        score += vt_stats.get("suspicious", 0) * 5
    if abuse_data:
        score += abuse_data.get("abuseConfidenceScore", 0)
    if score >= 50:
        return "CRITICO", Fore.RED
    if score >= 20:
        return "ALTO", Fore.YELLOW
    if score > 0:
        return "MEDIO", Fore.CYAN
    return "LIMPIO", Fore.GREEN


def gather_evidence(ioc):
    """Recolecta toda la evidencia real de un IOC: tipo, datos crudos de las
    APIs, veredicto y momento en que se realizo la consulta. Pensada para ser
    reutilizada tanto por main.py como por report_generator.py, de forma que
    los reportes muestren evidencia real y no solo un veredicto final."""
    ioc = ioc.strip()
    ioc_type = detect_ioc_type(ioc)
    vt_stats = check_virustotal(ioc, ioc_type) if ioc_type != "unknown" else None
    abuse_data = check_abuseipdb(ioc) if ioc_type == "ip" else None
    verdict, color = score_verdict(vt_stats, abuse_data)
    return {
        "ioc": ioc,
        "ioc_type": ioc_type,
        "vt_stats": vt_stats,
        "abuse_data": abuse_data,
        "verdict": verdict,
        "color": color,
        "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    }


def print_banner():
    print(Fore.CYAN + Style.BRIGHT + "=== Mini-SOAR :: Enriquecimiento de IOCs ===")


def print_result(evidence):
    ioc = evidence["ioc"]
    ioc_type = evidence["ioc_type"]
    vt_stats = evidence["vt_stats"]
    abuse_data = evidence["abuse_data"]
    verdict = evidence["verdict"]
    color = evidence["color"]

    print(Style.BRIGHT + f"\nIOC: {ioc} ({ioc_type})")
    if ioc_type == "unknown":
        print(Fore.YELLOW + "  Tipo de IOC no reconocido, no se realizo consulta.")
    if vt_stats:
        print(f"  VirusTotal -> malicioso: {vt_stats.get('malicious', 0)}, sospechoso: {vt_stats.get('suspicious', 0)}")
    else:
        print("  VirusTotal -> sin datos")
    if abuse_data:
        print(f"  AbuseIPDB -> confianza de abuso: {abuse_data.get('abuseConfidenceScore', 0)}%")
    else:
        print("  AbuseIPDB -> sin datos")
    print(color + Style.BRIGHT + f"  Veredicto: {verdict}")
    if verdict == "SIN DATOS":
        print(Fore.YELLOW + "  Nota: no se pudo determinar la reputacion real (sin API keys o sin respuesta)."
                             " No asumir que el IOC es benigno.")


def enrich_ioc(ioc):
    evidence = gather_evidence(ioc)
    print_result(evidence)
    return evidence


def main():
    print_banner()
    if len(sys.argv) > 1:
        iocs = sys.argv[1:]
    else:
        raw = input("Ingresa uno o mas IOCs separados por coma: ")
        iocs = [x.strip() for x in raw.split(",") if x.strip()]
    if not iocs:
        print(Fore.RED + "No se ingreso ningun IOC.")
        return
    for ioc in iocs:
        enrich_ioc(ioc)


if __name__ == "__main__":
    main()
