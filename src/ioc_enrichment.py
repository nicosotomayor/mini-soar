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
import requests
from colorama import Fore, Style, init

init(autoreset=True)

VT_API_KEY = os.getenv("VT_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

VT_URL = "https://www.virustotal.com/api/v3"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

IP_REGEX = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
HASH_REGEX = re.compile(r"^[a-fA-F0-9]{32,64}$")
DOMAIN_REGEX = re.compile(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")


def detect_ioc_type(ioc):
    if IP_REGEX.match(ioc):
        return "ip"
    if HASH_REGEX.match(ioc):
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


def print_banner():
    print(Fore.CYAN + Style.BRIGHT + "=== Mini-SOAR :: Enriquecimiento de IOCs ===")


def print_result(ioc, ioc_type, vt_stats, abuse_data, verdict, color):
    print(Style.BRIGHT + f"\nIOC: {ioc} ({ioc_type})")
    if vt_stats:
        print(f"  VirusTotal -> malicioso: {vt_stats.get('malicious', 0)}, sospechoso: {vt_stats.get('suspicious', 0)}")
    else:
        print("  VirusTotal -> sin datos")
    if abuse_data:
        print(f"  AbuseIPDB -> confianza de abuso: {abuse_data.get('abuseConfidenceScore', 0)}%")
    else:
        print("  AbuseIPDB -> sin datos")
    print(color + Style.BRIGHT + f"  Veredicto: {verdict}")


def enrich_ioc(ioc):
    ioc_type = detect_ioc_type(ioc)
    vt_stats = check_virustotal(ioc, ioc_type) if ioc_type != "unknown" else None
    abuse_data = check_abuseipdb(ioc) if ioc_type == "ip" else None
    verdict, color = score_verdict(vt_stats, abuse_data)
    print_result(ioc, ioc_type, vt_stats, abuse_data, verdict, color)


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
