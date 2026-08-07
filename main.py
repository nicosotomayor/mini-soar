#!/usr/bin/env python3
"""
Mini-SOAR - Orquestador principal del pipeline
Combina las etapas del proyecto: triage de alertas (Etapa 2),
mapeo a MITRE ATT&CK (Etapa 3) y enriquecimiento de IOCs (Etapa 1)
para las alertas mas criticas, generando un reporte consolidado
por cada alerta.

Autor: Nicolas Sotomayor

Uso:
    python main.py [ruta_al_archivo_de_alertas.json]
"""

import sys
from colorama import Fore, Style, init

from src.alert_triage import load_alerts, triage_alerts, PRIORITY_ACTIONS
from src.mitre_mapper import get_techniques
from src.ioc_enrichment import detect_ioc_type, check_virustotal, check_abuseipdb, score_verdict

init(autoreset=True)

DEFAULT_ALERTS_FILE = "data/sample_alerts.json"
ENRICH_PRIORITIES = {"P1", "P2"}


def print_banner():
    print(Fore.CYAN + Style.BRIGHT + "=== Mini-SOAR :: Pipeline completo ===")


def enrich_if_needed(alert, priority):
    ioc = alert.get("ioc")
    if priority not in ENRICH_PRIORITIES or ioc in (None, "", "N/A"):
        return None
    ioc_type = detect_ioc_type(ioc)
    if ioc_type == "unknown":
        return None
    vt_stats = check_virustotal(ioc, ioc_type)
    abuse_data = check_abuseipdb(ioc) if ioc_type == "ip" else None
    verdict, color = score_verdict(vt_stats, abuse_data)
    return verdict, color


def print_report(alert, score, priority, color, enrichment):
    print(Style.BRIGHT + f"\n{alert.get('id')} - {alert.get('alert_type')}")
    print(f"  Severidad: {alert.get('severity')} | Criticidad del activo: {alert.get('asset_criticality')}")
    print(color + Style.BRIGHT + f"  Prioridad de triage: {priority} (score {score})")
    print(f"  Accion recomendada: {PRIORITY_ACTIONS[priority]}")
    techniques = get_techniques(alert.get("alert_type"))
    print("  Tecnicas MITRE ATT&CK:")
    for tech in techniques:
        print(Fore.MAGENTA + f"    [{tech['id']}] {tech['name']} ({tech['tactic']})")
    if enrichment:
        verdict, vcolor = enrichment
        print(vcolor + Style.BRIGHT + f"  Veredicto de enriquecimiento del IOC: {verdict}")


def main():
    print_banner()
    path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_ALERTS_FILE
    try:
        alerts = load_alerts(path)
    except FileNotFoundError:
        print(Fore.RED + f"No se encontro el archivo de alertas: {path}")
        return
    if not alerts:
        print(Fore.RED + "No hay alertas para procesar.")
        return
    ranked = triage_alerts(alerts)
    for score, priority, color, alert in ranked:
        enrichment = enrich_if_needed(alert, priority)
        print_report(alert, score, priority, color, enrichment)


if __name__ == "__main__":
    main()
