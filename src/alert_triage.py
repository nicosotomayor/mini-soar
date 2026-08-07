#!/usr/bin/env python3
"""
Mini-SOAR - Etapa 2: Triage automatico de alertas
Lee alertas tipo SIEM desde un archivo JSON, calcula una prioridad
de triage combinando severidad, criticidad del activo y presencia
de IOCs conocidos, y sugiere una accion recomendada para el analista.

Autor: Nicolas Sotomayor
"""

import json
import sys
from colorama import Fore, Style, init

init(autoreset=True)

DEFAULT_ALERTS_FILE = "data/sample_alerts.json"

SEVERITY_WEIGHTS = {"low": 1, "medium": 2, "high": 3, "critical": 4}
CRITICALITY_WEIGHTS = {"low": 1, "medium": 2, "high": 3, "critical": 4}

PRIORITY_ACTIONS = {
    "P1": "Escalar de inmediato al equipo de respuesta a incidentes.",
    "P2": "Investigar en las proximas 2 horas.",
    "P3": "Investigar durante el turno actual.",
    "P4": "Registrar y revisar en el reporte diario.",
}


def load_alerts(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def score_alert(alert):
    sev = SEVERITY_WEIGHTS.get(alert.get("severity", "low"), 1)
    crit = CRITICALITY_WEIGHTS.get(alert.get("asset_criticality", "low"), 1)
    score = sev * crit
    has_ioc = alert.get("ioc") not in (None, "", "N/A")
    if has_ioc:
        score += 2
    return score


def classify_priority(score):
    if score >= 14:
        return "P1", Fore.RED
    if score >= 9:
        return "P2", Fore.YELLOW
    if score >= 4:
        return "P3", Fore.CYAN
    return "P4", Fore.GREEN


def print_banner():
    print(Fore.CYAN + Style.BRIGHT + "=== Mini-SOAR :: Triage de alertas ===")


def print_triage_row(alert, score, priority, color):
    print(Style.BRIGHT + f"\n{alert.get('id')} - {alert.get('alert_type')}")
    print(f"  Severidad: {alert.get('severity')} | Criticidad del activo: {alert.get('asset_criticality')}")
    print(f"  IOC: {alert.get('ioc')}")
    print(color + Style.BRIGHT + f"  Prioridad: {priority} (score {score})")
    print(f"  Accion recomendada: {PRIORITY_ACTIONS[priority]}")


def triage_alerts(alerts):
    scored = []
    for alert in alerts:
        score = score_alert(alert)
        priority, color = classify_priority(score)
        scored.append((score, priority, color, alert))
    scored.sort(key=lambda item: item[0], reverse=True)
    return scored


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
        print_triage_row(alert, score, priority, color)


if __name__ == "__main__":
    main()
