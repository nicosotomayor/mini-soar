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

try:
    from src.ioc_enrichment import detect_ioc_type
except ImportError:
    from ioc_enrichment import detect_ioc_type

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

PRIORITY_COLORS = {
    "P1": Fore.RED,
    "P2": Fore.YELLOW,
    "P3": Fore.CYAN,
    "P4": Fore.GREEN,
}

PRIORITY_ORDER = ["P1", "P2", "P3", "P4"]


def load_alerts(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def score_alert(alert):
    sev = SEVERITY_WEIGHTS.get(alert.get("severity", "low"), 1)
    crit = CRITICALITY_WEIGHTS.get(alert.get("asset_criticality", "low"), 1)
    score = sev * crit
    ioc = alert.get("ioc")
    if ioc and detect_ioc_type(ioc) != "unknown":
        score += 2
    return score


def classify_priority(score):
    if score >= 14:
        priority = "P1"
    elif score >= 9:
        priority = "P2"
    elif score >= 4:
        priority = "P3"
    else:
        priority = "P4"
    return priority, PRIORITY_COLORS[priority]


def escalate_priority(priority, verdict):
    """Sube la prioridad si el enriquecimiento revela una amenaza real.
    Nunca la baja: la ausencia de datos (SIN DATOS) no debe usarse para
    restar urgencia a una alerta."""
    if verdict == "CRITICO":
        target = "P1"
    elif verdict == "ALTO":
        target = "P2"
    else:
        target = priority
    if PRIORITY_ORDER.index(target) < PRIORITY_ORDER.index(priority):
        return target
    return priority


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
