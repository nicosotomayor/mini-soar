#!/usr/bin/env python3
"""
Mini-SOAR - Orquestador principal del pipeline
Combina las etapas del proyecto: triage de alertas (Etapa 2),
mapeo a MITRE ATT&CK (Etapa 3), enriquecimiento de IOCs (Etapa 1)
y generacion automatica de informes de incidentes (Etapa 4)
para las alertas mas criticas.

El flujo completo es: triage inicial -> enriquecimiento del IOC ->
recalculo de riesgo -> prioridad final del reporte.

Autor: Nicolas Sotomayor

Uso:
    python main.py [ruta_al_archivo_de_alertas.json]
"""

import sys
from colorama import Fore, Style, init

from src.alert_triage import (
    load_alerts,
    triage_alerts,
    escalate_priority,
    PRIORITY_ACTIONS,
    PRIORITY_COLORS,
)
from src.mitre_mapper import get_techniques
from src.ioc_enrichment import gather_evidence
from src.report_generator import save_report

init(autoreset=True)

DEFAULT_ALERTS_FILE = "data/sample_alerts.json"
ENRICH_PRIORITIES = {"P1", "P2"}


def print_banner():
    print(Fore.CYAN + Style.BRIGHT + "=== Mini-SOAR :: Pipeline completo ===")


def enrich_if_needed(alert):
    """Enriquece el IOC de la alerta sin importar la prioridad inicial.
    Si solo enriqueciera las alertas que ya son P1/P2, una alerta P3 con
    un IOC realmente critico nunca se consultaria contra threat intel, y
    escalate_priority() jamas podria subirla a P1. El orden correcto es
    triage inicial -> enriquecimiento -> recalculo de prioridad final."""
    ioc = alert.get("ioc")
    if ioc in (None, "", "N/A"):
        return None
    return gather_evidence(ioc)


def print_report(alert, score, priority, color, enrichment):
    print(Style.BRIGHT + f"\n{alert.get('id')} - {alert.get('alert_type')}")
    print(f"  Severidad: {alert.get('severity')} | Criticidad del activo: {alert.get('asset_criticality')}")
    print(f"  Score de triage inicial: {score}")
    print(color + Style.BRIGHT + f"  Prioridad final: {priority}")
    print(f"  Accion recomendada: {PRIORITY_ACTIONS[priority]}")
    techniques = get_techniques(alert.get("alert_type"))
    print("  Tecnicas MITRE ATT&CK:")
    for tech in techniques:
        print(Fore.MAGENTA + f"    [{tech['id']}] {tech['name']} ({tech['tactic']}) | confianza: {tech['confidence']} | evidencia: {tech['evidence']}")
    if enrichment:
        verdict = enrichment["verdict"]
        vcolor = enrichment["color"]
        print(vcolor + Style.BRIGHT + f"  Veredicto de enriquecimiento del IOC: {verdict}")
        if verdict == "SIN DATOS":
            print(Fore.YELLOW + "  Nota: sin datos suficientes para confirmar reputacion. No se asume que sea benigno.")


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
        enrichment = enrich_if_needed(alert)
        final_priority = priority
        final_color = color
        if enrichment:
            final_priority = escalate_priority(priority, enrichment["verdict"])
            final_color = PRIORITY_COLORS[final_priority]

        print_report(alert, score, final_priority, final_color, enrichment)

        if final_priority in ENRICH_PRIORITIES:
            report_path = save_report(alert, score, final_priority, PRIORITY_ACTIONS[final_priority], enrichment)
            print(Fore.GREEN + f"  Informe guardado en: {report_path}")


if __name__ == "__main__":
    main()
