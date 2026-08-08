#!/usr/bin/env python3
"""
Mini-SOAR - Etapa 3: Mapeo a MITRE ATT&CK
Asocia el tipo de alerta detectado con las tacticas y tecnicas
correspondientes del framework MITRE ATT&CK, junto con un nivel de
confianza y la evidencia que lo respalda, para evitar mapeos
absolutos y reflejar criterio analitico.

El mapa de tecnicas (ATTACK_MAP) vive en data/attack_map.json en vez
de estar hardcodeado en este modulo, para poder actualizarlo o
ampliarlo sin tocar el codigo Python.

Autor: Nicolas Sotomayor
"""

import json
import sys
from pathlib import Path

from colorama import Fore, Style, init

init(autoreset=True)

ATTACK_MAP_PATH = Path(__file__).resolve().parent.parent / "data" / "attack_map.json"

with open(ATTACK_MAP_PATH, "r", encoding="utf-8") as f:
    ATTACK_MAP = json.load(f)

DEFAULT_TECHNIQUE = [{"id": "N/A", "name": "Sin mapeo disponible", "tactic": "N/A", "confidence": "n/a", "evidence": "sin_datos"}]


def get_techniques(alert_type):
    return ATTACK_MAP.get(alert_type, DEFAULT_TECHNIQUE)


def print_techniques(alert_type):
    techniques = get_techniques(alert_type)
    print(Style.BRIGHT + f"Tecnicas MITRE ATT&CK para '{alert_type}':")
    for tech in techniques:
        print(Fore.MAGENTA + f"  [{tech['id']}] {tech['name']} ({tech['tactic']}) | confianza: {tech['confidence']} | evidencia: {tech['evidence']}")


def main():
    alert_type = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else input("Tipo de alerta: ")
    print_techniques(alert_type)


if __name__ == "__main__":
    main()
