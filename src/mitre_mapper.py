#!/usr/bin/env python3
"""
Mini-SOAR - Etapa 3: Mapeo a MITRE ATT&CK
Asocia el tipo de alerta detectado con las tacticas y tecnicas
correspondientes del framework MITRE ATT&CK, para dar contexto
al analista sobre el comportamiento del atacante.

Autor: Nicolas Sotomayor
"""

import sys
from colorama import Fore, Style, init

init(autoreset=True)

ATTACK_MAP = {
    "Brute Force SSH": [
        {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
        {"id": "T1021.004", "name": "Remote Services: SSH", "tactic": "Lateral Movement"},
    ],
    "Phishing Email": [
        {"id": "T1566", "name": "Phishing", "tactic": "Initial Access"},
        {"id": "T1204", "name": "User Execution", "tactic": "Execution"},
    ],
    "Port Scan": [
        {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
    ],
    "C2 Beaconing": [
        {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"},
        {"id": "T1571", "name": "Non-Standard Port", "tactic": "Command and Control"},
    ],
    "Malware Detected": [
        {"id": "T1204", "name": "User Execution", "tactic": "Execution"},
        {"id": "T1055", "name": "Process Injection", "tactic": "Defense Evasion"},
    ],
    "Failed Login": [
        {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    ],
    "Data Exfiltration": [
        {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
    ],
    "Suspicious PowerShell": [
        {"id": "T1059.001", "name": "PowerShell", "tactic": "Execution"},
        {"id": "T1027", "name": "Obfuscated Files or Information", "tactic": "Defense Evasion"},
    ],
}

DEFAULT_TECHNIQUE = [{"id": "N/A", "name": "Sin mapeo disponible", "tactic": "N/A"}]


def get_techniques(alert_type):
    return ATTACK_MAP.get(alert_type, DEFAULT_TECHNIQUE)


def print_techniques(alert_type):
    techniques = get_techniques(alert_type)
    print(Style.BRIGHT + f"Tecnicas MITRE ATT&CK para '{alert_type}':")
    for tech in techniques:
        print(Fore.MAGENTA + f"  [{tech['id']}] {tech['name']} ({tech['tactic']})")


def main():
    alert_type = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else input("Tipo de alerta: ")
    print_techniques(alert_type)


if __name__ == "__main__":
    main()
