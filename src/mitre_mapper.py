#!/usr/bin/env python3
"""
Mini-SOAR - Etapa 3: Mapeo a MITRE ATT&CK
Asocia el tipo de alerta detectado con las tacticas y tecnicas
correspondientes del framework MITRE ATT&CK, junto con un nivel de
confianza y la evidencia que lo respalda, para evitar mapeos
absolutos y reflejar criterio analitico.

Autor: Nicolas Sotomayor
"""

import sys
from colorama import Fore, Style, init

init(autoreset=True)

ATTACK_MAP = {
    "Brute Force SSH": [
        {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access", "confidence": "high", "evidence": "repeated_auth_failures"},
        {"id": "T1021.004", "name": "Remote Services: SSH", "tactic": "Lateral Movement", "confidence": "medium", "evidence": "ssh_service_targeted"},
    ],
    "Phishing Email": [
        {"id": "T1566", "name": "Phishing", "tactic": "Initial Access", "confidence": "high", "evidence": "phishing_email"},
        {"id": "T1204", "name": "User Execution", "tactic": "Execution", "confidence": "low", "evidence": "no_confirmed_execution"},
    ],
    "Port Scan": [
        {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery", "confidence": "high", "evidence": "port_scan_detected"},
    ],
    "C2 Beaconing": [
        {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control", "confidence": "high", "evidence": "beacon_pattern_detected"},
        {"id": "T1571", "name": "Non-Standard Port", "tactic": "Command and Control", "confidence": "medium", "evidence": "uncommon_port_usage"},
    ],
    "Malware Detected": [
        {"id": "T1204", "name": "User Execution", "tactic": "Execution", "confidence": "medium", "evidence": "malware_execution_suspected"},
        {"id": "T1055", "name": "Process Injection", "tactic": "Defense Evasion", "confidence": "low", "evidence": "not_confirmed_by_alert"},
    ],
    "Failed Login": [
        {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access", "confidence": "medium", "evidence": "failed_login_attempts"},
    ],
    "Data Exfiltration": [
        {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration", "confidence": "medium", "evidence": "outbound_data_transfer_detected"},
    ],
    "Suspicious PowerShell": [
        {"id": "T1059.001", "name": "PowerShell", "tactic": "Execution", "confidence": "high", "evidence": "powershell_execution_detected"},
        {"id": "T1027", "name": "Obfuscated Files or Information", "tactic": "Defense Evasion", "confidence": "medium", "evidence": "possible_obfuscation_patterns"},
    ],
}

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
