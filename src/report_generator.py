"""
report_generator.py - Generador de informes de incidentes (Etapa 4)

Genera un informe en Markdown para las alertas mas criticas (P1/P2),
consolidando la triage, las tecnicas MITRE ATT&CK asociadas y el
veredicto de enriquecimiento del IOC cuando este disponible.
"""

import os
import re
from datetime import datetime

from src.mitre_mapper import get_techniques

REPORTS_DIR = "reports"


def _slugify(text):
    text = str(text).lower()
    text = re.sub(r"[^a-z0-9]+", "_", text).strip("_")
    return text or "alerta"


def build_report(alert, score, priority, action, enrichment=None):
    """Construye el contenido Markdown del informe de un incidente."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    techniques = get_techniques(alert.get("alert_type"))

    lines = [
        f"# Informe de Incidente - {alert.get('id', 'N/A')}",
        "",
        f"**Generado:** {timestamp}",
        "",
        "## Resumen de la alerta",
        "",
        f"- **Tipo:** {alert.get('alert_type', 'N/A')}",
        f"- **Severidad:** {alert.get('severity', 'N/A')}",
        f"- **Criticidad del activo:** {alert.get('asset_criticality', 'N/A')}",
        f"- **IOC:** {alert.get('ioc', 'N/A')}",
        "",
        "## Triage",
        "",
        f"- **Prioridad:** {priority}",
        f"- **Score:** {score}",
        f"- **Accion recomendada:** {action}",
        "",
        "## Tecnicas MITRE ATT&CK asociadas",
        "",
    ]

    if techniques:
        for tech in techniques:
            lines.append(f"- **{tech['id']}** - {tech['name']} (Tactica: {tech['tactic']})")
    else:
        lines.append("- No se identificaron tecnicas asociadas.")

    lines += ["", "## Enriquecimiento de IOC", ""]

    if enrichment:
        verdict, _color = enrichment
        lines.append(f"- **Indicador analizado:** {alert.get('ioc', 'N/A')}")
        lines.append(f"- **Veredicto:** {verdict}")
    else:
        lines.append("- No se realizo enriquecimiento de IOC para esta alerta.")

    lines += [
        "",
        "---",
        "*Informe generado automaticamente por Mini-SOAR.*",
        "",
    ]

    return "\n".join(lines)


def save_report(alert, score, priority, action, enrichment=None, output_dir=REPORTS_DIR):
    """Genera el informe y lo guarda como archivo .md. Devuelve la ruta creada."""
    os.makedirs(output_dir, exist_ok=True)
    content = build_report(alert, score, priority, action, enrichment)
    filename = f"{_slugify(alert.get('id', 'alerta'))}.md"
    filepath = os.path.join(output_dir, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)
    return filepath


if __name__ == "__main__":
    sample_alert = {
        "id": "ALERT-001",
        "alert_type": "brute_force",
        "severity": "high",
        "asset_criticality": "critical",
        "ioc": "185.220.101.5",
    }
    path = save_report(
        sample_alert,
        score=92,
        priority="P1",
        action="Escalar a Nivel 2 inmediatamente",
        enrichment=("MALICIOUS", ""),
    )
    print(f"Informe generado en: {path}")
