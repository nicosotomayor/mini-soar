# mini-soar

Pipeline de respuesta a incidentes (SOAR) construido por etapas, pensado para automatizar el trabajo manual de un analista SOC Nivel 1: enriquecer indicadores, priorizar alertas, mapear tecnicas de ataque y documentar el resultado.

## Roadmap del proyecto

Etapa 1 (completada): enriquecimiento automatico de IOCs (IPs, dominios, hashes) contra VirusTotal y AbuseIPDB, con veredicto de severidad.

Etapa 2 (completada): triage automatico de alertas tipo SIEM, priorizando en base a severidad, criticidad del activo afectado y presencia de IOCs conocidos.

Etapa 3 (completada): mapeo automatico de cada tipo de alerta a tacticas y tecnicas del framework MITRE ATT&CK.

Etapa 4 (completada): generacion automatica de informe de incidente en Markdown para cada alerta critica.

## Etapa 1: IOC Enrichment

El script src/ioc_enrichment.py recibe una o varias IOCs (IP, dominio o hash) y devuelve tres cosas: el resultado de VirusTotal (detecciones maliciosas, sospechosas e inofensivas), el resultado de AbuseIPDB para IPs (score de abuso, cantidad de reportes, pais), y un veredicto final de severidad: ALTO, MEDIO o BAJO.

## Etapa 2: Alert Triage

El script src/alert_triage.py toma un listado de alertas tipo SIEM (por ejemplo data/sample_alerts.json), calcula un puntaje combinando severidad, criticidad del activo afectado y la presencia de un IOC conocido, y clasifica cada alerta en una prioridad de P1 (critica) a P4 (baja), sugiriendo la accion recomendada para el analista.

## Etapa 3: MITRE ATT&CK Mapping

El script src/mitre_mapper.py asocia el tipo de alerta (por ejemplo "C2 Beaconing" o "Suspicious PowerShell") con las tacticas y tecnicas correspondientes del framework MITRE ATT&CK, dando contexto sobre el comportamiento del atacante detras de cada alerta.

## Etapa 4: Generacion de Informes

El modulo src/report_generator.py genera automaticamente un informe de incidente en Markdown para cada alerta de prioridad P1 o P2, consolidando el resumen de la alerta, el resultado del triage, las tecnicas MITRE ATT&CK asociadas y el veredicto de enriquecimiento del IOC. Los informes se guardan en la carpeta reports/ (excluida del control de versiones).

## Pipeline completo (main.py)

El archivo main.py, en la raiz del proyecto, orquesta las cuatro etapas en un solo flujo: carga las alertas, las prioriza, mapea cada una a sus tecnicas MITRE ATT&CK, enriquece automaticamente el IOC de las alertas con prioridad P1 o P2 contra VirusTotal y AbuseIPDB, y genera un informe en Markdown para esas mismas alertas criticas. El resultado es un reporte consolidado por alerta, listo para que un analista lo revise.

## Instalacion

```
git clone https://github.com/nicosotomayor/mini-soar.git
cd mini-soar
pip install -r requirements.txt
```

## Configuracion

Este proyecto usa APIs gratuitas de VirusTotal y AbuseIPDB. Copia .env.example a .env y completa tus propias claves (nunca subas tus claves reales a un repositorio).

Luego exporta las variables antes de ejecutar:

```
export VT_API_KEY=tu_api_key_de_virustotal
export ABUSEIPDB_API_KEY=tu_api_key_de_abuseipdb
```

## Uso

Pipeline completo (recomendado):

```
python main.py data/sample_alerts.json
```

Enriquecimiento de IOCs por separado:

```
python src/ioc_enrichment.py 8.8.8.8 malicious-domain.com 44d88612fea8a8f36de82e1278abb02f
```

Triage de alertas por separado:

```
python src/alert_triage.py data/sample_alerts.json
```

Mapeo MITRE ATT&CK por separado:

```
python src/mitre_mapper.py "C2 Beaconing"
```

Si no se indica un archivo de alertas, los scripts usan data/sample_alerts.json por defecto.

## Ejemplo de salida

Pipeline completo (main.py):

```
ALT-1004 - C2 Beaconing
  Severidad: critical | Criticidad del activo: critical
  Prioridad de triage: P1 (score 18)
  Accion recomendada: Escalar de inmediato al equipo de respuesta a incidentes.
  Tecnicas MITRE ATT&CK:
    [T1071] Application Layer Protocol (Command and Control)
    [T1571] Non-Standard Port (Command and Control)
  Veredicto de enriquecimiento del IOC: ALTO
  Informe guardado en: reports/alt_1004.md
```

## Por que este proyecto

Este pipeline automatiza el mismo trabajo que documente manualmente en real-phishing-incident-report y trickbot-incident-analysis-ad: tomar un indicador sospechoso, consultarlo contra fuentes de inteligencia de amenazas, priorizarlo frente a otras alertas, entender que tecnica de ataque representa, y decidir que tan grave es. La idea es ir sumando etapas hasta tener un flujo completo de triage y documentacion automatizada, similar a lo que hace una herramienta SOAR en un SOC real.

## Autor

Nicolas Sotomayor - Analista SOC Jr. | Blue Team | Tecnico Superior en Ciberseguridad
LinkedIn: https://www.linkedin.com/in/nikosotomayor-cyber

## Aviso

Proyecto educativo de portfolio. Usalo de forma responsable y respetando los limites de uso de las APIs de terceros (VirusTotal, AbuseIPDB).
