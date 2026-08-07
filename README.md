# mini-soar

Pipeline de respuesta a incidentes (SOAR) construido por etapas, pensado para automatizar el trabajo manual de un analista SOC Nivel 1: enriquecer indicadores, priorizar alertas, mapear tecnicas de ataque y documentar el resultado.

## Roadmap del proyecto

Etapa 1: enriquecimiento automatico de IOCs (IPs, dominios, hashes) contra VirusTotal y AbuseIPDB, con veredicto de severidad y deteccion explicita de casos sin datos suficientes.

Etapa 2: triage automatico de alertas tipo SIEM, priorizando en base a severidad, criticidad del activo afectado y presencia de un IOC valido, con recalculo de prioridad segun el resultado del enriquecimiento.

Etapa 3: mapeo automatico de cada tipo de alerta a tacticas y tecnicas del framework MITRE ATT&CK, con nivel de confianza y evidencia para cada tecnica.

Etapa 4: generacion automatica de informe de incidente en Markdown para cada alerta critica, incluyendo la evidencia real del enriquecimiento.

## Etapa 1: IOC Enrichment

El script src/ioc_enrichment.py recibe una o varias IOCs (IP, dominio o hash) y devuelve tres cosas: el resultado de VirusTotal (detecciones maliciosas y sospechosas), el resultado de AbuseIPDB para IPs (score de confianza de abuso), y un veredicto final: CRITICO, ALTO, MEDIO, LIMPIO o SIN DATOS.

La deteccion de IOCs valida las IPs con el modulo ipaddress de Python (para no aceptar direcciones invalidas) y distingue explicitamente hashes MD5 (32 caracteres), SHA-1 (40) y SHA-256 (64). Ademas, si VirusTotal y AbuseIPDB no responden o no hay API keys configuradas, el veredicto es SIN DATOS en lugar de LIMPIO: la ausencia de informacion nunca se interpreta como que el indicador es benigno.

## Etapa 2: Alert Triage

El script src/alert_triage.py toma un listado de alertas tipo SIEM (por ejemplo data/sample_alerts.json), calcula un puntaje combinando severidad, criticidad del activo afectado y la presencia de un IOC que sea realmente reconocible (no cualquier valor en el campo ioc), y clasifica cada alerta en una prioridad de P1 (critica) a P4 (baja), sugiriendo la accion recomendada para el analista.

Ademas, expone escalate_priority(): una vez que se conoce el veredicto del enriquecimiento, la prioridad final puede subir (por ejemplo de P3 a P1 si el IOC resulta CRITICO), pero nunca baja por falta de datos.

## Etapa 3: MITRE ATT&CK Mapping

El script src/mitre_mapper.py asocia el tipo de alerta (por ejemplo "C2 Beaconing" o "Suspicious PowerShell") con las tacticas y tecnicas correspondientes del framework MITRE ATT&CK. Cada tecnica incluye un nivel de confianza (high/medium/low) y la evidencia que la respalda, para evitar mapeos absolutos: por ejemplo, detectar malware no prueba por si solo que hubo process injection.

## Etapa 4: Generacion de Informes

El modulo src/report_generator.py genera automaticamente un informe de incidente en Markdown para cada alerta de prioridad P1 o P2, consolidando el resumen de la alerta, el resultado del triage (score inicial y prioridad final), las tecnicas MITRE ATT&CK con su confianza/evidencia, y la evidencia real del enriquecimiento del IOC (tipo de indicador, detecciones de VirusTotal, score de AbuseIPDB y fecha de consulta), no solo el veredicto. Los informes se guardan en la carpeta reports/ (excluida del control de versiones).

## Pipeline completo (main.py)

El archivo main.py, en la raiz del proyecto, orquesta las cuatro etapas en un solo flujo: triage inicial -> enriquecimiento del IOC -> recalculo de la prioridad segun el veredicto -> generacion del informe en Markdown para las alertas mas criticas. El resultado es un reporte consolidado por alerta, listo para que un analista lo revise.

## Instalacion

Requiere Python 3.9 o superior instalado.

Linux / Kali:

```bash
git clone https://github.com/nicosotomayor/mini-soar.git
cd mini-soar
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Windows (PowerShell):

```powershell
git clone https://github.com/nicosotomayor/mini-soar.git
cd mini-soar
python -m venv venv
venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Si PowerShell bloquea la ejecucion de scripts, corre una vez: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`

## Configuracion

Este proyecto usa APIs gratuitas de VirusTotal y AbuseIPDB. Copia .env.example a .env y completa tus propias claves (nunca subas tus claves reales a un repositorio).

Linux / Kali (bash):

```bash
cp .env.example .env
export VT_API_KEY=tu_api_key_de_virustotal
export ABUSEIPDB_API_KEY=tu_api_key_de_abuseipdb
```

Windows (PowerShell):

```powershell
copy .env.example .env
$env:VT_API_KEY = "tu_api_key_de_virustotal"
$env:ABUSEIPDB_API_KEY = "tu_api_key_de_abuseipdb"
```

## Uso

Pipeline completo (recomendado):

```bash
python main.py data/sample_alerts.json
```

Enriquecimiento de IOCs por separado:

```bash
python src/ioc_enrichment.py 8.8.8.8 malicious-domain.com 44d88612fea8a8f36de82e1278abb02f
```

Triage de alertas por separado:

```bash
python src/alert_triage.py data/sample_alerts.json
```

Mapeo MITRE ATT&CK por separado:

```bash
python src/mitre_mapper.py "C2 Beaconing"
```

Si no se indica un archivo de alertas, los scripts usan data/sample_alerts.json por defecto. En Windows se usa python y en Linux/Kali generalmente python3.

## Ejemplo de salida

Pipeline completo (main.py):

```
ALT-1004 - C2 Beaconing
Severidad: critical | Criticidad del activo: critical
Score de triage inicial: 18
Prioridad final: P1
Accion recomendada: Escalar de inmediato al equipo de respuesta a incidentes.
Tecnicas MITRE ATT&CK:
    [T1071] Application Layer Protocol (Command and Control) | confianza: high | evidencia: beacon_pattern_detected
    [T1571] Non-Standard Port (Command and Control) | confianza: medium | evidencia: uncommon_port_usage
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
