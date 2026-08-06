# mini-soar

Pipeline de respuesta a incidentes (SOAR) construido por etapas, pensado para automatizar el trabajo manual de un analista SOC Nivel 1: enriquecer indicadores, priorizar alertas y documentar el resultado.

## Roadmap del proyecto

Etapa 1 (completada): enriquecimiento automatico de IOCs (IPs, dominios, hashes) contra VirusTotal y AbuseIPDB, con veredicto de severidad.

Etapa 2 (pendiente): triage de alertas, priorizacion automatica combinando enriquecimiento y reglas de severidad.

Etapa 3 (pendiente): mapeo automatico a tecnicas MITRE ATT&CK segun el comportamiento observado.

Etapa 4 (pendiente): generacion automatica de informe de incidente en Markdown o PDF.

## Etapa 1: IOC Enrichment

El script src/ioc_enrichment.py recibe una o varias IOCs (IP, dominio o hash) y devuelve tres cosas: el resultado de VirusTotal (detecciones maliciosas, sospechosas e inofensivas), el resultado de AbuseIPDB para IPs (score de abuso, cantidad de reportes, pais), y un veredicto final de severidad: ALTO, MEDIO o BAJO.

### Instalacion

git clone https://github.com/nicosotomayor/mini-soar.git
cd mini-soar
pip install -r requirements.txt

### Configuracion

Este proyecto usa APIs gratuitas de VirusTotal y AbuseIPDB. Copia .env.example a .env y completa tus propias claves (nunca subas tus claves reales a un repositorio).

Luego exporta las variables antes de ejecutar:

export VT_API_KEY=tu_api_key_de_virustotal
export ABUSEIPDB_API_KEY=tu_api_key_de_abuseipdb

### Uso

python src/ioc_enrichment.py 8.8.8.8 malicious-domain.com 44d88612fea8a8f36de82e1278abb02f

O de forma interactiva:

python src/ioc_enrichment.py

### Ejemplo de salida

IOC: 8.8.8.8 (tipo: ip)
VirusTotal -> malicious: 0 | suspicious: 0 | harmless: 68
AbuseIPDB -> abuse score: 0% | reports: 0 | pais: US
Veredicto: BAJO

## Por que este proyecto

Este pipeline automatiza el mismo trabajo que documente manualmente en real-phishing-incident-report y trickbot-incident-analysis-ad: tomar un indicador sospechoso, consultarlo contra fuentes de inteligencia de amenazas, y decidir que tan grave es. La idea es ir sumando etapas hasta tener un flujo completo de triage y documentacion automatizada, similar a lo que hace una herramienta SOAR en un SOC real.

## Autor

Nicolas Sotomayor - Analista SOC Jr. | Blue Team | Tecnico Superior en Ciberseguridad
LinkedIn: https://www.linkedin.com/in/nikosotomayor-cyber

## Aviso

Proyecto educativo de portfolio. Usalo de forma responsable y respetando los limites de uso de las APIs de terceros (VirusTotal, AbuseIPDB).
