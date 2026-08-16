# Employee Virtual Risk OSINT / Ciberinteligencia

Aplicación CLI en Python para análisis **autorizado** de exposición pública, riesgo digital y señales OSINT/ciberinteligencia asociadas a personal de una organización.

El sistema genera un **informe HTML** con:

- Resumen ejecutivo por empleado.
- Riesgo total y clasificación.
- Riesgo por dimensión.
- Evidencias con URL, título, snippet, keyword, dimensión y score.
- Detección de posibles perfiles sociales o superficies públicas.
- Gráficas de riesgo, matriz probabilidad x impacto, radar de exposición y top keywords.
- Matriz de toma de decisiones por áreas: RR. HH., Legal, Seguridad Física, Ciberseguridad, Seguridad de la Información, Riesgos, Compliance y Gerencia.
- Control de consentimiento y revisión humana obligatoria.

## Uso permitido

Esta herramienta está diseñada para programas de seguridad corporativa, ciberinteligencia, gestión de exposición pública y prevención de riesgos, siempre que exista:

1. Autorización y finalidad documentada.
2. Tratamiento mínimo de datos personales.
3. Fuentes públicas o APIs oficiales.
4. Revisión humana antes de cualquier acción.
5. Proceso de rectificación, exclusión y eliminación de datos.

No se debe usar para vigilancia no autorizada, acoso, doxxing, discriminación, scraping agresivo, evasión de autenticación ni decisiones laborales automáticas.

## Instalación

```bash
cd employee_virtual_risk_osint
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Configuración

Copia el archivo de ejemplo:

```bash
cp .env.example .env
```

Variables principales:

```env
SEARCH_CLIENT=mock
BING_SEARCH_API_KEY=
BING_SEARCH_ENDPOINT=https://api.bing.microsoft.com/v7.0/search
GOOGLE_CSE_API_KEY=
GOOGLE_CSE_ID=
REPORT_PASSWORD=
HASH_SALT=
MIN_CONFIDENCE=0.35
```

Para pruebas usa `SEARCH_CLIENT=mock`. Para producción usa `bing` o `google_cse`, con la API correspondiente.

## Crear plantilla de empleados

```bash
python -m app.main generate-template --output data/input/template.xlsx
```

También puedes usar CSV. Ejemplo mínimo:

```csv
employee_id,full_name,personal_email,corporate_email,identification_document,role,department,organization,country,city,access_level,access_category,consent_status,consent_date,authorized_personal_email
SYN-001,Synthetic Employee 001,employee-001@example.invalid,employee-001@organization.example.invalid,,Security Analyst,Security,Authorized Organization,,,4,confidential,approved,2026-01-01,true
```

## Validar consentimiento

```bash
python -m app.main validate-consent --input data/input/sample_employees.csv
```

## Ejecutar análisis y generar informe HTML

```bash
python -m app.main analyze \
  --input data/input/sample_employees.csv \
  --output data/output \
  --search-client mock \
  --formats html,json,csv \
  --results-per-query 3 \
  --max-keywords-per-dimension 20
```

El informe principal queda en:

```text
data/output/cyberintelligence_report.html
```

## Cliente de búsqueda

### Mock

No consulta internet. Sirve para probar estructura, scoring, gráficos y reporte.

```bash
--search-client mock
```

### Bing Web Search API

```bash
export BING_SEARCH_API_KEY="..."
python -m app.main analyze --input empleados.xlsx --output data/output --search-client bing
```

### Google Custom Search JSON API

```bash
export GOOGLE_CSE_API_KEY="..."
export GOOGLE_CSE_ID="..."
python -m app.main analyze --input empleados.xlsx --output data/output --search-client google_cse
```

## Modelo matemático

Cada evidencia se puntúa con:

```text
confidence_score(e) =
0.35 * identity_match +
0.20 * source_reliability +
0.15 * keyword_relevance +
0.15 * context_relevance +
0.10 * recency_score +
0.05 * evidence_quality
```

Riesgo por dimensión:

```text
dimension_risk = min(100, sum(confidence_score * severity_score * 10) * access_multiplier)
```

Riesgo total:

```text
total_risk = min(100, weighted_average(dimension_risk) - mitigation_score)
```

Clasificación:

| Rango | Nivel |
|---:|---|
| 0-20 | Bajo |
| 21-40 | Moderado |
| 41-60 | Alto |
| 61-80 | Crítico |
| 81-100 | Extremo |

## Estructura

```text
employee_virtual_risk_osint/
  app/
    main.py
    config.py
    models.py
    ingestion.py
    query_builder.py
    scoring.py
    false_positive.py
    privacy.py
    audit.py
    search_clients/
      base.py
      mock_client.py
      bing_client.py
      google_cse_client.py
    reporting/
      charts.py
      html_report.py
      templates/
        cyberintelligence_report.html.j2
  catalogs/
    keywords.yaml
    risk_weights.yaml
    decision_matrix.yaml
  data/
    input/sample_employees.csv
    output/.gitkeep
  tests/
  requirements.txt
  .env.example
```

## Notas operativas

- La columna `consent_status` debe estar en estado positivo: `approved`, `autorizado`, `si`, `yes`, `true`, `consentido`.
- El documento de identificación se transforma a hash SHA-256 con salt; no se usa para búsquedas.
- El correo personal solo se usa si pasas `--allow-personal-email` y la fila tiene `authorized_personal_email=true`.
- El reporte marca hallazgos de baja confianza como posible falso positivo.
- Las acciones recomendadas son preventivas/investigativas y requieren revisión humana.


## Mejoras de reporting enterprise
- Genera un índice maestro `cyberintelligence_report.html` y un informe individual por empleado en `output/employees/`.
- Gráficas optimizadas para evitar traslape de etiquetas: barras horizontales, radar, matriz probabilidad-impacto, heatmap por dimensión/dato de búsqueda y gráfico de hallazgos por vector de búsqueda.
- Muestra trazabilidad de qué dato originó el hallazgo (nombre, nombre+organización, correo corporativo, nombre+dominio, correo personal autorizado).
- Incluye branding: `Proceso de análisis diseñado por Edwin Peñuela`.
- Incluye `sample_employees.csv` únicamente con identificadores sintéticos y
  dominios reservados `.invalid`; sustituye esos campos localmente solo con
  autorización y nunca publiques el archivo resultante.


## Ejecución en macOS

Desde Terminal:

```bash
# 1. Ir a la carpeta donde descomprimiste el proyecto
cd ~/Downloads/employee_virtual_risk_osint

# 2. Crear entorno virtual
python3 -m venv .venv

# 3. Activarlo
source .venv/bin/activate

# 4. Actualizar pip e instalar dependencias
python -m pip install --upgrade pip
pip install -r requirements.txt

# 5. Ejecutar demo local sin internet real
python -m app.main analyze \
  --input data/input/sample_employees.csv \
  --output data/output_demo \
  --search-client mock \
  --formats html,json,csv \
  --results-per-query 3 \
  --max-keywords-per-dimension 5

# 6. Abrir el índice maestro
open data/output_demo/cyberintelligence_report.html
```

## Búsqueda normal sin APIs

Para una demostración sin Bing API ni Google Custom Search API, usa el cliente HTML:

```bash
python -m app.main analyze \
  --input data/input/empleados_autorizados.csv \
  --output data/output_osint \
  --search-client duckduckgo_lite \
  --formats html,json,csv \
  --results-per-query 5 \
  --max-keywords-per-dimension 5 \
  --max-queries-per-employee 120
```

También puedes usar el alias:

```bash
--search-client ddg
```

Notas:
- Este modo no requiere API keys.
- Consulta páginas HTML públicas del buscador.
- No evade bloqueos, captcha, autenticación, paywalls ni controles de acceso.
- Puede ser más lento y menos estable que una API oficial.
- Para producción regulada se recomienda mantener logs, revisión humana y autorización documentada.
- Para demos, limita `--max-keywords-per-dimension` y `--max-queries-per-employee` para no generar búsquedas excesivas.

## Mejoras visuales v3

La versión v3 incorpora:
- Velocímetro ejecutivo de riesgo.
- Donut de contribución relativa.
- Lollipop chart por dimensión.
- Heatmap de trazabilidad dato usado vs dimensión.
- Matriz CTI probabilidad x impacto con cuadrantes.
- Radar de superficie de exposición.
- Distribución de confianza de evidencias.
- Calidad operativa de evidencias.
- Ranking de dominios con señales.

## V4: Corrección de búsqueda normal sin API

### Qué se corrigió
La versión anterior podía devolver cero resultados por dos razones:

1. **Problema de conectividad o bloqueo**: si el entorno no podía resolver `html.duckduckgo.com` o `www.bing.com`, el reporte quedaba con cero evidencias. En V4, si todas las búsquedas fallan, el informe marca el empleado como **búsqueda no completada**, no como “sin hallazgos”.
2. **Problema lógico de consulta**: antes se buscaba principalmente `"nombre" + keyword`, por ejemplo `"<nombre-autorizado>" "password"`. Si en Google hay resultados con solo `"<nombre-autorizado>"`, esos resultados podían no aparecer. En V4 se agregó una etapa inicial de **descubrimiento de identidad digital**:
   - `"Nombre completo"`
   - `"Nombre completo" site:linkedin.com`
   - `"Nombre completo" site:github.com`
   - `"Nombre completo" site:facebook.com`
   - `"Nombre completo" site:instagram.com`
   - `"Nombre completo" site:x.com`
   - `"Nombre completo" site:twitter.com`
   - correo exacto si existe y está autorizado

Esta etapa es informativa y no suma riesgo automáticamente.

### Cliente recomendado sin API

```bash
python -m app.main analyze \
  --input data/input/nombres_autorizados.csv \
  --output data/output_nombres_noapi \
  --search-client multi_noapi \
  --formats html,json,csv \
  --results-per-query 5 \
  --max-keywords-per-dimension 3 \
  --max-queries-per-employee 80
```

`multi_noapi` intenta DuckDuckGo HTML/Lite y Bing HTML. No usa llaves, no usa APIs y no evade captchas ni bloqueos.

### Modo 100% controlado con resultados manuales de Google
Si Google muestra resultados en el navegador, pero el scraping automático se bloquea, exporta o copia las URLs relevantes a un CSV y ejecútalo así:

```bash
python -m app.main analyze \
  --input data/input/nombres_autorizados.csv \
  --manual-results data/input/manual_results_google.csv \
  --skip-web-search \
  --output data/output_manual_google \
  --formats html,json,csv
```

Formato mínimo de `manual_results_google.csv`:

```csv
employee_id,url,title,snippet,query,source
SYN-003,https://profile.example.invalid/person,Perfil público,Texto visible en el buscador,"<nombre-autorizado>",manual_import
```

Este modo evita bloqueos porque no automatiza Google: usa resultados recolectados manualmente por un analista autorizado.
