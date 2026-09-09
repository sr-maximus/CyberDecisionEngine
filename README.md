# CyberDecisionEngine

CyberDecisionEngine es el motor defensivo de ciberinteligencia, evidencia,
decisión y riesgo creado por **Edwin Peñuela**. Es la
implementación de referencia viva de **P-CIDER v1.0** (Peñuela Cyber
Intelligence Decision, Evidence & Risk Model), construido a partir de su
investigación, arquitectura, metodología y modelos propios.

El repositorio genera dashboards, JSON/CSV e informes HTML ejecutivo y técnico
para dirección, CISO, SOC, riesgo, fraude, infraestructura, cloud, DevSecOps y
legal. El pipeline combina OSINT permitido, inteligencia de vulnerabilidades,
CTI, SOCMINT público, Dark Web autorizada, fraude digital, ATT&CK, D3FEND,
ATLAS, DISARM, MITRE F3, NIST CSF 2.0, ISO/IEC 27001:2022, SOC 2, PESTEL,
Porter, matriz 4x4 e índice no calibrado de presión de señales.

## Alineación P-CIDER

CyberDecisionEngine operacionaliza el ciclo P-CIDER:

```text
Prepare -> Collect -> Integrate -> Determine -> Estimate -> Respond & Review
```

Y conserva la cadena analítica:

```text
Claim -> Evidence -> Interpretation -> Limitation -> Decision -> Closure
```

La razón teórica es separar conceptos que suelen mezclarse: severidad técnica
(`CVSS`), prior de explotación (`EPSS`), explotación conocida (`KEV`),
plausibilidad contextual, impacto, confianza, controles y riesgo. La razón
práctica es evitar decisiones infladas por duplicados, fuentes incompletas,
controles no evidenciados o escenarios que no pertenecen al alcance.

Invariantes aplicados:

- La probabilidad/plausibilidad contextual excluye controles.
- El riesgo inherente se calcula antes de controles.
- La efectividad de controles se aplica una sola vez al riesgo residual.
- `sin datos`, `cero observado`, `evidencia potencial`, `hallazgo validado` e
  `incidente confirmado` son estados distintos.
- Todos los dashboards, reportes y exportes salen del mismo snapshot persistido
  por `runId`.
- MITRE ATT&CK, D3FEND, ATLAS, F3, DISARM, NIST, ISO y otros marcos se usan
  como referencias interoperables; no transfieren autoría ni propiedad del
  modelo.

## Principios de seguridad

- Solo inteligencia defensiva, pasiva, publica o autorizada.
- No ejecuta exploits, fuerza bruta, intrusion, evasion ni scraping contra terminos de uso.
- No recolecta credenciales, tarjetas, documentos personales ni contenido ilicito.
- El canal profundo queda deshabilitado por defecto y solo procesa fuentes autorizadas con evidencias redactadas.
- Las capacidades externas opcionales se desacoplan del motor y su ausencia nunca bloquea el análisis determinista.
- Todo analisis organizacional exige `authorized_scope: true` en el perfil YAML.
- Consola e informe aplican redaccion de secretos y datos sensibles.

## Licencia y derechos

CyberDecisionEngine no usa licencia MIT. Se publica bajo **SDMC
SOURCE-AVAILABLE NON-COMMERCIAL LICENSE**. Edwin Javier Peñuela Camacho reserva
los derechos económicos, patrimoniales, de explotación comercial, reproducción,
distribución, transformación y licenciamiento.

Todo uso comercial, consultoría, SaaS, reportes para clientes, capacitación
pagada, APIs, dashboards, productos, datasets, modelos o cualquier beneficio
económico directo o indirecto requiere autorización escrita y pagada de Edwin
Javier Peñuela Camacho.

## Instalacion en Mac Intel

```bash
bash scripts/install_mac_intel.sh
source .venv/bin/activate
cyberdeck doctor --verbose
```

El instalador verifica arquitectura `x86_64`, Xcode Command Line Tools, Homebrew y Python 3.13+. No instala herramientas sensibles ni dependencias de sistema sin confirmacion.

## Demo rapida

```bash
source .venv/bin/activate
cyberdeck frameworks sync --all --verbose
cyberdeck run --org config/orgs/example_organization.yml --mode snapshot --lookback-days 30 --html reports/example_organization_executive.html --verbose
open reports/example_organization_executive.html
```

Tambien puedes usar:

```bash
scripts/run_demo.sh
```

El demo solo se usa cuando se solicita explicitamente. En una corrida real, una API key ausente, un timeout o una fuente sin resultados conserva su estado y no genera evidencia simulada.

## App web local

La consola web agrega una capa FastAPI + React sobre el motor existente. Permite ingresar uno o muchos dominios, confirmar alcance autorizado, lanzar analisis defensivo pasivo, ver estado del run, fuentes, hallazgos priorizados y abrir el reporte HTML generado.

La arquitectura recomendada para Mac local y posterior despliegue en servidor dedicado es Docker Compose con servicios aislados:

- `cyberdecisionengine-web`: React/Nginx.
- `cyberdecisionengine-api`: FastAPI + motor de analisis.
- `cyberdecisionengine-postgres`: Postgres para historial de corridas y cache de eventos.
- Servicios internos aislados: recolección pública, superficie externa y canal profundo autorizado.

```bash
cp .env.example .env
make web-up
```

- Web: http://localhost:8080
- API: http://localhost:8000/api/health
- Docs API: http://localhost:8000/docs
- Postgres local: localhost:15432
- Reportes: `reports/web/`
- Estado de runs en Docker: Postgres (`web_runs` y `run_contexts`)
- Fallback sin Docker: `data/web_runs.json`

Documentación operativa y de auditoría:

- Manual navegable: http://localhost:8080/docs/Manual_Plataforma_Ciberinteligencia.html
- Manual fuente: `docs/manual/Manual_Plataforma_Ciberinteligencia.md`
- Proceso, evidencia y cálculos: `docs/cyberdecisionengine_proceso_modelo_calculos.md`
- Despliegue y operación: `docs/operacion/Guia_Despliegue_y_Operacion.md`
- Validación paso a paso de dominios: `docs/auditoria/04-validacion-paso-a-paso-dominios.md`
- Rendimiento y arquitectura: `docs/auditoria/rendimiento-y-arquitectura.md`
- Catálogo funcional final: `docs/auditoria/catalogo-funcional-final.md`

La API mantiene el guardrail de seguridad: todo analisis exige `authorized_scope=true`. Los runs generan perfiles YAML temporales y contexto atomico bajo `data/web_runs/`; el contexto completo se replica en Postgres. Los reportes HTML bajo `reports/web/` se generan solo cuando el usuario los solicita.

### Capacidades de recolección

La experiencia pública presenta capacidades, no nombres de herramientas:

- inteligencia de vulnerabilidades;
- búsqueda pública;
- índice público;
- índice de canal profundo autorizado;
- correlación OSINT;
- superficie externa;
- SOCMINT público;
- inteligencia de amenazas;
- evidencia web validada;
- caché local de evidencias.

Cada capacidad registra si estaba disponible, si fue consultada, si produjo
registros y qué limitaciones tuvo. Los servicios viven en redes internas sin
puertos públicos, aplican límites de recursos y degradan de forma explícita si
una integración opcional no está configurada.

### Inteligencia multidominio

La misma corrida clasifica evidencia en `IT`, `IoT`, `IIoT`, `OT` o
`Sin clasificar`, y en los ámbitos `Cyber`, `Fraude`, `Marca`,
`Desinformación` e `IA`. Los filtros son proyecciones reproducibles del snapshot:
no recollectan, no alteran la corrida fuente y se propagan a dashboard,
grafos, informes y exportaciones.

La **Huella Tecnológica Pública** muestra únicamente lo observado externamente.
No constituye inventario interno ni confirma firmware, CVE aplicable o
compromiso. El catálogo incorpora 1.138 plantillas preventivas, incluidas 22
plantillas multidominio; ninguna se presenta como escenario activo sin evidencia
de la corrida que satisfaga sus puertas de atribución y corroboración.

Si necesitas evitar conflictos de puertos con otras apps, ajusta `.env`:

```bash
CDE_WEB_PORT=18100
CDE_API_PORT=18101
CDE_DB_PORT=15432
```

Si Docker no esta instalado, puedes levantar la app en modo local:

```bash
make web-local
```

- Web local: http://127.0.0.1:8080
- API local: http://127.0.0.1:8000/docs
- Apagar modo local: `make web-local-stop`

## Licenciamiento y multiempresa

La app incluye una capa de gobierno preparada para evolucionar a SaaS/licenciamiento comercial. En Docker se persiste en Postgres y expone `GET/POST/PATCH /api/licensing/*`.

- `superadmin`: puede crear empresas, asignar licencias, activar/suspender licencias, crear admins de empresa, ver modulos efectivos y consultar bitacora.
- `admin`: administra usuarios operativos de su empresa, sin crear empresas ni licencias.
- Planes base: `starter`, `professional`, `enterprise`, `sovereign`.
- Acceso efectivo: rol + plan asignado al usuario o licencia empresarial + overrides modulares autorizados.
- Tablas: `license_companies`, `license_plans`, `license_assignments`, `license_control_users`, `license_audit_log`.
- Bitacora: registra arranque del control plane y cambios de empresa, licencia, usuario, estado y acceso.

Las credenciales locales de laboratorio no se publican en el repositorio. Deben
solicitarse al propietario y entregarse por un
canal seguro. El repositorio y la interfaz no incluyen usuarios, contraseñas ni
hashes predeterminados.

Nota de produccion: el login local actual conserva compatibilidad de laboratorio
y no constituye una frontera de seguridad server-side. Para venta comercial se
debe conectar autenticacion de backend con sesiones revocables o SSO, hashing
Argon2/bcrypt, MFA y enforcement de licencia en la API ademas del menu.

## Comandos principales

```bash
cyberdeck doctor --verbose
cyberdeck init-org --name "Organization Under Assessment" --sector authorized_test_sector --country ZZ --author "authorized_operator" --out config/orgs/example_organization.yml
cyberdeck frameworks sync --all --verbose
cyberdeck run --org config/orgs/example_organization.yml --mode snapshot --lookback-days 30 --html reports/example_organization_executive.html --verbose
cyberdeck run --org config/orgs/example_organization.yml --mode deep --lookback-days 90 --html reports/example_organization_deep.html --verbose
cyberdeck monitor --org config/orgs/example_organization.yml --duration 24h --interval 30m --html reports/example_organization_24h.html --verbose
cyberdeck report open --latest
```

## Fraude financiero incorporado

El motor incluye un dominio explicito de fraude que no se limita a "amenazas cyber" genericas:

- Phishing, smishing, vishing, BEC y suplantacion de marca.
- Account takeover, credential stuffing, session hijacking y MFA fatigue.
- Mule accounts, fraude transaccional, pagos no autorizados y abuso de canales digitales.
- Fraude de identidad, onboarding sintetico, SIM swap y deepfake-enabled social engineering.
- Senales SOCMINT publicas y agregadas de campanas de suplantacion.
- Controles de fraude vinculados con identidad digital, monitoreo transaccional, velocity rules, device intelligence, deteccion de anomalias, graph risk, case management y respuesta.

## Estructura

```text
cyberdeck/
  cli.py                    # Typer CLI
  collectors/               # fuentes reales, autorizadas u opcionales
  analysis/                 # riesgo, fraude, PESTEL, Porter, forecast
  frameworks/               # sync y mappings ATT&CK, D3FEND, ATLAS, NIST, ISO, SOC2
  reporting/                # informe HTML autocontenido
  storage/                  # SQLite cache
  utils/                    # HTTP, scoring, fechas, texto
config/
  app.yml
  sources.yml
  frameworks.yml
  orgs/example_organization.yml
tests/
scripts/
reports/
data/
```

## Calidad

```bash
make test
scripts/healthcheck.sh
```

Los tests cubren el modelo matematico P-CIDER, matriz 4x4, mappings y generacion de reporte. El demo genera un HTML valido sin servidor local.

La aceptación vigente comprende 225 pruebas Python, lint, build TypeScript/Vite,
validación de informes y paridad entre API, snapshot de decisión, HTML, JSON y CSV.

## Fuentes metodologicas

El README, el motor y el informe se basan en fuentes oficiales y literatura reconocida:

- NIST CSF 2.0, CSWP 29: https://csrc.nist.gov/pubs/cswp/29/the-nist-cybersecurity-framework-csf-20/final
- NIST SP 800-30 Rev. 1: https://csrc.nist.gov/pubs/sp/800/30/r1/final
- NIST SP 800-53 Rev. 5: https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
- NIST SP 800-63-4 Digital Identity Guidelines: https://csrc.nist.gov/pubs/sp/800/63/4/final
- CISA KEV Catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- FIRST EPSS: https://www.first.org/epss/
- MITRE ATT&CK Data and Tools: https://attack.mitre.org/resources/attack-data-and-tools/
- MITRE D3FEND: https://d3fend.mitre.org/
- MITRE ATLAS: https://atlas.mitre.org/
- OASIS STIX/TAXII: https://oasis-open.github.io/cti-documentation/
- MITRE ATT&CK for ICS: https://attack.mitre.org/matrices/ics/
- MITRE EMB3D: https://emb3d.mitre.org/
- FBI IC3 annual reports: https://www.ic3.gov/annualreport/reports
- ENISA Threat Landscape Finance Sector: https://www.enisa.europa.eu/publications/enisa-threat-landscape-finance-sector
- FFIEC Cybersecurity resources: https://www.ffiec.gov/resources/cybersecurity-awareness
- ACFE Report to the Nations: https://legacy.acfe.com/report-to-the-nations/2024/
- Bolton, R. J. and Hand, D. J. (2002), Statistical Fraud Detection: A Review: https://projecteuclid.org/journals/statistical-science/volume-17/issue-3/Statistical-Fraud-Detection-A-Review/10.1214/ss/1042727940.pdf

## Alcance

CyberDecisionEngine no calcula una probabilidad calibrada de ataque. Calcula un indice de presion de senales, plausibilidad contextual, impacto, riesgo residual y postura externa con limitaciones explicitas. Su valor esta en convertir evidencia publica dispersa en decisiones defensivas trazables.

## VPS privado

El perfil [deploy/vps](deploy/vps/README.md) prepara una instalación vacía sobre
Debian 13 y Docker Compose, con acceso por túnel SSH, API y PostgreSQL sin puertos
públicos, secretos externos al repositorio y volúmenes independientes. No incorpora
informes, recolecciones ni cuentas del operador. No sustituye autenticación y
autorización de backend para una futura oferta pública multiusuario.
