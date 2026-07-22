# CyberDecisionEngine

CyberDecisionEngine es un motor CLI defensivo de ciberinteligencia, analitica de ciberriesgo y fraude financiero creado conceptualmente por Edwin Penuela.

El repositorio genera informes HTML ejecutivo y tecnico para direccion, CISO, SOC, riesgo, fraude, infraestructura, cloud, DevSecOps y legal. El pipeline combina OSINT permitido, inteligencia de vulnerabilidades, CTI, SOCMINT publico, Dark Web autorizada, fraude digital, ATT&CK, D3FEND, ATLAS, DISARM, NIST CSF 2.0, ISO/IEC 27001:2022, SOC 2, PESTEL, Porter, matriz 4x4 e indice no calibrado de presion de senales.

## Principios de seguridad

- Solo inteligencia defensiva, pasiva, publica o autorizada.
- No ejecuta exploits, fuerza bruta, intrusion, evasion ni scraping contra terminos de uso.
- No recolecta credenciales, tarjetas, documentos personales ni contenido ilicito.
- Dark Web queda deshabilitado por defecto y solo acepta CSV/JSON/TAXII/MISP autorizados con evidencias redactadas.
- Shodan, Censys, VirusTotal, GreyNoise y AbuseIPDB son conectores pasivos opcionales por API key.
- Todo analisis organizacional exige `authorized_scope: true` en el perfil YAML.
- Consola e informe aplican redaccion de secretos y datos sensibles.

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
cyberdeck run --org config/orgs/grupo_aval.yml --mode snapshot --lookback-days 30 --html reports/grupo_aval_executive.html --verbose
open reports/grupo_aval_executive.html
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
- Sidecars internos: `osint-tools`, `kali-surface`, `spiderfoot` y `tor-proxy`.

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
- Despliegue y operación: `docs/operacion/Guia_Despliegue_y_Operacion.md`
- Validación paso a paso de dominios: `docs/auditoria/04-validacion-paso-a-paso-dominios.md`
- Rendimiento y arquitectura: `docs/auditoria/rendimiento-y-arquitectura.md`
- Catálogo funcional final: `docs/auditoria/catalogo-funcional-final.md`

La API mantiene el guardrail de seguridad: todo analisis exige `authorized_scope=true`. Los runs generan perfiles YAML temporales y contexto atomico bajo `data/web_runs/`; el contexto completo se replica en Postgres. Los reportes HTML bajo `reports/web/` se generan solo cuando el usuario los solicita.

### Sidecars OSINT y superficie de ataque

La arquitectura local incluye sidecars para traer evidencia publica sin mezclar herramientas pesadas dentro de la API principal.

```bash
scripts/osint_tools.sh start
scripts/osint_tools.sh test
scripts/kali_surface.sh start
scripts/kali_surface.sh test
```

- `osint-tools`: instala Sherlock para presencia publica de marcas/usuarios en plataformas sociales. `socialscan` queda instalado pero la enumeracion de cuentas/email esta deshabilitada por defecto con `ALLOW_ACCOUNT_ENUMERATION=false`.
- `kali-surface`: usa una imagen Kali minima con `subfinder`, `dnsrecon`, `dig`, `httpx-toolkit`, `whatweb` y `sslscan` para superficie de ataque. `amass`, `theHarvester`, `wafw00f` y `nuclei` quedan instalados o disponibles, pero las funciones lentas, privilegiadas o policy-gated no se ejecutan por defecto.
- `spiderfoot`: queda como motor OSINT interno sin UI publicada. La API lo llama por `SPIDERFOOT_URL=http://spiderfoot:7020`, ejecuta `sf.py` en modo pasivo profundo por demanda, espera la recoleccion completa dentro del timeout configurado, serializa una ejecucion a la vez para evitar corrupcion de cache, filtra registros crudos por defecto y solo incorpora eventos observados por la herramienta.
- `urlscan.io`: consulta busquedas archivadas/publicas por marca o dominio y agrega URLs de evidencia. `URLSCAN_API_KEY` es opcional para mejorar cuota; la app no envia escaneos por defecto.
- `AlienVault OTX`: consulta pulsos CTI por dominio cuando `OTX_API_KEY` esta configurado. Si no hay key, la fuente queda marcada como opcional sin inventar eventos.

Comandos utiles:

```bash
scripts/osint_tools.sh search grupoaval
scripts/kali_surface.sh scan grupoaval.com
scripts/spiderfoot_sidecar.sh start
scripts/spiderfoot_sidecar.sh scan grupoaval.com
```

Estos contenedores no publican APIs al host; la API consume `OSINT_TOOLS_URL=http://osint-tools:7001`, `KALI_SURFACE_URL=http://kali-surface:7010` y `SPIDERFOOT_URL=http://spiderfoot:7020` por redes Docker internas. Si un sidecar no esta activo, la fuente se marca como `skipped` y el analisis continua sin inventar datos.

### TOR sidecar defensivo

La arquitectura incluye un sidecar opcional `tor-proxy` para revisiones Dark Web autorizadas. No se levanta por defecto, no publica puertos al host y solo queda accesible para la API por la red interna `tor_net` usando `socks5h://tor-proxy:9050`.

```bash
scripts/tor_window.sh start
scripts/tor_window.sh test
scripts/tor_window.sh logs
scripts/tor_window.sh stop
```

Controles aplicados:

- Sidecar interno sin puerto publicado al host; la ejecucion efectiva exige `allow_tor=true`.
- Sin puertos publicados en `localhost`.
- Contenedor read-only, `tmpfs` efimero, `cap_drop: ALL`, `no-new-privileges`, limites de memoria, CPU y procesos.
- TOR configurado como cliente SOCKS, no relay, no exit node, sin ControlPort.
- La API solo reporta el runtime TOR como disponible si `allow_tor=true` y el proxy interno responde.
- No interactua con mercados, no descarga payloads, no compra datos y no evade controles. Para produccion se recomienda allowlist de consultas, limites de tiempo y revision legal.

VPN gratuita no queda habilitada por defecto. Para cyberinteligencia empresarial es preferible SOCKS/TOR controlado o una VPN corporativa/proveedor confiable con politicas claras; una VPN gratuita agrega riesgo de privacidad, logging y manipulacion de trafico.

### Cuentas y API keys recomendadas

Las cuentas externas no se crean automaticamente desde la app porque requieren identidad, aprobacion de terminos, dominio/correo empresarial y, a veces, plan pago. Configura las keys en `.env` y reinicia Docker:

- CTI: `MISP_URL` + `MISP_API_KEY` y `TAXII_DISCOVERY_URL` + credenciales TAXII/STIX.
- Superficie/asset intelligence: `SHODAN_API_KEY`, `CENSYS_API_ID`, `CENSYS_API_SECRET`, `URLSCAN_API_KEY`, `OTX_API_KEY`, `CIRCL_PDNS_USERNAME`, `CIRCL_PDNS_PASSWORD`.
- Enriquecimiento: `VIRUSTOTAL_API_KEY`, `GREYNOISE_API_KEY`, `ABUSEIPDB_API_KEY`.
- Fraude/exposicion de identidad: `HIBP_API_KEY`, solo para dominios verificados por el propietario.

OpenCTI es un backend de conocimiento opcional, no una fuente ni un requisito. Su modo predeterminado es `OPENCTI_MODE=disabled`; consulta la decisión y los modos de integración en `docs/OPENCTI_DECISION.md`.

Fuentes oficiales de referencia: MISP API, OASIS STIX/TAXII 2.1, Shodan Developer API, Censys Search API, urlscan.io API, AlienVault OTX DirectConnect, GreyNoise API, VirusTotal API, Have I Been Pwned API y CIRCL Passive DNS.

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
entregarse al operador por un canal seguro y cargarse como variables temporales o
mediante el mecanismo de aprovisionamiento administrado.

Nota de produccion: el login local actual conserva compatibilidad de laboratorio
y no constituye una frontera de seguridad server-side. Para venta comercial se
debe conectar autenticacion de backend con sesiones revocables o SSO, hashing
Argon2/bcrypt, MFA y enforcement de licencia en la API ademas del menu.

## Comandos principales

```bash
cyberdeck doctor --verbose
cyberdeck init-org --name "Grupo Aval" --sector financial --country CO --author "Edwin Penuela" --out config/orgs/grupo_aval.yml
cyberdeck frameworks sync --all --verbose
cyberdeck run --org config/orgs/grupo_aval.yml --mode snapshot --lookback-days 30 --html reports/grupo_aval_executive.html --verbose
cyberdeck run --org config/orgs/grupo_aval.yml --mode deep --lookback-days 90 --html reports/grupo_aval_deep.html --verbose
cyberdeck monitor --org config/orgs/grupo_aval.yml --duration 24h --interval 30m --html reports/grupo_aval_24h.html --verbose
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
  orgs/grupo_aval.yml
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

Los tests cubren el modelo matematico, matriz 4x4, mappings y generacion de reporte. El demo genera un HTML valido sin servidor local.

La aceptación vigente comprende 120 pruebas Python, lint, build TypeScript/Vite,
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
- MISP Project: https://www.misp-project.org/
- OpenCTI, evaluado únicamente como backend opcional de interoperabilidad: https://filigran.io/solutions/open-cti/
- FBI IC3 annual reports: https://www.ic3.gov/annualreport/reports
- ENISA Threat Landscape Finance Sector: https://www.enisa.europa.eu/publications/enisa-threat-landscape-finance-sector
- FFIEC Cybersecurity resources: https://www.ffiec.gov/resources/cybersecurity-awareness
- ACFE Report to the Nations: https://legacy.acfe.com/report-to-the-nations/2024/
- Bolton, R. J. and Hand, D. J. (2002), Statistical Fraud Detection: A Review: https://projecteuclid.org/journals/statistical-science/volume-17/issue-3/Statistical-Fraud-Detection-A-Review/10.1214/ss/1042727940.pdf

## Alcance

CyberDecisionEngine no calcula una probabilidad calibrada de ataque. Calcula un indice de presion de senales, plausibilidad contextual, impacto, riesgo residual y postura externa con limitaciones explicitas. Su valor esta en convertir evidencia publica dispersa en decisiones defensivas trazables.
