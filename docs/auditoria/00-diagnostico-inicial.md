# Diagnóstico inicial de CyberDecisionEngine

**Fecha:** 2026-07-19  
**Alcance:** repositorio local, frontend, API, motor analítico, PostgreSQL y sidecars Docker.  
**Principio:** no se modificaron ni eliminaron resultados históricos durante la línea base.

## Entorno observado

| Elemento | Resultado |
|---|---|
| Sistema | macOS 26.5.2, build 25F84 |
| Arquitectura | Intel `x86_64` |
| Memoria física | 16 GiB |
| Disco del volumen | 466 GiB; 223 GiB disponibles |
| Docker | 29.6.1 |
| Docker Compose | 5.2.0 |
| Python local | 3.9.6 |
| Python requerido | >= 3.13 |
| Java | OpenJDK 21.0.10 |
| Node/npm local | no instalados; build encapsulado en Node 22 Docker |
| Go local | no instalado |
| Git | la carpeta entregada no contiene `.git` |
| Tamaño del proyecto | 640 MiB; 426 archivos inventariados por `rg --files` |

## Componentes y límites

| Componente | Responsabilidad | Persistencia/red |
|---|---|---|
| `web` | React, navegación, dashboards, evidencia y administración | Nginx, puerto 8080 |
| `api` | FastAPI, ejecución, contexto, informes, licencias, monitoreo e IA | puerto 8000 |
| `postgres` | corridas, contextos, licencias y auditoría | volumen Docker, host 15432 |
| `cyberdeck` | recolección, normalización, análisis, semántica y reportes | biblioteca Python |
| `osint-tools` | utilidades públicas acotadas | red interna `osint_net` |
| `kali-surface` | superficie externa defensiva y autorizada | red interna `surface_net` |
| `spiderfoot` | recolección pasiva en segundo plano | red interna `osint_net` |
| `tor-proxy` | SOCKS Tor opcional y aislado | red interna `tor_net`; sin puerto host |
| `reports/web` | HTML ejecutivo/técnico, JSON y CSV | volumen local montado |
| `data/web_runs` | contexto atómico de cada `runId` | volumen local y réplica PostgreSQL |

## Estado inicial de contenedores

Los siete servicios de CyberDecisionEngine estaban activos. API, PostgreSQL, OSINT, SpiderFoot, superficie y Tor reportaron estado saludable. La aplicación ajena `astroflornative` fue observada pero no modificada.

Consumo aproximado en reposo:

| Servicio | CPU | Memoria |
|---|---:|---:|
| API | 3.35 % | 120 MiB |
| Web | 0.36 % | 11 MiB |
| PostgreSQL | 0.02 % | 58 MiB |
| Tor | 0.04 % | 107 MiB |
| SpiderFoot | 0.38 % | 39 MiB |
| Superficie | 0.21 % | 39 MiB |
| OSINT tools | 0.45 % | 36 MiB |

## Línea base de calidad

| Control | Resultado inicial | Estado |
|---|---|---|
| Pytest | 103 pruebas aprobadas en 13.49 s | aprobado |
| Build React/TypeScript | completó | aprobado con advertencia |
| Ruff | 31 incidencias: imports/variables sin uso, nombres ambiguos y f-strings | pendiente |
| API health | HTTP 200 | aprobado |
| Web | HTTP 200 | aprobado |
| Persistencia | PostgreSQL saludable; fallback JSON disponible | aprobado |

## Hallazgos

| Severidad | Hallazgo | Evidencia técnica | Impacto | Estado |
|---|---|---|---|---|
| Alta | El runtime local no cumple Python >=3.13 | `python3 --version` = 3.9.6; `pyproject.toml` exige 3.13 | ejecución local no reproducible; Docker continúa operativo | documentado; usar Docker o instalar 3.13 |
| Alta | No existía validador final de bundle HTML/JSON/CSV | `render_report` escribía artefactos sin resultado de aprobación | un informe incoherente podía aparecer como listo | corregido con `reporting/validator.py` |
| Alta | Una afirmación podía quedar `supported` sin `evidence_ids` | contexto histórico `a9dad6033577`, `claim-0001` | rompe trazabilidad afirmación → evidencia | corregido: pasa a `candidate` |
| Media | `/api/runs` entrega respuestas cercanas a 3 MB y el frontend repite consultas | logs Nginx/API durante reposo | ancho de banda y renderizado innecesarios | pendiente de paginación/resumen |
| Media | Chunk geográfico diferido de 8.1 MB | build Vite; ver auditoría 01 | latencia solo al abrir selector de ciudades | aceptado temporalmente con lazy loading |
| Media | Ruff detecta 31 incidencias | `python -m ruff check .` | ruido de mantenimiento; no implica 31 fallos funcionales | pendiente de limpieza controlada |
| Baja | Healthcheck de Tor genera avisos SOCKS | `Denying socks connection from untrusted address 127.0.0.1` | ruido operacional | pendiente de ajustar healthcheck |
| Informativa | No existe `.env` local | comparación de claves | Compose usa defaults y secretos opcionales vacíos | crear solo para despliegue administrado |
| Informativa | La copia no contiene Git | `git status` falla | no es posible crear la rama solicitada ni producir diff Git | limitación del workspace |

## Variables y secretos

`.env.example` declara 30 claves. No existe `.env`; los servicios funcionan con defaults y conectores opcionales deshabilitados. Ningún secreto fue impreso durante la auditoría. Antes de producción se deben sustituir las credenciales predeterminadas de PostgreSQL y cargar secretos mediante el mecanismo del entorno de despliegue.

## Estado al cierre de esta fase

- Línea base funcional reproducida.
- Validador de informes añadido y probado.
- Regla semántica corregida para no respaldar afirmaciones sin evidencia resoluble.
- Pruebas nuevas ejecutadas: 22 aprobadas en el subconjunto de semántica/reporte.
- Los cambios de arquitectura, UX y las corridas independientes se registran en documentos posteriores.

