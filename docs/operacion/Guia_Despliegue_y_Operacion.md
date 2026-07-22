# Guía de despliegue y operación

## Prerrequisitos

- Docker Engine o Docker Desktop con Compose v2.
- 8 GiB de RAM disponibles; 16 GiB recomendados para perfiles de recolección.
- Espacio persistente para PostgreSQL, `data/` y `reports/`.
- Archivo `.env` creado desde `.env.example`, sin publicarlo ni copiar secretos a documentación.

## Inicio reproducible

Ejecute desde la raíz del repositorio:

```bash
cp .env.example .env
docker compose --profile osint --profile surface up --build -d
docker compose ps
curl -fsS http://localhost:8000/api/health
curl -fsS -o /dev/null -w '%{http_code}\n' http://localhost:8080/
```

Interfaces locales:

- Web: `http://localhost:8080`
- API: `http://localhost:8000/docs`

## Actualización

```bash
docker compose build api web
docker compose up -d api web
docker compose ps
```

No use `docker compose down -v` durante una actualización: elimina volúmenes persistentes.

## Pruebas

```bash
.venv/bin/python -m pytest -q
.venv/bin/python -m ruff check cyberdeck cyberdeck_api tests
cd web && pnpm build
```

## Regeneración trazable de informes

En una instalación Docker con PostgreSQL, ejecute el comando dentro de la API. El proceso actualiza `run_contexts`, el resumen de la corrida, HTML, JSON, CSV y validación desde el mismo `RunContext`:

```bash
docker exec cyberdecisionengine-api python scripts/regenerate_persisted_reports.py <runId>
```

Para regenerar las corridas de aceptación registradas, omita el `runId`. Fuera de Docker, el mismo comando opera sobre contextos locales; en ese modo no existe una base PostgreSQL que sincronizar.

## Respaldo

```bash
docker exec cyberdecisionengine-postgres pg_dump -U cde cyberdecisionengine > cyberdecisionengine.sql
tar -czf cyberdecisionengine-artifacts.tgz data reports config
```

## Restauración

1. Detenga API y workers sin eliminar volúmenes.
2. Restaure PostgreSQL con `psql` usando las credenciales del entorno.
3. Restaure `data/`, `reports/` y `config/` conservando propietarios y permisos.
4. Inicie servicios y valide `/api/health`, migraciones, listado de corridas e integridad de informes.

## Operación segura

- Los sidecars de OSINT, superficie y TOR permanecen en redes internas.
- OpenCTI y OpenClaw están deshabilitados por defecto y no bloquean ninguna función principal.
- Una corrida continúa en backend aunque finalice la sesión web.
- Los informes se generan únicamente por solicitud del usuario.
- Una fuente fallida no se sustituye por datos sintéticos.

## Detención

```bash
docker compose stop
```

Para retirar contenedores conservando datos:

```bash
docker compose down
```
