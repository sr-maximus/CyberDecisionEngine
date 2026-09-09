# Runbook de conocimiento CTI

## Objetivo

Actualizar catálogos públicos de inteligencia sin detener una corrida, perder
la última copia usable ni mezclar conocimiento de referencia con evidencia.

## Fuentes administradas

| Fuente | Carácter | Formato local |
|---|---|---|
| ATT&CK Enterprise | obligatoria | STIX JSON |
| ATT&CK ICS | obligatoria | STIX JSON |
| ATT&CK Mobile | obligatoria | STIX JSON |
| D3FEND | opcional | SPARQL JSON |
| ATLAS | opcional | STIX JSON |
| Fight Fraud Framework F3 | opcional | JSON |
| Attack Flow | opcional | JSON Schema |
| Technique Inference Engine | referencia | no se descarga |

La configuración vive en `config/cti.yml`; los artefactos se guardan en
`data/frameworks/` y el manifiesto en
`data/frameworks/cti_knowledge_manifest.json`.

## Actualización manual

```bash
./.venv/bin/python scripts/sync_cti_knowledge.py
```

Para una fuente:

```bash
./.venv/bin/python scripts/sync_cti_knowledge.py --source attack-enterprise
```

Para recalcular hashes y conteos sin red:

```bash
./.venv/bin/python scripts/sync_cti_knowledge.py --manifest-only
```

## Criterios de aceptación

1. `status` global es `ready`.
2. `mandatory_usable_count` coincide con `mandatory_count`.
3. Cada fuente descargada tiene `sha256`, `updated_at` y conteo no negativo.
4. ATT&CK valida una raíz STIX con `objects`.
5. La descarga se escribe primero en un archivo temporal.
6. La versión anterior se conserva con sufijo `.lkg` antes del reemplazo.
7. Un fallo de fuente opcional no invalida las fuentes obligatorias.

## Rollback

```bash
./.venv/bin/python scripts/sync_cti_knowledge.py --rollback attack-enterprise
```

El rollback copia el archivo `.lkg` sobre la versión activa y recalcula el
manifiesto. Si no existe respaldo, la operación falla sin alterar el archivo
actual.

## API administrativa

```bash
curl -X POST http://localhost:8000/api/admin/cti/knowledge/sync \
  -H "Content-Type: application/json" \
  -H "X-Admin-Key: $CDE_ADMIN_API_KEY" \
  -d '{"source_ids":["attack-enterprise"]}'
```

El secreto se define fuera del repositorio. No debe incluirse en logs,
capturas, informes ni archivos de configuración versionados.

## Recuperación ante fallo

- `last_known_good`: continuar operando y revisar la causa del fallo.
- `missing` obligatorio: bloquear publicación CTI final y restaurar LKG.
- hash inesperado: no promover el archivo; verificar fuente y licencia.
- JSON inválido o ATT&CK sin `objects`: descartar temporal y conservar activo.
- timeout: reintentar con backoff; no reemplazar por contenido parcial.

Después de corregir una fuente, ejecutar las pruebas de conocimiento y el
validador de informes antes de regenerar reportes.
