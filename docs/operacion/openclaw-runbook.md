# Runbook de OpenClaw

## Estado local soportado

```dotenv
OPENCLAW_ENABLED=true
OPENCLAW_GATEWAY_URL=http://openclaw-gateway:18789
OPENCLAW_GATEWAY_TOKEN_FILE=/run/openclaw/gateway-token
OPENCLAW_AUTOMATION_MODE=analysis_only
```

Docker Compose inicia el gateway fijado a la versión definida en `infra/openclaw/Dockerfile`. El entrypoint genera un token aleatorio cuando no existe y lo comparte con la API mediante un volumen de runtime; el token no se guarda en el repositorio. La capacidad de modelo permanece separada: sin credencial válida, `/api/ai/config` debe informar `configured_unverified`.

## Criterios antes de habilitar

1. Gateway aislado en red Docker sin acceso directo a PostgreSQL.
2. Usuario no privilegiado, filesystem de solo lectura y `no-new-privileges`.
3. Token dedicado fuera del repositorio y política de rotación.
4. Allowlist de operaciones analíticas; shell y acciones destructivas denegadas.
5. Límites de tiempo, tokens, tamaño, concurrencia y reintentos.
6. Auditoría por organización, usuario, runId, prompt, modelo, herramientas y respuesta.
7. Pruebas de prompt injection, tool injection y fuga entre organizaciones aprobadas.
8. Mecanismo administrativo de detención y revocación.

## Activación de un proveedor de modelo

1. Configure únicamente la credencial del proveedor aprobado fuera del repositorio.
2. Mantenga `OPENCLAW_AUTOMATION_MODE=analysis_only`.
3. Compruebe `/readyz`, `/v1/models` y el estado de `/api/ai/config`.
4. Ejecute pruebas negativas y modo sin IA.
5. Habilite primero en una organización de prueba sin datos sensibles.
6. Verifique que las respuestas sean propuestas con `evidenceIds` existentes.
7. Active por licencia y rol solo después de revisión de seguridad.

## Incidentes

Deshabilite inmediatamente si existe fuga de datos, herramientas fuera de allowlist, respuesta sin trazabilidad, acceso cruzado, consumo anómalo o intento de convertir contenido externo en instrucción. Rote el token, preserve auditoría, revise solicitudes correlacionadas y mantenga el motor determinista operativo.

## Verificación de degradación

Con `OPENCLAW_ENABLED=false` o sin modelo disponible, deben seguir funcionando recolección, validación, riesgo, escenarios, dashboard, exportes e informes. Esta prueba es obligatoria en cada release.
