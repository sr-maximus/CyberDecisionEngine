# Modelo de amenazas de OpenClaw

## Activos

- evidencias originales y normalizadas;
- contexto de organizaciones y ejecuciones;
- credenciales de proveedores;
- prompts, respuestas y auditoría;
- decisiones e informes.

## Fronteras de confianza

1. Navegador a API.
2. API a almacenamiento interno.
3. API a gateway OpenClaw.
4. Gateway a proveedor IA.
5. Contenido externo no confiable a contexto del modelo.

## Amenazas y controles

| Amenaza | Impacto | Control requerido |
|---|---|---|
| prompt injection en web o documento | ejecución o conclusión indebida | separar instrucciones de evidencia, delimitar contenido y salida estructurada |
| tool injection | acción no autorizada | allowlist y modo propuesta; sin ejecución directa |
| fuga entre organizaciones | exposición de datos | memoria y contexto por `organization_id` y `run_id` |
| fuga de secretos | compromiso de conectores | secretos fuera del prompt, redacción y token dedicado |
| alucinación | decisión sin sustento | referencias de evidencia obligatorias y revisión humana |
| agotamiento de recursos | indisponibilidad o costo | timeout, concurrencia, límites de tokens y tamaño de contexto |
| respuesta manipulada | cambio de scores | scores deterministas e inmutables para la IA |
| publicación automática | difusión incorrecta | aprobación humana y validador de informe |

## Riesgo residual

El modelo puede producir inferencias incorrectas aun con controles. Por ello su salida permanece como propuesta, incluye hechos, inferencias, confianza, advertencias, versión de prompt/modelo y evidencias relacionadas. La función debe desactivarse ante pérdida de aislamiento, auditoría o control de herramientas.
