# Controles de seguridad de OpenClaw

## Configuración mínima de producción

- contenedor y usuario dedicados;
- red Docker sin acceso directo a PostgreSQL;
- endpoint autenticado con token rotativo;
- volúmenes de solo lectura, salvo auditoría acotada;
- allowlist de endpoints y herramientas;
- modo `analysis_only` por defecto;
- timeout, concurrencia y presupuesto de tokens;
- trazabilidad `organization_id` + `run_id` + solicitud + herramientas + respuesta;
- parada administrativa y revocación del token;
- retención y redacción configurables.

## Matriz de permisos

| Acción | Predeterminado | Aprobación |
|---|---|---|
| leer resumen validado de una corrida | permitido | rol con acceso al run |
| explicar un score existente | permitido | no modifica datos |
| proponer consulta o reintento | permitido | propuesta únicamente |
| crear borrador de informe | permitido | revisión antes de publicar |
| navegar, ejecutar colector o programar | denegado | flujo administrativo separado |
| ejecutar shell o modificar archivos | denegado | no habilitable desde contenido IA |
| cambiar score, evidencia o estado | denegado | proceso determinista/humano |

## Pruebas existentes

`tests/test_ai_orchestration.py` valida que el payload sea de propuesta, que la planificación use estructura segura y que la configuración publique la política. El sistema debe probar también modo sin IA y rechazo de contenido que intente redefinir instrucciones.

## Estado de control validado

El despliegue local ya aplica gateway aislado, token generado fuera del repositorio, denegación de herramientas, límites y pruebas negativas. `OPENCLAW_ENABLED=true` habilita el gateway, no autoriza herramientas ni garantiza un modelo: la credencial del proveedor se gestiona aparte y su ausencia debe mostrarse como `configured_unverified`. El modo `OPENCLAW_ENABLED=false` permanece cubierto como degradación obligatoria.
