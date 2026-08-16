# Registro de cambios 2026-07-19

## Cierre de auditoría integral

- registro metodológico versionado y reutilizado por API, dashboard, manual e informes;
- ciclo de fuentes normalizado en registradas, elegibles, consultadas, exitosas, productivas, vacías, degradadas, omitidas y no configuradas;
- contrato de capturas verificables y prohibición de imágenes remotas incrustadas como evidencia del informe;
- 1.500 elementos reclasificados como plantillas preventivas de referencia, no como escenarios ejecutables;
- alcance organizacional separado del flujo individual de riesgo virtual de empleados;
- regeneración trazable de informes para filesystem y PostgreSQL;
- manual integral y guía de despliegue publicados en HTML navegable desde Uso y modelo;
- paquetes sintéticos y corridas multidominio regenerados y aprobados sin
  publicar datos del alcance autorizado.

## Datos, semántica e informes

- fuente canónica `DecisionIntelligenceSnapshot` para dashboard, HTML, JSON y CSV;
- modelo claim-evidence endurecido para no elevar registros sin método ni evidencia;
- validador automático con estado `approved`, `approved_with_observations` o `rejected`;
- informe final únicamente cuando el validador lo aprueba;
- paridad de conteos y referencias entre contexto, JSON y CSV;
- hash común de snapshot verificado en API, HTML ejecutivo, HTML técnico, JSON y CSV;
- localización de país, sector y modo en informes;
- eliminación de marcadores de evidencia vacíos;
- informe solicitado por usuario, no generado automáticamente al recolectar.

## Frontend y manual

- acceso al manual HTML desde Uso de la plataforma;
- país del tablero estratégico localizado mediante el catálogo central;
- manual integral navegable, documentos semánticos y guía de lectura;
- documentos de arquitectura/seguridad OpenClaw y evaluación OpenCTI;
- bitácora reproducible con marcadores sintéticos y resultados conservados
  localmente.

## Pruebas y ejecuciones

- 120 pruebas aprobadas para semántica, OpenCTI opcional, OpenClaw en modo propuesta e informes;
- dos corridas autorizadas independientes con `runId`, salidas y logs
  segregados fuera del repositorio;
- validación visual de manual e informes ejecutivo/técnico;
- servicios Docker conservados en redes internas y sin alterar aplicaciones externas al proyecto.
