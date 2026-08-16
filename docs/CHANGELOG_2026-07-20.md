# Registro de cambios 2026-07-20

## Inteligencia estratégica

- PESTEL y Porter usan evidencia corporativa pública, regulatoria, sectorial y
  de noticias; las noticias dejaron de ser la única base analítica;
- la cobertura de evidencia, la confianza y la presión direccional se muestran
  como magnitudes diferentes;
- una dimensión con evidencia, pero sin soporte suficiente para puntuar presión,
  conserva sus aspectos y cobertura en lugar de publicar un cero ficticio;
- el snapshot común propaga versión, estado, aspectos, cobertura y limitaciones
  al dashboard, HTML ejecutivo, HTML técnico, JSON y CSV;
- las consultas estratégicas incluyen regulación, resultados e inversión,
  competencia, proveedores, clientes, transformación digital, sostenibilidad y
  asuntos legales o reputacionales.

## Experiencia y navegación

- el alcance, la configuración, la ejecución, el progreso y el resumen se
  consolidaron en Overview;
- el menú separado `Alcance de análisis` fue retirado y su URL heredada redirige
  a Overview;
- `Red SOCMINT` fue sustituido por `Inteligencia SOCMINT` en navegación,
  encabezados, accesibilidad y documentación;
- los informes ejecutivo y técnico aparecen como productos independientes en
  el historial, con apertura y descarga directas.

## Evidencia e informes

- el navegador interno captura evidencia durante la generación solicitada por
  el usuario y conserva URL final, título, fecha UTC, hash, dimensiones y
  versión del navegador;
- la selección de capturas prioriza dominios oficiales y relaciones directas,
  evita feeds no visuales y no utiliza vulnerabilidades contextuales como prueba
  de aplicabilidad;
- las capturas se sirven como activos locales del informe técnico y pueden
  ampliarse sin depender de imágenes remotas;
- la generación produce un informe ejecutivo y otro técnico, sin alias HTML
  históricos que duplicaban el catálogo.

## OpenClaw y operación

- OpenClaw se ejecuta como gateway interno aislado, autenticado y sin puerto
  publicado al host;
- el token se genera en tiempo de ejecución y no se conserva en el repositorio;
- las herramientas de sistema, navegador, escritura y red permanecen denegadas
  por defecto;
- si no existe una credencial de modelo verificable, el pipeline determinista
  continúa y el estado se informa como `configured_unverified`.

## Calidad y regresión

- 127 pruebas Python y lint Ruff aprobados;
- las pruebas históricas dejaron de depender de corridas eliminadas y usan un
  fixture sintético identificado explícitamente como prueba;
- el historial operativo anterior se limpió sin eliminar usuarios, licencias ni
  configuración;
- las corridas autorizadas se validan de forma independiente; sus nombres,
  dominios, identificadores, métricas y artefactos permanecen fuera de Git y el
  procedimiento queda en `docs/auditoria/04-validacion-paso-a-paso-dominios.md`.
