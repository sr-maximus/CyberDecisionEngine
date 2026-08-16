# Plantilla de diagnóstico inicial de CyberDecisionEngine

## Alcance

El diagnóstico cubre frontend, API, motor analítico, persistencia y sidecars
contenedorizados. Debe ejecutarse con un alcance sintético o expresamente
autorizado. Los datos del equipo, nombres de organizaciones, dominios,
identificadores, cuentas y resultados se conservan fuera del repositorio.

## Entorno a registrar localmente

| Elemento | Valor local |
|---|---|
| Sistema y arquitectura | `<os-and-architecture>` |
| Recursos disponibles | `<cpu-memory-disk>` |
| Docker y Compose | `<versions>` |
| Python | `<version>`; debe cumplir `pyproject.toml` |
| Node y gestor de paquetes | `<versions>` |
| Revisión del código | `<local-commit>` |

El registro completo debe guardarse en un artefacto ignorado por Git.

## Componentes y límites

| Componente | Responsabilidad | Persistencia/red |
|---|---|---|
| `web` | navegación, dashboards, evidencia y administración | Nginx, puerto configurable |
| `api` | ejecución, contexto, informes, licencias, monitoreo e IA | puerto configurable |
| `postgres` | corridas, contextos, licencias y auditoría | volumen Docker |
| `cyberdeck` | recolección, normalización, análisis, semántica y reportes | biblioteca Python |
| `osint-tools` | utilidades públicas acotadas | red interna |
| `kali-surface` | superficie externa defensiva y autorizada | red interna |
| `spiderfoot` | recolección pasiva en segundo plano | red interna |
| `tor-proxy` | proxy opcional y aislado | red interna; sin puerto host |
| `reports/web` | informes y exportes generados | almacenamiento local ignorado |
| `data/web_runs` | contexto atómico de cada corrida | almacenamiento local ignorado |

## Línea base de calidad

| Control | Resultado local | Criterio |
|---|---|---|
| Pruebas Python | `<pass-or-fail>` | todas aprobadas |
| Lint Python | `<pass-or-fail>` | sin incidencias |
| Build React/TypeScript | `<pass-or-fail>` | compilación completa |
| API y web | `<pass-or-fail>` | endpoints saludables |
| Persistencia | `<pass-or-fail>` | lectura y escritura verificadas |
| Higiene pública | `<pass-or-fail>` | sin credenciales ni datos operativos |

## Hallazgos que deben comprobarse

- el runtime cumple la versión declarada;
- el bundle HTML/JSON/CSV pasa el validador final;
- ninguna afirmación soportada carece de evidencia resoluble;
- el historial se pagina antes de crecer a volumen de producción;
- los componentes diferidos no bloquean la carga inicial;
- los healthchecks no generan ruido ni abren puertos innecesarios;
- los conectores opcionales degradan de forma explícita cuando no están
  configurados.

## Variables y secretos

Los ejemplos de entorno solo declaran nombres de variables y valores no
sensibles. Usuarios, contraseñas, tokens, claves, sales y credenciales de base de
datos deben suministrarse por el mecanismo seguro del despliegue y nunca
registrarse en logs, capturas, informes o commits.

## Cierre

El diagnóstico se considera completo cuando las verificaciones son
reproducibles, el informe final queda aprobado y los artefactos locales han sido
revisados para evitar información sensible antes de cualquier intercambio.
