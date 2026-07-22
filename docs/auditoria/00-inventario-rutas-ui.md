# Inventario de rutas de interfaz

La aplicacion usa `?view=<clave>` y control de acceso por rol/licencia.

| Clave | Vista ES | Grupo | Roles base |
|---|---|---|---|
| `overview` | Vision general | Estrategia | todos |
| `dashboards` | Tablero estrategico | Estrategia | todos |
| `scenarios` | Escenarios de decision | Estrategia | ejecutivo y analista |
| `ai` | IA estrategica | Estrategia | ejecutivo y analista |
| `attackSurface` | Superficie de ataque | Estrategia | ejecutivo y analista |
| `brand` | Marca y fraude | Estrategia | ejecutivo y analista |
| `employeeRisk` | Riesgo virtual de empleados | Inteligencia | analista y administracion |
| `disinformation` | Desinformacion | Inteligencia | ejecutivo y analista |
| `osint` | Inteligencia OSINT | Inteligencia | analista y administracion |
| `socmint` | Inteligencia SOCMINT | Inteligencia | analista y administracion |
| `darkweb` | Inteligencia Dark Web | Inteligencia | analista y administracion |
| `frameworks` | Mapeo de frameworks | Inteligencia | ejecutivo y analista |
| `runs` | Historial de analisis | Operacion | analista y administracion |
| `reports` | Informes | Operacion | todos |
| `help` | Uso de la plataforma | Operacion | todos |
| `settings` | Configuracion | Operacion | administrador y superadministrador |

## Controles transversales

- idioma ES/EN, tema claro/oscuro y menu contraible;
- sesion con politicas por rol y cierre explicito;
- contexto de ejecucion seleccionado visible en las vistas con evidencia;
- licencia por modulo, salvo superadministrador;
- los KPIs deben abrir el detalle del mismo `runId`.

## Alcance consolidado

`overview` integra la configuracion del alcance, el lanzamiento, el progreso por
etapas y la lectura de resultados. La antigua clave `domains` se conserva solo
como redireccion de compatibilidad hacia `overview`; no aparece en el menu ni
renderiza un segundo formulario.
