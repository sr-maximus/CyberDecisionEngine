# Auditoría de `country-state-city`

**Fecha de medición:** 2026-07-19  
**Versión instalada:** 3.2.1  
**Build:** Node 22 Alpine, TypeScript 5.9.3, Vite 6.4.3.

## Uso real

Se localizaron dos imports, ambos dinámicos:

1. `EmployeeRiskView.loadCities`: carga ciudades del país seleccionado para el formulario individual.
2. `FilterRail`: carga ciudades de los países seleccionados para filtros estratégicos.

No existe un import estático accidental. Países, códigos ISO, continentes y capitales provienen de `world-countries`; el catálogo completo de ciudades solo se solicita cuando una interacción lo necesita.

## Medición de producción

Build limpio con `docker compose build --no-cache web`:

| Artefacto | Tamaño | Gzip | Carga |
|---|---:|---:|---|
| HTML | 0.40 KB | 0.28 KB | inicial |
| CSS | 160.71 KB | 26.82 KB | inicial |
| JS principal | 867.35 KB | 201.70 KB | inicial |
| `country-state-city` | 8,065.19 KB | 2,188.53 KB | diferida |

Transformación: 1,628 módulos. Build Vite: 4.20 s después de compilar TypeScript en el runtime local disponible. El warning de 500 KB corresponde principalmente al chunk diferido.

## Evaluación

| Alternativa | Ventaja | Riesgo/limitación | Decisión |
|---|---|---|---|
| Mantener lazy loading | preserva cobertura y no penaliza el primer render | primera selección de ciudades descarga 2.19 MB gzip | seleccionada |
| Catálogo de capitales | muy pequeño | pierde cobertura requerida | descartada |
| Subconjuntos por país en build | carga óptima por país | exige un generador versionado y cientos de artefactos | roadmap P2 |
| Resolver en backend | reduce JS y permite caché | añade endpoint, almacenamiento y migración | roadmap P2 |
| API geográfica externa | implementación rápida | privacidad, costo y dependencia de red | descartada para funciones básicas |

## Decisión

Se conserva `country-state-city` con carga dinámica. El warning es real, pero no bloquea el frontend ni forma parte del chunk inicial. Una refactorización inmediata reduciría cobertura o introduciría una nueva dependencia operacional sin beneficio suficiente para el flujo principal.

## Controles vigentes

- la carga ocurre solo después de seleccionar país;
- se limita la lista a 6,000 ciudades en riesgo de empleados y 1,200 en filtros;
- la UI dispone de capitales como fallback inmediato;
- no se realizan llamadas a terceros;
- el proceso es local y puede cachearse por el navegador.

## Próximo criterio de aceptación

Migrar a catálogos por país únicamente cuando una medición de usuario demuestre latencia perceptible. Objetivo: chunk por país menor de 250 KB gzip, misma cobertura, búsqueda menor de 100 ms y funcionamiento offline.
