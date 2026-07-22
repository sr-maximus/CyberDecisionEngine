# Matriz de consolidación funcional

| Superficie | Propósito canónico | Datos/acciones | Decisión |
|---|---|---|---|
| Visión general | Lectura resumida de resultados, tendencia, estado y fuentes | Snapshot de la corrida seleccionada | Se retiró el formulario duplicado |
| Alcance | Configurar organización, dominios, comparativos, sector, países, período y profundidad | Crea corridas y perfiles de monitoreo | Único editor de alcance organizacional |
| Tablero estratégico | Decisión ejecutiva y trazabilidad | Snapshot versionado | Sin campos de entrada duplicados |
| Riesgo virtual de empleados | Investigación autorizada de personas | Formulario individual/archivo, permisos e informe propios | Separado del alcance organizacional |

## Cambios verificados

- `App.tsx` ya no renderiza `DomainComposer` en Visión general.
- `DomainComposer` ya no permite seleccionar persona.
- La solicitud general fija `subject_type=organization`.
- El módulo de empleados conserva su formulario y su informe independiente.
- La navegación mantiene rutas distintas y no duplica KPI con semánticas alternativas.
