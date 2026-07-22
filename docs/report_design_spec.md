# Especificación de informes

## Principios

- Identidad dinámica desde `ReportContext`; no se infiere un grupo sin validación del alcance.
- El registro de decisión aparece en ejecutivo y técnico desde el mismo snapshot.
- Ejecutivo: referencias compactas y decisiones; técnico: referencias completas y URLs.
- Los cinco dominios permanecen visibles aunque no tengan hallazgos.
- `null` no se presenta como cero y una gráfica inelegible se reemplaza por explicación.
- Los alias canónicos siguen `{group_slug}_{period}_{run_id}_{type}.html`.

## Jerarquía

Portada, interpretación, estado de decisión, dominios, evidencia/hallazgos, escenarios, riesgo, PESTEL/Porter, fuentes, decisiones, plan, limitaciones y referencias.
