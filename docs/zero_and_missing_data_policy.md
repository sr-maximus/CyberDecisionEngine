# Política de cero y datos faltantes

Estados permitidos: `valid_value`, `observed_zero`, `no_data`, `insufficient_evidence`, `source_unavailable`, `not_applicable`, `not_calculated`, `stale_data`, `partial_data`, `error`.

`observed_zero` requiere consulta ejecutada y denominador conocido. `no_data` significa que no existe base suficiente para el valor. Las tasas solo se calculan con denominador mayor que cero. Riesgo sin hallazgos validados permanece `null/no_data`; PESTEL y Porter sin noticias trazables permanecen `null/insufficient_evidence`.
