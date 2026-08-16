# Plantilla de comparación antes y después

Esta tabla documenta qué debe compararse sin publicar corridas, dominios,
cuentas, hashes ni resultados operativos.

| Aspecto | Antes | Después esperado |
|---|---|---|
| Salud de fuentes | interpretación no unificada | saludables, elegibles y consultadas separadas |
| Radar/calor | podía renderizar sin evidencia suficiente | estado explícito de evidencia insuficiente |
| Escenarios | rutas de cálculo independientes | instancias deduplicadas y trazables |
| PESTEL/Porter | riesgo de valores heredados | sin dato cuando no existen clusters trazables |
| Alcance | lecturas distribuidas | snapshot común para dashboard e informes |
| Exportes | evidencia sin contrato único | JSON/CSV vinculados al snapshot validado |
| Consistencia | verificación manual | resultado local `<pass-or-fail>` para todos los consumidores |

Los valores medidos se guardan únicamente en `artifacts/`, que está excluido de
la publicación.
