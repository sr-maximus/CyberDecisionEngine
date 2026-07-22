# Fórmula Cyber-PESTEL basada en evidencia

Modelo: `strategic-evidence-v1.2.0`.

Para un clúster `j` y una dimensión `d`, la calidad base es una media ponderada, no un producto:

```text
B_jd = 0.18R + 0.16Q + 0.10T + 0.16D
     + 0.08N + 0.12C + 0.10X + 0.10A
```

`R` es relación con el sujeto, `Q` calidad de fuente, `T` recencia, `D` directitud, `N` novedad, `C` corroboración, `X` calidad de extracción y `A` fuerza aprobada del mapeo. Una contradicción explícita aplica `B_jd := 0.65 * B_jd`.

```text
EvidenceMass_d = SUM(B_jd * Magnitude_j)
Coverage_d = 1 - EXP(-EvidenceMass_d / tau_d)
SignalScore_d = 100 * (0.65*Coverage_d + 0.20*Directness_d
                      + 0.15*MIN(1, ClusterCount_d/4))
QualitySupport_d = 0.20*SourceDiversity_d + 0.30*Directness_d
                 + 0.20*Agreement_d + 0.30*ExtractionQuality_d
Confidence_d = 100 * (0.20*Coverage_d + 0.80*QualitySupport_d)
```

`SignalScore` es la serie principal del radar y mapa de calor. `Coverage` solo expresa disponibilidad y `Confidence` soporte analítico. Las contradicciones reducen además la confianza en 35 %.

La presión validada conserva una puerta más estricta:

```text
Z_d = SUM(B_jd * Magnitude_j * Direction_jd) / EvidenceMass_d
ValidatedPressure_d = CLAMP(50 + 50*TANH(1.5*Z_d), 0, 100)
```

Se publica solo con dos clústeres directos y dos fuentes independientes, o con un evento oficial, directo, validado y de alta magnitud. Si hay señales pero falta ese soporte, `ValidatedPressure = null` y el estado queda `candidate/under_review`; la señal no desaparece. Sin evidencia se muestra `N/D`, nunca cero.

