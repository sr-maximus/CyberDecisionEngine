# Validación Cyber-PESTEL y Cyber-Porter

El contrato `strategic-evidence-v1.2.0` exige seis dimensiones Cyber-PESTEL y cinco fuerzas Cyber-Porter. Toda dimensión permanece presente con `signalScore`, `confidence`, `coverage`, `validatedPressure`, estado, evidence IDs y limitaciones.

Reglas verificadas automáticamente:

- `signalScore` con evidencia es visible aunque la presión validada sea `N/D`;
- una ausencia usa `N/D/no_data`, no cero;
- una contradicción reduce contribución y confianza;
- copias sindicadas se agrupan antes de puntuar;
- el radar y el mapa de calor usan `signalScore`;
- el validador rechaza dimensiones omitidas, scores sin evidence IDs y visualizaciones estratégicas ausentes;
- Cyber-Porter no publica índice agregado si `MarketScope` es provisional;
- PESTEL/Porter no confirman incidentes ni ATT&CK, ATLAS o DISARM.

La calibración de clasificación no declara error menor o igual a 3 %: no existe todavía un conjunto humano independiente y representativo que permita demostrarlo. La plataforma informa esta limitación sin impedir el análisis determinista.
