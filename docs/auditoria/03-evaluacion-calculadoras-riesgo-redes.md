# Evaluacion de calculadoras de riesgo y analisis de redes

Fecha de revision: 2026-07-24

## Decisiones

| Proyecto | Licencia observada | Aporte | Decision |
|---|---|---|---|
| h4x0r/cybrisk | MIT | FAIR, Monte Carlo financiero y comunicacion ejecutiva | No se integra la aplicacion. La plataforma no tiene datos actuariales propios suficientes para publicar perdidas probabilisticas. |
| Laugerr/Cyber-Risk-Calculator | MIT | SLE, ALE y ROSI | Se incorporan formulas generales en `CDE-QRA-1.0`, solo con entradas financieras explicitas. |
| SIA-77/Industrial-Cybersecurity-Risk-Calculator | GPL-3.0 | LOPA y degradacion de barreras OT/ICS | No se copia codigo GPL. Se implementa un modelo propio y sector-neutral de escenarios por capas, `CDE-LAYERED-SCENARIO-1.0`, con entradas explicitas. |
| RescueSocial/Social-Network-Analysis | Sin licencia reutilizable visible | Ideas de clustering y analisis social | No se incorpora codigo ni scraping. El grafo interno se mejora con centralidad de grado, PageRank y betweenness sobre evidencia propia. |

## Reglas aplicadas

- Ninguna cifra financiera se infiere desde OSINT.
- `SLE = valor del activo * factor de exposicion`.
- `ALE = SLE * frecuencia anual`.
- `ROSI` solo existe cuando se declara un costo de control positivo.
- Los resultados financieros son escenarios, no predicciones de perdida.
- El modelo por capas calcula la frecuencia residual y la perdida anual esperada de escenarios declarados para cualquier sector.
- La degradacion cibernetica aumenta la probabilidad efectiva de fallo de cada capa, sin asumir que una noticia o una CVE demuestra degradacion.
- El calculo por capas asume independencia estadistica entre barreras y lo declara como limitacion.
- Los modelos sin entradas suficientes conservan estado `no_data`.
- Las metricas de red se calculan exclusivamente sobre nodos y aristas trazables de la corrida seleccionada.
