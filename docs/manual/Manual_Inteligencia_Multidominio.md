# Manual de inteligencia multidominio

**Versión:** 1.0.0
**Fecha:** 2026-08-20
**Creador conceptual:** Edwin Javier Peñuela Camacho; modelo desarrollado desde 2022.

## Para qué sirve

Este módulo organiza observaciones públicas de una corrida en dos ejes:

- **Tecnología:** IT, IoT, IIoT, OT y Sin clasificar.
- **Análisis:** Cyber, Fraude, Marca, Desinformación e IA.

Permite responder qué se observó públicamente, con qué soporte, qué marcos pueden
ayudar a interpretarlo y qué información falta antes de decidir. No sustituye
un inventario interno ni una validación técnica dentro de la organización.

## Cómo usar los filtros

1. Seleccione uno o varios dominios tecnológicos.
2. Seleccione uno o varios ámbitos de análisis.
3. Revise la Huella Tecnológica Pública y el libro de evidencia.
4. Abra los grafos para inspeccionar entidades y relaciones trazables.
5. Genere el informe desde la misma selección si necesita una vista acotada.

`Todos` restablece cada eje. La selección se conserva durante la sesión. Cambiar
un filtro no ejecuta una búsqueda nueva, no borra datos y no altera el snapshot.

## Huella Tecnológica Pública

Cada elemento muestra:

- dominio tecnológico principal y dominios secundarios;
- estado de atribución pública;
- entidad, host o URL observada;
- fecha, confianza y referencias de evidencia;
- marcos preventivos relacionados;
- escenarios candidatos que superaron sus puertas de evidencia.

Estados de atribución:

| Estado | Lectura correcta |
|---|---|
| Posible | existe una señal, pero su relación no está demostrada |
| Relacionada | tiene contexto de alcance, aún requiere validación |
| Observada públicamente | una observación directa o validada la vincula |
| Corroborada públicamente | dos referencias independientes la respaldan |
| Confirmada | existe un método explícito de confirmación |

## Tipos de fraude

El análisis contempla phishing, smishing, vishing, BEC, suplantación de marca,
dominios falsos, aplicaciones falsas, soporte falso, empleo falso, reclutamiento
de mulas, fraude de inversión, QR falso, abuso de pagos, toma de cuentas,
credential stuffing, deepfake y suplantación ejecutiva. Una coincidencia crea
una señal; solo evidencia validada permite elevarla a hallazgo.

## Marcos y escenarios

Los mappings disponibles incluyen ATT&CK Enterprise/ICS, EMB3D, F3, D3FEND,
ATLAS, DISARM, CWE, CAPEC y familias de control NIST, ISO, CIS, COBIT, PCI y
SOC. Un mapping describe compatibilidad analítica, no cumplimiento ni ataque
observado.

La biblioteca contiene 1.138 referencias preventivas: 1.116 derivadas de marcos
y 22 multidominio. Las 22 cubren presencia tecnológica, IoT/IIoT/OT,
administración remota, vulnerabilidades aplicables, obsolescencia, terceros,
transiciones IT-IoT-OT, campañas ICS, EMB3D, pérdida de vista/control y cadenas
de fraude. Solo se muestran como candidatas cuando la corrida satisface su
puerta explícita.

## Lectura del riesgo

- **Presión:** concentración relativa de señales, no probabilidad.
- **Suficiencia:** cuánto soporte tiene una clasificación.
- **Confianza:** fuerza de evidencia de una afirmación.
- **Riesgo inherente:** plausibilidad e impacto antes de controles.
- **Riesgo residual:** solo se publica como conocido cuando existen controles
  observables; de lo contrario indica evidencia de controles insuficiente.

## Informes y exportaciones

El ejecutivo resume huella, distribución, señales relevantes, limitaciones y
posibilidades de decisión. El técnico conserva evidencia, URL, hash, timestamp,
atribución, mappings y escenario. JSON y CSV usan el mismo snapshot y la misma
selección de filtros.

Los nombres de componentes internos no se muestran. El usuario ve capacidades
funcionales y URLs de evidencia; el operador conserva la procedencia técnica en
trazas internas separadas.

## Glosario

- **Huella tecnológica pública:** observaciones externas atribuibles con el
  grado indicado.
- **IIoT:** dispositivos conectados de uso industrial.
- **OT:** tecnología operacional que supervisa o controla procesos físicos.
- **Mapping:** correspondencia analítica con un marco de referencia.
- **Escenario candidato:** hipótesis preventiva con soporte mínimo de corrida.
- **Corroboración:** respaldo por referencias independientes.

> Este análisis se basa en evidencia pública y observaciones externas consolidadas por CyberDecisionEngine. No constituye un inventario interno, auditoría, prueba de compromiso, confirmación de firmware instalado ni certificación de cumplimiento.
