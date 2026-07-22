# Guía Claim-Evidence

1. Formular una afirmación acotada a entidad, periodo y condición.
2. Enlazar evidencia mediante `ClaimEvidenceLink`; no usar coincidencia textual como prueba directa.
3. Registrar método, validador, fecha, hash, URL y relación.
4. Buscar evidencia contradictoria y resolverla antes de confirmar.
5. Explicar qué demuestra y qué no demuestra.
6. Calcular confianza sin convertirla en probabilidad de ataque.
7. Proponer una decisión con responsable y criterio de cierre.

## Ejemplo válido

“El certificado de `subdominio.example` está vencido” puede validarse con handshake TLS reproducible, fecha de observación, entidad, hash y URL. Esto demuestra la condición del certificado; no demuestra explotación ni incidente.

## Ejemplo inválido

“La organización fue comprometida” a partir de una noticia que contiene el nombre. La coincidencia crea un registro relacionado, no evidencia directa ni incidente confirmado.

## Cierre

Una afirmación se cierra como validada, mitigada o descartada. El cierre requiere evidencia de revalidación o una justificación auditable; cambiar una etiqueta no es cierre.
