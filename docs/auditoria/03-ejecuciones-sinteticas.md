# Ejecuciones sintéticas y privadas

Este documento describe qué debe registrarse durante una validación sin
publicar organizaciones, dominios, identificadores de corrida ni resultados
operativos.

## Datos que se completan localmente

- organización autorizada: `<organization-name>`;
- alcance primario: `<authorized-domain-list>`;
- país y sector: `<authorized-context>`;
- identificador de corrida: `<run-id>`;
- ventana y modo: `<analysis-window>` y `<run-mode>`;
- informe ejecutivo y técnico: `<local-report-path>`;
- estado del validador: `<approved-or-rejected>`.

## Evidencia esperada

1. El alcance fue confirmado explícitamente antes de recolectar.
2. Cada fuente conserva estado, tiempo, conteos y limitaciones.
3. Los informes proceden del mismo snapshot canónico.
4. Las afirmaciones críticas enlazan evidencia o quedan marcadas como no
   demostradas.
5. Los archivos generados permanecen bajo directorios ignorados por Git.

## Regla de publicación

El repositorio público conserva el procedimiento, no los datos completados.
Antes de compartir una captura o informe, sustituye todos los campos por
marcadores sintéticos, elimina usuarios y contactos del entorno analizado y
confirma que no existan secretos ni metadatos de una ejecución real.
