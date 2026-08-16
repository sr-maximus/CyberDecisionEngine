# Validación paso a paso de un alcance autorizado

La validación se ejecuta localmente con información suministrada por el titular
del alcance. Este repositorio no contiene nombres, dominios, usuarios ni
resultados de organizaciones evaluadas.

## 1. Preparar el perfil

1. Copia `config/orgs/example_organization.yml` fuera del repositorio o en un
   archivo ignorado.
2. Sustituye `<organization-name>` y `<authorized-domain-list>` solo con datos
   cuya evaluación esté autorizada.
3. Mantén `authorized_scope: true` únicamente después de verificar la
   autorización.

## 2. Ejecutar

Usa el modo, ventana y fuentes apropiados. Los identificadores y artefactos
resultantes deben permanecer en `data/web_runs/`, `reports/web/`, `outputs/` o
`artifacts/`, todos tratados como datos locales.

## 3. Comprobar

- estado final de la corrida;
- separación entre fuentes registradas, elegibles, intentadas y productivas;
- deduplicación y trazabilidad;
- cobertura de evidencia por afirmación;
- coherencia entre dashboard, JSON, CSV e informes;
- estado `approved` del validador antes de usar un informe como final.

## 4. Registrar sin exponer

Documenta el método con marcadores como `<run-id>`, `<source-count>` y
`<validation-status>`. No copies al repositorio capturas, URLs, nombres de
cuenta, correos de personas evaluadas, dominios, claves, contraseñas, hashes de
credenciales ni resultados operativos.
