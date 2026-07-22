# Navegador interno y capturas de evidencia

## Fuente de verdad

Una captura solo es evidencia visual cuando existe un objeto `EvidenceCapture` vinculado a un `evidenceId`, `runId` y fuente. Los previews remotos o campos heredados de terceros no se convierten en capturas.

## Flujo

`URL canónica -> solicitud de captura -> navegador interno aislado -> validación -> hash -> almacenamiento por runId -> manifiesto -> informe técnico`

El generador de informes nunca vuelve a visitar una URL. Consume únicamente capturas ya persistidas y verificadas. Si no existe una, muestra la causa de ausencia y conserva URL/hash textual.

## Controles

- HTTP/HTTPS públicos; destinos privados, loopback y metadata cloud bloqueados;
- contexto sin cookies ni credenciales persistentes;
- timeout y reintentos acotados;
- detección de login, CAPTCHA, errores y capturas vacías;
- redacción explícita y registrada;
- hash criptográfico, tamaño y dimensiones obligatorios;
- rutas relativas `assets/` sin traversal;
- imágenes remotas rechazadas por el generador;
- validador de informe rechaza imágenes faltantes o remotas.

## Estado real

El contrato, la presentación y la validación están implementados. Las corridas históricas no contienen capturas internas verificadas; por eso los informes regenerados declaran `Captura no disponible` en vez de mostrar imágenes de urlscan como prueba propia.
