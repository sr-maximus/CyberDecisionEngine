# Limitaciones pendientes

1. El Índice de Presión de Señales no es un modelo predictivo calibrado. No existe todavía un histórico etiquetado de outcomes con validación temporal y métricas de calibración.
2. La plausibilidad contextual y los pesos de impacto son un modelo de priorización explicable; no sustituyen una cuantificación FAIR ni una estimación actuarial de pérdidas.
3. El Índice de Postura de Ciberinteligencia Externa no evalúa controles internos, arquitectura, procesos, personas, continuidad ni certificaciones.
4. Los valores de control solo se usan si fueron declarados y siguen sin verificación independiente. Los mappings de NIST, ISO, PCI, SOC 2, GDPR, CIS y COBIT no son auditoría.
5. DKIM no puede evaluarse exhaustivamente sin selectores conocidos o evidencia administrativa del dominio. El estado correcto en ese caso es `not_assessed`.
6. Una fuente pública puede limitar cuota, bloquear automatización, cambiar formato o no devolver resultados. El sistema registra la limitación, pero no puede garantizar cobertura total de Internet.
7. SOCMINT se limita a contenido público, indexado o entregado por APIs autorizadas. La ausencia de resultados no demuestra ausencia de conversación.
8. Dark Web se limita a índices y metadatos autorizados. No accede a foros privados, no compra datos, no descarga payloads y no valida por sí solo una filtración.
9. La atribución de actor requiere que una fuente confiable nombre al actor y que exista soporte suficiente; de lo contrario permanece `unattributed`.
10. Las capturas de evidencia dependen de una página pública estable. Una URL de API protegida, expirada o sin sesión se conserva como referencia, pero no se presenta como captura validada.
11. Los sidecars externos tienen tiempos y resultados variables. Las pruebas automatizadas usan fixtures controlados para validar lógica, y las verificaciones Docker confirman integración, no exhaustividad de fuentes reales.
12. La aplicación local usa credenciales de laboratorio documentadas. Un despliegue comercial requiere secretos rotados, SSO o autenticación server-side completa, MFA, sesiones revocables, TLS y gestión centralizada de secretos.
13. El módulo de riesgo virtual de empleados carga el catálogo mundial de países y ciudades en un fragmento diferido de aproximadamente 8 MB. No afecta la carga inicial ni los demás módulos, pero una siguiente optimización debería servir ese catálogo por región desde la API o cargarlo bajo demanda.
