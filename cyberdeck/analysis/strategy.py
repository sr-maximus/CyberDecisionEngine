from __future__ import annotations

from collections import Counter
from typing import Dict, Iterable

from cyberdeck.schemas import EvidenceStatus, OrganizationProfile, RiskFinding, ThreatEvent


def build_strategic_action_plan(
    findings: Iterable[RiskFinding],
    events: Iterable[ThreatEvent],
    org: OrganizationProfile,
    source_coverage: Dict[str, object],
) -> Dict[str, object]:
    finding_list = list(findings)
    event_list = [
        event
        for event in events
        if event.evidence_status in {EvidenceStatus.DIRECT, EvidenceStatus.VALIDATED, EvidenceStatus.CONFIRMED}
    ]
    top_risk = max((finding.residual_risk for finding in finding_list), default=0.0)
    category_counts = Counter(event.category for event in event_list)
    technique_counts = Counter(event.technique or "unmapped" for event in event_list)
    kev_count = sum(
        1
        for event in event_list
        if "kev" in event.tags and event.vulnerability_status in {"cve_applicable", "kev_exposed", "exploitation_observed"}
    )
    fraud_signal = category_counts.get("phishing", 0) + category_counts.get("fraud", 0) + sum(1 for event in event_list if "fraud" in event.tags)
    roles = [
        {
            "role": "Junta / CEO",
            "strategic_decision": "Aprobar apetito de riesgo cyber-fraude y umbrales de escalamiento ejecutivo.",
            "preventive": "Exigir tablero mensual con KEV, EPSS, fraude, cobertura ATT&CK y excepciones de patching.",
            "corrective": "Activar comite ejecutivo si riesgo residual critico supera el umbral o hay exposicion KEV sin remediar.",
            "predictive": "Usar forecast 7/14/30 dias para decidir refuerzo temporal de presupuesto, comunicacion y capacidad SOC.",
            "technical_detail": "Indicadores: KEV abiertos, EPSS alto, T1190/T1566, incidentes por canal digital, MTTR y cobertura D3FEND.",
        },
        {
            "role": "CISO",
            "strategic_decision": "Orquestar el portafolio de controles que reduzca maxima perdida esperada por unidad de esfuerzo.",
            "preventive": "Priorizar controles D3FEND asociados a técnicas ATT&CK sustentadas; mantener el resto como referencia preventiva.",
            "corrective": "Convertir los top riesgos en backlog con owner, fecha, evidencia y criterio de aceptacion.",
            "predictive": "Vigilar aceleracion de KEV/EPSS, concentracion por tecnica y senales SOCMINT/Dark Web autorizada.",
            "technical_detail": "Acciones: patching por riesgo, detecciones SIEM/NDR/EDR, hardening IAM, pruebas de respuesta y reglas antifraude.",
        },
        {
            "role": "Director SOC / Cyber Defense",
            "strategic_decision": "Alinear detecciones a TTP reales en vez de alertas genericas.",
            "preventive": "Crear casos de uso para T1190, T1566, T1078 y ransomware_signal cuando aparezcan en fuentes reales.",
            "corrective": "Medir cobertura de logs, falsos positivos, tiempo de triage y gaps de telemetria por tecnica.",
            "predictive": "Elevar vigilancia cuando suban eventos KEV, advisories o patrones repetidos por fuente.",
            "technical_detail": "Herramientas: SIEM, EDR/XDR, NDR, SOAR, detecciones Sigma/YARA cuando aplique, enrichment CVE/EPSS.",
        },
        {
            "role": "Director de Fraude",
            "strategic_decision": "Integrar fraude digital con inteligencia cyber y no tratarlo como silo transaccional.",
            "preventive": "Fortalecer monitoreo de phishing, smishing, device intelligence, velocity rules y graph analytics.",
            "corrective": "Retroalimentar reglas/modelos con casos confirmados y patrones de beneficiarios, dispositivos y sesiones.",
            "predictive": "Usar senales publicas de suplantacion y picos de phishing para anticipar refuerzo de monitoreo por canal.",
            "technical_detail": "Controles: FIDO2/step-up, scoring transaccional, deteccion de cuentas mula, takedown, case management.",
        },
        {
            "role": "Infraestructura / Vulnerabilidades",
            "strategic_decision": "Mover patching de calendario fijo a priorizacion por explotacion real y criticidad de activo.",
            "preventive": "Cruzar CISA KEV, EPSS, NVD y exposicion externa con CMDB y crown jewels.",
            "corrective": "Remediar o compensar CVEs con KEV/EPSS alto; documentar excepciones aceptadas por riesgo.",
            "predictive": "Anticipar ventanas de cambio si crece la tasa de KEV o advisories de proveedores clave.",
            "technical_detail": "Herramientas: VM, EASM, CMDB, WAF, patch orchestration, SCA/SBOM para dependencias open source.",
        },
        {
            "role": "Cloud / DevSecOps",
            "strategic_decision": "Reducir exposicion de APIs, secretos, pipelines y dependencias antes de explotacion.",
            "preventive": "Integrar GitHub advisories, SCA, IaC scanning, secret scanning y proteccion de ramas.",
            "corrective": "Bloquear despliegues con vulnerabilidades explotables o secretos detectados.",
            "predictive": "Usar tendencias de advisories open source para anticipar actualizaciones de imagenes base y librerias.",
            "technical_detail": "Controles: SAST/SCA/DAST, SBOM, admission control, CSPM/CWPP, API gateway, least privilege.",
        },
        {
            "role": "Riesgo Operacional / GRC",
            "strategic_decision": "Traducir hallazgos tecnicos a riesgo residual, KRIs y apetito de riesgo.",
            "preventive": "Mantener trazabilidad NIST/ISO/SOC2/D3FEND para auditoria y priorizacion de controles.",
            "corrective": "Registrar aceptaciones temporales con impacto, compensatorios y fecha de cierre.",
            "predictive": "Usar PESTEL/Porter y forecast para escenarios trimestrales y pruebas de estres.",
            "technical_detail": "KRIs: residual risk, CE, matrix score, excepciones KEV, cobertura ATT&CK, MTTR, fraude por canal.",
        },
        {
            "role": "Legal / Cumplimiento / Comunicaciones",
            "strategic_decision": "Preparar respuesta regulatoria, contractual y reputacional antes del incidente.",
            "preventive": "Validar obligaciones de notificacion, evidencia, privacidad y terceros criticos.",
            "corrective": "Coordinar comunicaciones, preservacion de evidencia y notificaciones si hay impacto material.",
            "predictive": "Monitorear presion regulatoria, fraude de marca y campanas de suplantacion que requieran comunicacion preventiva.",
            "technical_detail": "Insumos: fuentes, timestamps, decisiones, owners, datos redacted, TLP y cadena de custodia.",
        },
    ]
    early_warnings = [
        {
            "indicator": "KEV activos en tecnologias propias",
            "current_signal": kev_count,
            "trigger": "Cualquier KEV en activo expuesto o crown jewel exige decision CISO en 24-72h.",
            "anticipation": "Reservar ventana de cambio y controles compensatorios antes de explotacion masiva.",
        },
        {
            "indicator": "Concentracion ATT&CK",
            "current_signal": technique_counts.most_common(1)[0][0] if technique_counts else "sin datos",
            "trigger": "Una tecnica domina la corrida o aparece en varias fuentes independientes.",
            "anticipation": "Aumentar detecciones, telemetria y playbooks sobre esa tecnica.",
        },
        {
            "indicator": "Senales fraude/phishing",
            "current_signal": fraud_signal,
            "trigger": "Aumento de phishing/fraude en fuentes publicas o SOCMINT autorizado.",
            "anticipation": "Refuerzo de monitoreo transaccional, customer comms y takedown.",
        },
        {
            "indicator": "Dark Web autorizada",
            "current_signal": source_coverage.get("darkweb", {}).get("direct_or_validated", 0),
            "trigger": "Metadatos redacted con marca, proveedor, credenciales o sector financiero.",
            "anticipation": "Forzar rotacion preventiva, hunting de accesos y revision de terceros.",
        },
        {
            "indicator": "Riesgo residual maximo",
            "current_signal": round(top_risk, 2),
            "trigger": "Riesgo residual critico o creciente despues de controles.",
            "anticipation": "Elevar a comite de riesgo y ajustar capacidad defensiva temporal.",
        },
    ]
    return {
        "purpose": "Esta capa convierte inteligencia tecnica en decisiones por rol. Sirve para anticipar, asignar accountability y coordinar CISO, directores y areas de negocio antes de que el riesgo se materialice.",
        "roles": roles,
        "early_warnings": early_warnings,
    }
