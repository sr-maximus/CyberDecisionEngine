import type { LanguageMode, SourceStatus, ThreatEvent } from "../types";

const TOOL_NAME_PATTERNS = [
  /[^.:\n]+ sidecar unavailable:[^.]+\.?/gi,
  /[^.:\n]+ provider (?:ignored|omitted|unavailable):[^.]+\.?/gi,
  /\b[a-z0-9_.-]+_(?:sidecar|scanner|collector|search|surface|index)\b/gi,
  /\b(?:scanner|collector|sidecar|search provider):[a-z0-9_.-]+\b/gi,
  /\btool:[a-z0-9_.-]+\b/gi,
  /Internet Search:\s*/gi
];

export function displaySourceName(source?: string | null, language: LanguageMode = "es"): string {
  const value = (source || "").trim();
  if (!value) return language === "en" ? "Public evidence" : "Evidencia publica";
  if (/external surface|superficie externa|dns|whois|certificate|certificado|technology exposure/i.test(value)) {
    return language === "en" ? "External surface" : "Superficie externa";
  }
  if (/passive inventory|inventario pasivo/i.test(value)) {
    return language === "en" ? "Passive inventory" : "Inventario pasivo";
  }
  if (/public search|busqueda publica|news|noticia|rss/i.test(value)) {
    return language === "en" ? "Public search" : "Busqueda publica";
  }
  if (/evidencia web validada|validated web evidence|evidence explorer/i.test(value)) {
    return language === "en" ? "Validated web evidence" : "Evidencia web validada";
  }
  if (/public index|indice publico|osint public|sidecar/i.test(value)) {
    return language === "en" ? "Public index" : "Indice publico";
  }
  if (/ransomware|dark web|tor|onion|leak/i.test(value)) {
    return language === "en" ? "Authorized dark web index" : "Indice dark web autorizado";
  }
  if (/configured cti|cti configurada|threat intelligence/i.test(value)) {
    return language === "en" ? "Configured CTI platform" : "Plataforma CTI configurada";
  }
  if (/passive surface index|indice pasivo de superficie/i.test(value)) {
    return language === "en" ? "Passive surface index" : "Indice pasivo de superficie";
  }
  if (/vulnerability|vulnerabil|advisory|kev|epss/i.test(value)) {
    return language === "en" ? "Vulnerability intelligence" : "Inteligencia de vulnerabilidades";
  }
  if (/socmint|reddit|facebook|instagram|tiktok|twitter|\bx\b|linkedin/i.test(value)) {
    return "SOCMINT";
  }
  return value.replace(/\s+/g, " ");
}

export function cleanEvidenceTitle(title?: string | null): string {
  let text = (title || "").trim();
  for (const pattern of TOOL_NAME_PATTERNS) text = text.replace(pattern, "");
  return text
    .replace(/<SFURL>[\s\S]*?<\/SFURL>/gi, "")
    .replace(/\bobservo\b/gi, "detecto")
    .replace(/\bobserv[oó]\b/gi, "detecto")
    .replace(/\s+\|\s*query:/gi, " | busqueda:")
    .replace(/\(\s*real\s*\)/gi, "")
    .replace(/\s{2,}/g, " ")
    .replace(/^[:\-,;\s]+/, "")
    .trim() || "Evidencia pública";
}

export function cleanEvidenceText(text?: string | null): string {
  let value = (text || "").trim();
  for (const pattern of TOOL_NAME_PATTERNS) value = value.replace(pattern, "");
  if (/api key|not configured|configure/i.test(value)) {
    return value.replace(/GOOGLE_CSE_API_KEY|GOOGLE_CSE_CX|BRAVE_SEARCH_API_KEY/gi, "credencial opcional").trim();
  }
  return value
    .replace(/\(\s*real\s*\)/gi, "")
    .replace(/\s{2,}/g, " ")
    .replace(/^[:\-,;\s]+/, "")
    .trim() || "Evidencia publica validada";
}

export function eventEvidenceUrl(event: Pick<ThreatEvent, "evidence_url">): string | null {
  return publicEvidenceUrl(event.evidence_url || "");
}

export function publicEvidenceUrl(url?: string | null): string | null {
  const value = (url || "").trim();
  try {
    const parsed = new URL(value);
    if (!["http:", "https:"].includes(parsed.protocol)) return null;
    const host = parsed.hostname.toLowerCase();
    if (!host || host === "localhost" || host.endsWith(".localhost") || host === "[::1]" || /^(127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.)/.test(host)) return null;
    if (/\[REDACTED\]|%5BREDACTED%5D/i.test(value)) return null;
    parsed.hash = "";
    return parsed.href;
  } catch {
    return null;
  }
}

export function statusDisplayName(status: SourceStatus, language: LanguageMode): string {
  return displaySourceName(status.name, language);
}
