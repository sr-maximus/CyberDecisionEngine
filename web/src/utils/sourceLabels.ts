import type { LanguageMode, SourceStatus, ThreatEvent } from "../types";

const TOOL_NAME_PATTERNS = [
  /Kali Surface Tools:?/gi,
  /Kali Surface Sidecar/gi,
  /SpiderFoot Passive Sidecar/gi,
  /SpiderFoot(?: UI)?/gi,
  /OSINT Tools Sidecar/gi,
  /urlscan\.io Public Search/gi,
  /Dark Web Ransomware\.live/gi,
  /Ransomware\.live/gi,
  /Kali sidecar unavailable:[^.]+\.?/gi,
  /SpiderFoot sidecar unavailable:[^.]+\.?/gi,
  /OSINT tools sidecar unavailable:[^.]+\.?/gi,
  /Google CSE omitted:[^.]+\.?/gi,
  /Brave Search omitted:[^.]+\.?/gi,
  /Search provider ignored:[^.]+\.?/gi,
  /subfinder\/amass\/dnsrecon/gi,
  /sfp_[a-z0-9_]+/gi,
  /\b(?:sslscan|wafw00f|whatweb|nuclei|amass|subfinder|dnsrecon)\b/gi,
  /\b(?:kali_surface|osint_tools|spiderfoot|duckduckgo_lite|internet_search|open_web_signal)\b/gi,
  /\btool:[a-z0-9_.-]+\b/gi,
  /Internet Search:\s*/gi
];

export function displaySourceName(source?: string | null, language: LanguageMode = "es"): string {
  const value = (source || "").trim();
  if (!value) return language === "en" ? "Public evidence" : "Evidencia publica";
  if (/kali|subfinder|amass|dnsrecon|sslscan|wafw00f|whatweb|nuclei/i.test(value)) {
    return language === "en" ? "External surface" : "Superficie externa";
  }
  if (/spiderfoot|sfp_/i.test(value)) {
    return language === "en" ? "Passive inventory" : "Inventario pasivo";
  }
  if (/internet search|google|duckduckgo|gdelt|news|rss/i.test(value)) {
    return language === "en" ? "Public search" : "Busqueda publica";
  }
  if (/evidencia web validada|validated web evidence|evidence explorer/i.test(value)) {
    return language === "en" ? "Validated web evidence" : "Evidencia web validada";
  }
  if (/common crawl|osint public|osint tools|osint sidecar|sidecar|urlscan/i.test(value)) {
    return language === "en" ? "Public index" : "Indice publico";
  }
  if (/ransomware|dark web|tor|onion|leak/i.test(value)) {
    return language === "en" ? "Authorized dark web index" : "Indice dark web autorizado";
  }
  if (/misp|stix|taxii/i.test(value)) {
    return language === "en" ? "Configured CTI platform" : "Plataforma CTI configurada";
  }
  if (/shodan|censys/i.test(value)) {
    return language === "en" ? "Passive surface index" : "Indice pasivo de superficie";
  }
  if (/cisa|kev|nvd|epss|github/i.test(value)) {
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
    .replace(/\bobservo\b/gi, "detecto")
    .replace(/\bobserv[oó]\b/gi, "detecto")
    .replace(/\s+\|\s*query:/gi, " | busqueda:")
    .replace(/\(\s*real\s*\)/gi, "")
    .replace(/\s{2,}/g, " ")
    .replace(/^[:\-,;\s]+/, "")
    .trim() || "Evidencia publica validada";
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
  if (!value) return null;
  const match = value.match(/urlscan\.io\/(?:api\/v1\/)?result\/([0-9a-f-]{32,36})\/?/i);
  if (match?.[1]) return `https://urlscan.io/result/${match[1]}/`;
  return value;
}

export function evidencePreviewUrl(url?: string | null): string | null {
  const value = (url || "").trim();
  const match = value.match(/urlscan\.io\/(?:api\/v1\/)?result\/([0-9a-f-]{32,36})\/?/i);
  if (match?.[1]) return `https://urlscan.io/screenshots/${match[1]}.png`;
  return null;
}

export function statusDisplayName(status: SourceStatus, language: LanguageMode): string {
  return displaySourceName(status.name, language);
}
