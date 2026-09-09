export function formatNumber(value: number): string {
  return new Intl.NumberFormat("en-US", { maximumFractionDigits: 0 }).format(value);
}

export function formatRisk(value: number): string {
  return value.toFixed(value >= 10 ? 1 : 2);
}

import type { LanguageMode } from "../types";

export function formatDateTime(value?: string | null, language: LanguageMode = "en"): string {
  const emptyLabel = language === "es" ? "Sin datos" : "No data";
  if (!value) return emptyLabel;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return emptyLabel;
  return new Intl.DateTimeFormat(language === "es" ? "es-CO" : "en-US", {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hour12: language === "en"
  }).format(date);
}

export function riskTone(value: number): "low" | "medium" | "high" | "critical" {
  if (value >= 35) return "critical";
  if (value >= 24) return "high";
  if (value >= 12) return "medium";
  return "low";
}
