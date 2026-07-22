export function formatNumber(value: number): string {
  return new Intl.NumberFormat("en-US", { maximumFractionDigits: 0 }).format(value);
}

export function formatRisk(value: number): string {
  return value.toFixed(value >= 10 ? 1 : 2);
}

export function formatDateTime(value?: string | null): string {
  if (!value) return "No data";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "No data";
  return new Intl.DateTimeFormat("en-US", {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit"
  }).format(date);
}

export function riskTone(value: number): "low" | "medium" | "high" | "critical" {
  if (value >= 35) return "critical";
  if (value >= 24) return "high";
  if (value >= 12) return "medium";
  return "low";
}
