import type { LanguageMode } from "../types";

export function DisclosureSummary({ label, language }: { label: string; language: LanguageMode }) {
  return <summary><span className="disclosure-closed-label">{label}</span><span className="disclosure-open-label">{language === "es" ? "Mostrar menos" : "Show less"}</span></summary>;
}
