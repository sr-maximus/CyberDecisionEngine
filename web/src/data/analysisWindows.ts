import type { AnalysisWindow, LanguageMode } from "../types";

export const DEFAULT_ANALYSIS_WINDOW: AnalysisWindow = "365d";

export const ANALYSIS_WINDOWS: Array<{
  value: AnalysisWindow;
  hours: number;
  days: number;
  label: Record<LanguageMode, string>;
  description: Record<LanguageMode, string>;
}> = [
  {
    value: "1h",
    hours: 1,
    days: 1,
    label: { es: "Última hora", en: "Last hour" },
    description: { es: "Para alertas inmediatas y crisis activa.", en: "For immediate alerts and active crisis review." }
  },
  {
    value: "24h",
    hours: 24,
    days: 1,
    label: { es: "Último día", en: "Last day" },
    description: { es: "Lectura diaria de noticias, menciones y registros.", en: "Daily view of news, mentions and collected records." }
  },
  {
    value: "7d",
    hours: 168,
    days: 7,
    label: { es: "Última semana", en: "Last week" },
    description: { es: "Rango operativo para tendencias recientes.", en: "Operational range for recent trends." }
  },
  {
    value: "30d",
    hours: 720,
    days: 30,
    label: { es: "Último mes", en: "Last month" },
    description: { es: "Lectura mensual para seguimiento operativo.", en: "Monthly range for operational follow-up." }
  },
  {
    value: "180d",
    hours: 4320,
    days: 180,
    label: { es: "Último semestre", en: "Last semester" },
    description: { es: "Lectura estratégica de campañas y patrones.", en: "Strategic view of campaigns and patterns." }
  },
  {
    value: "365d",
    hours: 8760,
    days: 365,
    label: { es: "Último año", en: "Last year" },
    description: { es: "Base estratégica recomendada para PESTEL, Porter y planeación.", en: "Recommended strategic base for PESTEL, Porter and planning." }
  }
];

export function analysisWindowConfig(value: AnalysisWindow) {
  return ANALYSIS_WINDOWS.find((item) => item.value === value) ?? ANALYSIS_WINDOWS.find((item) => item.value === DEFAULT_ANALYSIS_WINDOW)!;
}

export function analysisWindowFromRequest(request?: { analysis_window?: AnalysisWindow; lookback_hours?: number; lookback_days?: number }): AnalysisWindow {
  if (request?.analysis_window && ANALYSIS_WINDOWS.some((item) => item.value === request.analysis_window)) {
    return request.analysis_window;
  }
  const hours = request?.lookback_hours ?? (request?.lookback_days ? request.lookback_days * 24 : undefined);
  const exact = ANALYSIS_WINDOWS.find((item) => item.hours === hours || item.days === request?.lookback_days);
  return exact?.value ?? DEFAULT_ANALYSIS_WINDOW;
}

export function analysisWindowLabel(
  request: { analysis_window?: AnalysisWindow; lookback_hours?: number; lookback_days?: number } | undefined,
  language: LanguageMode
): string {
  const config = analysisWindowConfig(analysisWindowFromRequest(request));
  return `${config.label[language]} (${config.hours}h)`;
}
