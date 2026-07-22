import type {
  AIAnalysisPackage,
  AIAnalysisRequest,
  AIOrchestrationConfig,
  AttackSurfaceResponse,
  DisinformationFrameworkResponse,
  DomainAnalysisRequest,
  EmployeeRiskRunResponse,
  LicensingOverview,
  MethodologyRegistryResponse,
  MitreGroup,
  MonitoringOverview,
  MonitoringProfile,
  MonitoringProfileRequest,
  ReportCatalogItem,
  RunRecord,
  ScenarioLibraryResponse,
  ViewKey
} from "./types";

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "";

export function apiUrl(path: string): string {
  if (!path) return API_BASE || "/";
  if (/^https?:\/\//i.test(path)) return path;
  return `${API_BASE}${path}`;
}

async function apiFetch<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json", ...options?.headers },
    ...options
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({ detail: response.statusText }));
    const detail = Array.isArray(payload.detail) ? payload.detail[0]?.msg : payload.detail;
    throw new Error(detail || `Request failed: ${response.status}`);
  }
  return response.json() as Promise<T>;
}

export function listRuns(): Promise<RunRecord[]> {
  return apiFetch<RunRecord[]>("/api/runs");
}

export function listReports(): Promise<ReportCatalogItem[]> {
  return apiFetch<ReportCatalogItem[]>("/api/reports");
}

export function deleteReport(reportPath: string): Promise<{ status: string; report: string }> {
  const encoded = reportPath.split("/").map(encodeURIComponent).join("/");
  return apiFetch<{ status: string; report: string }>(`/api/reports/${encoded}`, { method: "DELETE" });
}

export function listMitreGroups(): Promise<MitreGroup[]> {
  return apiFetch<MitreGroup[]>("/api/mitre/groups");
}

export function createAnalysis(request: DomainAnalysisRequest): Promise<RunRecord> {
  return apiFetch<RunRecord>("/api/analysis", {
    method: "POST",
    body: JSON.stringify(request)
  });
}

export function rerunAnalysis(runId: string): Promise<RunRecord> {
  return apiFetch<RunRecord>(`/api/runs/${runId}/rerun`, { method: "POST" });
}

export function generateRunReport(runId: string): Promise<RunRecord> {
  return apiFetch<RunRecord>(`/api/runs/${runId}/report`, { method: "POST" });
}

export function getMonitoringOverview(): Promise<MonitoringOverview> {
  return apiFetch<MonitoringOverview>("/api/monitoring");
}

export function createMonitoringProfile(request: MonitoringProfileRequest): Promise<MonitoringProfile> {
  return apiFetch<MonitoringProfile>("/api/monitoring/profiles", {
    method: "POST",
    body: JSON.stringify(request)
  });
}

export function updateMonitoringProfile(
  profileId: string,
  request: {
    name?: string;
    cadence?: MonitoringProfileRequest["cadence"];
    collection_duration_minutes?: number;
    enabled?: boolean;
  }
): Promise<MonitoringProfile> {
  return apiFetch<MonitoringProfile>(`/api/monitoring/profiles/${profileId}`, {
    method: "PATCH",
    body: JSON.stringify(request)
  });
}

export function createSupportTicket(request: {
  subject: string;
  description: string;
  user: string;
  run_id?: string | null;
  severity?: "low" | "medium" | "high";
}): Promise<unknown> {
  return apiFetch("/api/support/tickets", {
    method: "POST",
    body: JSON.stringify(request)
  });
}

export function updateMonitoringAlert(alertId: string, request: {
  status: "open" | "acknowledged" | "closed" | "false_positive";
  user?: string;
}): Promise<unknown> {
  return apiFetch(`/api/monitoring/alerts/${alertId}`, {
    method: "PATCH",
    body: JSON.stringify(request)
  });
}

export function updateSupportTicket(ticketId: string, request: {
  status: "open" | "in_review" | "resolved";
  user?: string;
}): Promise<unknown> {
  return apiFetch(`/api/support/tickets/${ticketId}`, {
    method: "PATCH",
    body: JSON.stringify(request)
  });
}

export function getAttackSurface(domains: string[], competitors: string[] = []): Promise<AttackSurfaceResponse> {
  const params = new URLSearchParams();
  domains.forEach((domain) => params.append("domains", domain));
  competitors.forEach((domain) => params.append("competitors", domain));
  return apiFetch<AttackSurfaceResponse>(`/api/attack-surface?${params.toString()}`);
}

export async function runEmployeeRiskAnalysis(formData: FormData): Promise<EmployeeRiskRunResponse> {
  const response = await fetch(`${API_BASE}/api/employee-risk/analyze`, {
    method: "POST",
    body: formData
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({ detail: response.statusText }));
    const detail = Array.isArray(payload.detail) ? payload.detail[0]?.msg : payload.detail;
    throw new Error(detail || `Request failed: ${response.status}`);
  }
  return response.json() as Promise<EmployeeRiskRunResponse>;
}

export function getDisinformationFramework(): Promise<DisinformationFrameworkResponse> {
  return apiFetch<DisinformationFrameworkResponse>("/api/disinformation/framework");
}

export function getScenarioLibrary(): Promise<ScenarioLibraryResponse> {
  return apiFetch<ScenarioLibraryResponse>("/api/scenarios/library");
}

export function getMethodologyRegistry(): Promise<MethodologyRegistryResponse> {
  return apiFetch<MethodologyRegistryResponse>("/api/methodologies");
}

export function getLicensingOverview(): Promise<LicensingOverview> {
  return apiFetch<LicensingOverview>("/api/licensing/overview");
}

export function getAIOrchestrationConfig(): Promise<AIOrchestrationConfig> {
  return apiFetch<AIOrchestrationConfig>("/api/ai/config");
}

export function createAIAnalysisPackage(request: AIAnalysisRequest): Promise<AIAnalysisPackage> {
  return apiFetch<AIAnalysisPackage>("/api/ai/package", {
    method: "POST",
    body: JSON.stringify(request)
  });
}

export function createLicenseCompany(request: {
  name: string;
  parent_id?: string | null;
  country?: string;
  sector?: string;
  status?: "active" | "inactive";
}): Promise<LicensingOverview> {
  return apiFetch<LicensingOverview>("/api/licensing/companies", {
    method: "POST",
    body: JSON.stringify(request)
  });
}

export function createCompanyLicense(request: {
  company_id: string;
  plan_code: string;
  status?: "active" | "trial" | "suspended" | "expired";
  seats: number;
  expires_at?: string | null;
  modules_override?: ViewKey[];
}): Promise<LicensingOverview> {
  return apiFetch<LicensingOverview>("/api/licensing/licenses", {
    method: "POST",
    body: JSON.stringify(request)
  });
}

export function updateCompanyLicense(
  licenseId: string,
  request: {
    status?: "active" | "trial" | "suspended" | "expired";
    seats?: number;
    expires_at?: string | null;
    modules_override?: ViewKey[];
  }
): Promise<LicensingOverview> {
  return apiFetch<LicensingOverview>(`/api/licensing/licenses/${licenseId}`, {
    method: "PATCH",
    body: JSON.stringify(request)
  });
}

export function createLicenseUser(request: {
  company_id: string;
  username: string;
  full_name: string;
  role: "super_admin" | "admin" | "analyst" | "executive" | "viewer";
  plan_code?: string | null;
  status?: "active" | "inactive";
  modules?: ViewKey[];
  created_by?: string;
}): Promise<LicensingOverview> {
  return apiFetch<LicensingOverview>("/api/licensing/users", {
    method: "POST",
    body: JSON.stringify(request)
  });
}

export function updateLicenseUser(
  userId: string,
  request: {
    status?: "active" | "inactive";
    role?: "super_admin" | "admin" | "analyst" | "executive" | "viewer";
    plan_code?: string | null;
    modules?: ViewKey[];
  }
): Promise<LicensingOverview> {
  return apiFetch<LicensingOverview>(`/api/licensing/users/${userId}`, {
    method: "PATCH",
    body: JSON.stringify(request)
  });
}
