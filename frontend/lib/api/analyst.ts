import { apiGet, apiPost } from "@/lib/api/client";

export type Finding = { statement: string; cites: string[] };
export type SuggestedCheck = { text: string; cites: string[] };

export type AnalystReport = {
  summary: Finding;
  findings: Finding[];
  limits: string[];
  suggested_checks: SuggestedCheck[];
  mode: "llm" | "deterministic";
  provider: string;
  model: string | null;
  generated_at: string;
  evidence_hash: string;
  /** Why the built-in explanation is shown although a hosted analyst is configured. */
  fallback_reason: string | null;
  advisory: string;
  cached: boolean;
};

export function getAnalysis(alertId: number, signal?: AbortSignal): Promise<AnalystReport> {
  return apiGet<AnalystReport>(`/api/v1/alerts/${alertId}/analysis`, signal);
}

export function refreshAnalysis(alertId: number): Promise<AnalystReport> {
  return apiPost<AnalystReport>(`/api/v1/alerts/${alertId}/analysis/refresh`);
}
