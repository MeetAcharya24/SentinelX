import { apiGet, apiPatch, apiPostRaw } from "@/lib/api/client";

export const SEVERITIES = ["critical", "high", "medium", "low"] as const;
export type Severity = (typeof SEVERITIES)[number];

export const STATUSES = ["open", "acknowledged", "false_positive", "resolved"] as const;
export type AlertStatus = (typeof STATUSES)[number];

export const CATEGORIES = [
  "network_anomaly",
  "brute_force",
  "known_bad_source",
  "suspicious_activity",
  "phishing",
] as const;
export type AlertCategory = (typeof CATEGORIES)[number];

export type Evidence = {
  kind:
    | "model_score"
    | "rule_match"
    | "phishing_signal"
    | "model_term"
    | "caveat"
    | "threat_intel_match";
  name: string;
  description: string;
  value: number | null;
  examples: string[];
};

export type AlertNote = { id: number; created_at: string; text: string };

export type Alert = {
  id: number;
  created_at: string;
  occurred_at: string | null;
  severity: Severity;
  confidence: number;
  category: AlertCategory;
  source: string;
  asset: string | null;
  title: string;
  evidence: Evidence[];
  status: AlertStatus;
  demo: boolean;
  notes: AlertNote[];
};

export type AlertPage = { total: number; limit: number; offset: number; alerts: Alert[] };

export type AlertQuery = {
  severity?: Severity[];
  status?: AlertStatus[];
  category?: AlertCategory[];
  source?: string;
  created_from?: string;
  sort?: "newest" | "severity";
  limit?: number;
  offset?: number;
};

export function alertQueryString(query: AlertQuery): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === "") continue;
    if (Array.isArray(value)) value.forEach((item) => params.append(key, item));
    else params.set(key, String(value));
  }
  const text = params.toString();
  return text ? `?${text}` : "";
}

export function getAlerts(query: AlertQuery, signal?: AbortSignal): Promise<AlertPage> {
  return apiGet<AlertPage>(`/api/v1/alerts${alertQueryString(query)}`, signal);
}

export function getAlert(id: number, signal?: AbortSignal): Promise<Alert> {
  return apiGet<Alert>(`/api/v1/alerts/${id}`, signal);
}

export function updateAlert(
  id: number,
  change: { status?: AlertStatus; note?: string },
): Promise<Alert> {
  return apiPatch<Alert>(`/api/v1/alerts/${id}`, change);
}

export function analyzeLogFile(file: File, demo: boolean): Promise<{ analyzed: number; alerts: Alert[]; duplicates: number }> {
  const isJson = file.name.toLowerCase().endsWith(".json");
  return apiPostRaw(
    `/api/v1/analyze/logs?demo=${demo}`,
    file,
    isJson ? "application/json" : "text/csv",
  );
}
