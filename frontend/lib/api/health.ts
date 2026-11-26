import { apiGet } from "@/lib/api/client";

export type HealthStatus = {
  status: "ok";
  version: string;
  environment: string;
  analyst: { mode: "llm" | "deterministic"; provider: string | null };
  threatfox_configured: boolean;
};

export function getHealth(signal?: AbortSignal): Promise<HealthStatus> {
  return apiGet<HealthStatus>("/health", signal);
}
