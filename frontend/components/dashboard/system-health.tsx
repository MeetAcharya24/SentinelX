"use client";

import { Plate } from "@/components/ui/plate";
import { ApiError } from "@/lib/api/client";
import { getHealth } from "@/lib/api/health";
import { getModelSummary } from "@/lib/api/network";
import { useApiQuery } from "@/lib/api/use-api-query";
import { cn } from "@/lib/utils";

type Row = { label: string; value: string; ok: boolean | null };

function Rows({ rows }: { rows: Row[] }) {
  return (
    <ul className="space-y-2.5">
      {rows.map((row) => (
        <li key={row.label} className="flex items-center justify-between gap-3 text-sm">
          <span>{row.label}</span>
          <span className="flex items-center gap-2 text-muted-foreground">
            <span
              aria-hidden
              className={cn("size-2 rounded-full", row.ok === null ? "bg-muted-foreground" : row.ok ? "bg-sev-low" : "bg-sev-high")}
            />
            {row.value}
          </span>
        </li>
      ))}
    </ul>
  );
}

/** Reads /health and the network model endpoint; each row states what was actually checked. */
export function SystemHealth() {
  const health = useApiQuery(getHealth);
  const model = useApiQuery(getModelSummary);

  const rows: Row[] = [];
  if (health.state.status === "success") {
    const h = health.state.data;
    rows.push(
      { label: "API", value: `Online, v${h.version}`, ok: true },
      { label: "AI analyst", value: h.analyst.mode === "llm" ? `Hosted (${h.analyst.provider})` : "Built-in explanations", ok: true },
      { label: "Threat intelligence", value: h.threat_intel_configured ? "Configured" : "Not configured", ok: h.threat_intel_configured },
    );
  }
  if (model.state.status === "success") {
    rows.push({ label: "Network detector", value: `${model.state.data.model.name}, trained`, ok: true });
  } else if (model.state.status === "error") {
    const missing = model.state.error instanceof ApiError && model.state.error.code === "model_unavailable";
    rows.push({ label: "Network detector", value: missing ? "Not trained" : "Could not check", ok: false });
  }

  return (
    <Plate title="System health" id="health">
      {health.state.status === "error" ? (
        <p role="alert" className="text-sm">{health.state.error.message}</p>
      ) : rows.length === 0 ? (
        <p role="status" className="text-sm text-muted-foreground">Checking…</p>
      ) : (
        <Rows rows={rows} />
      )}
    </Plate>
  );
}
