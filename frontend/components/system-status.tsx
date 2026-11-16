"use client";

import { Button } from "@/components/ui/button";
import { API_BASE_URL } from "@/lib/api/client";
import { getHealth, type HealthStatus } from "@/lib/api/health";
import { useApiQuery } from "@/lib/api/use-api-query";

function StatusRows({ health }: { health: HealthStatus }) {
  const rows = [
    { label: "API", value: `Online · v${health.version}` },
    { label: "Environment", value: health.environment },
    {
      label: "AI analyst",
      value:
        health.analyst.mode === "llm"
          ? `Hosted model (${health.analyst.provider})`
          : "Built-in explanations (no API key configured)",
    },
    {
      label: "Threat intelligence",
      value: health.threat_intel_configured ? "Configured" : "Not configured",
    },
  ];

  return (
    <dl className="divide-y divide-border">
      {rows.map((row) => (
        <div key={row.label} className="flex items-baseline justify-between gap-6 py-3">
          <dt className="text-sm text-muted-foreground">{row.label}</dt>
          <dd className="text-right font-mono text-sm">{row.value}</dd>
        </div>
      ))}
    </dl>
  );
}

export function SystemStatus() {
  const { state, retry } = useApiQuery(getHealth);

  return (
    <section
      aria-labelledby="system-status-heading"
      aria-busy={state.status === "loading"}
      className="w-full rounded-xl border border-border bg-card p-6"
    >
      <h2 id="system-status-heading" className="text-base font-medium">
        System status
      </h2>

      {state.status === "loading" && (
        <p role="status" className="py-3 text-sm text-muted-foreground">
          Checking API…
        </p>
      )}

      {state.status === "error" && (
        <div role="alert" className="space-y-3 py-3">
          <p className="text-sm">{state.error.message}</p>
          <p className="font-mono text-xs text-muted-foreground">{API_BASE_URL}</p>
          <Button variant="outline" size="sm" onClick={retry}>
            Try again
          </Button>
        </div>
      )}

      {state.status === "success" && <StatusRows health={state.data} />}
    </section>
  );
}
