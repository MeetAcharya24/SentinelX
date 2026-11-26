"use client";

import { getHealth } from "@/lib/api/health";
import { useApiQuery } from "@/lib/api/use-api-query";
import { cn } from "@/lib/utils";

/** Reports the API's real state from /health. The dot is steady: a checked fact, not a pulse. */
export function Topbar() {
  const { state } = useApiQuery(getHealth);
  const label =
    state.status === "loading"
      ? "Checking API"
      : state.status === "error"
        ? "API unreachable"
        : "API online";
  const tone =
    state.status === "success"
      ? "bg-sev-low"
      : state.status === "error"
        ? "bg-sev-critical"
        : "bg-muted-foreground";

  return (
    <header className="flex items-center justify-between gap-3 border-b border-sidebar-border bg-background/60 px-4 py-2.5 backdrop-blur md:px-6">
      <div className="plate flex items-center gap-3 px-3 py-1.5 text-sm">
        <span className="font-medium">SOC Operations</span>
        <span className="flex items-center gap-1.5 text-muted-foreground" role="status">
          <span aria-hidden className={cn("size-2 rounded-full", tone)} />
          {label}
        </span>
      </div>
      {state.status === "success" && (
        <p className="hidden font-mono text-xs text-muted-foreground sm:block">
          v{state.data.version} ·{" "}
          {state.data.analyst.mode === "llm" ? "hosted analyst" : "built-in analyst"}
        </p>
      )}
    </header>
  );
}
