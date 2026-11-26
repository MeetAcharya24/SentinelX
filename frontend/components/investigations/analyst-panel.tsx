"use client";

import { useCallback, useState } from "react";
import { Button } from "@/components/ui/button";
import { ErrorNotice, LoadingRows } from "@/components/ui/query-view";
import { type AnalystReport, getAnalysis, refreshAnalysis } from "@/lib/api/analyst";
import { toApiError } from "@/lib/api/client";
import { useApiQuery } from "@/lib/api/use-api-query";
import { formatDateTime } from "@/lib/format";

/** `evidence:failed_login_burst` becomes "evidence · failed_login_burst". */
export function citeLabel(cite: string): string {
  const [scope, ...rest] = cite.split(":");
  return `${scope} · ${rest.join(":")}`;
}

function Cites({ cites }: { cites: string[] }) {
  return (
    <ul aria-label="Cited evidence" className="mt-1.5 flex flex-wrap gap-1.5">
      {cites.map((cite) => (
        <li key={cite} className="rounded bg-secondary px-1.5 py-0.5 font-mono text-xs text-muted-foreground">
          {citeLabel(cite)}
        </li>
      ))}
    </ul>
  );
}

function sourceLine(report: AnalystReport): string {
  const who = report.mode === "llm" ? `Hosted model ${report.model}` : "Built-in explanation";
  const cached = report.cached ? ", saved from an earlier view" : "";
  return `${who} · generated ${formatDateTime(report.generated_at)}${cached}`;
}

export function ReportBody({
  report,
  onRefresh,
  refreshing,
  refreshError,
}: {
  report: AnalystReport;
  onRefresh: () => void;
  refreshing: boolean;
  refreshError: string | null;
}) {
  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="font-mono text-xs text-muted-foreground">{sourceLine(report)}</p>
        <Button variant="outline" size="sm" onClick={onRefresh} disabled={refreshing}>
          {refreshing ? "Regenerating…" : "Regenerate"}
        </Button>
      </div>
      {refreshError && (
        <p role="alert" className="text-sm">
          {refreshError}
        </p>
      )}
      {report.fallback_reason && (
        <p role="status" className="border-l-2 border-border pl-3 text-sm text-muted-foreground">
          {report.fallback_reason}
        </p>
      )}

      <section aria-labelledby="analyst-summary">
        <h3 id="analyst-summary" className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
          Summary
        </h3>
        <p className="mt-1 text-sm">{report.summary.statement}</p>
        <Cites cites={report.summary.cites} />
      </section>

      <section aria-labelledby="analyst-findings">
        <h3 id="analyst-findings" className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
          What the evidence says
        </h3>
        <ul className="mt-2 space-y-3">
          {report.findings.map((finding, index) => (
            <li key={index} className="border-l-2 border-border pl-3">
              <p className="text-sm">{finding.statement}</p>
              <Cites cites={finding.cites} />
            </li>
          ))}
        </ul>
      </section>

      <section aria-labelledby="analyst-limits">
        <h3 id="analyst-limits" className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
          What it does not show
        </h3>
        <ul className="mt-2 list-disc space-y-1 pl-5 text-sm text-muted-foreground">
          {report.limits.map((limit, index) => (
            <li key={index}>{limit}</li>
          ))}
        </ul>
      </section>

      {report.suggested_checks.length > 0 && (
        <section aria-labelledby="analyst-checks">
          <h3 id="analyst-checks" className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
            Suggested checks
          </h3>
          <ul className="mt-2 space-y-3">
            {report.suggested_checks.map((check, index) => (
              <li key={index} className="border-l-2 border-border pl-3">
                <p className="text-sm">{check.text}</p>
                <Cites cites={check.cites} />
              </li>
            ))}
          </ul>
        </section>
      )}

      <p className="text-xs text-muted-foreground">{report.advisory}</p>
    </div>
  );
}

export function AnalystPanel({ alertId }: { alertId: number }) {
  const fetcher = useCallback((signal: AbortSignal) => getAnalysis(alertId, signal), [alertId]);
  const { state, retry } = useApiQuery(fetcher);
  const [fresh, setFresh] = useState<AnalystReport | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [refreshError, setRefreshError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setRefreshing(true);
    setRefreshError(null);
    try {
      setFresh(await refreshAnalysis(alertId));
    } catch (error) {
      setRefreshError(toApiError(error).message);
    } finally {
      setRefreshing(false);
    }
  }, [alertId]);

  if (state.status === "loading") return <LoadingRows rows={5} />;
  if (state.status === "error") return <ErrorNotice message={state.error.message} onRetry={retry} />;
  return (
    <ReportBody
      report={fresh ?? state.data}
      onRefresh={refresh}
      refreshing={refreshing}
      refreshError={refreshError}
    />
  );
}
