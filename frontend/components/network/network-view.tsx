"use client";

import Link from "next/link";
import { Bar, BarChart, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Plate } from "@/components/ui/plate";
import { EmptyNotice, ErrorNotice, QueryView } from "@/components/ui/query-view";
import Reveal, { staggerDelay } from "@/components/ui/reveal";
import { SEVERITY_COLOR, SeverityTag } from "@/components/ui/severity-tag";
import type { Alert } from "@/lib/api/alerts";
import { ApiError } from "@/lib/api/client";
import { getModelSummary, type ModelSummary } from "@/lib/api/network";
import { useApiQuery } from "@/lib/api/use-api-query";
import { useAlerts } from "@/lib/api/use-alerts";
import { formatDateTime } from "@/lib/format";
import { topFactors } from "@/lib/network";

const percent = (value: number) => `${(value * 100).toFixed(1)}%`;

function ModelPerformance({ summary }: { summary: ModelSummary }) {
  const { model } = summary;
  const m = model.test_metrics;
  const rows: [string, string][] = [
    ["Model", model.name],
    ["F1", m.f1.toFixed(3)],
    ["Precision", m.precision.toFixed(3)],
    ["Recall", m.recall.toFixed(3)],
    ["False positive rate", percent(m.false_positive_rate)],
    ["Trained", formatDateTime(model.trained_at)],
    ["Flag threshold", summary.threshold.toFixed(2)],
  ];
  return (
    <>
      <dl className="grid grid-cols-[auto_1fr] gap-x-6 gap-y-2 text-sm">
        {rows.map(([label, value]) => (
          <div key={label} className="contents">
            <dt className="text-muted-foreground">{label}</dt>
            <dd className="text-right font-mono text-[0.8125rem]">{value}</dd>
          </div>
        ))}
      </dl>
      <p className="mt-3 text-xs text-muted-foreground">
        Measured on {m.test_rows.toLocaleString("en")} held-out flows ({percent(m.test_attack_share)} attacks), untuned. These figures
        describe the dataset, not your network.
      </p>
    </>
  );
}

function ModelPanel() {
  const { state, retry } = useApiQuery(getModelSummary);
  return (
    <Plate title="Model performance" id="model">
      {state.status === "error" && state.error instanceof ApiError && state.error.code === "model_unavailable" ? (
        <ErrorNotice message={state.error.message} />
      ) : (
        <QueryView state={state} retry={retry} rows={5}>
          {(summary) => <ModelPerformance summary={summary} />}
        </QueryView>
      )}
    </Plate>
  );
}

function ScoreChart({ alerts }: { alerts: Alert[] }) {
  const data = [...alerts].reverse().map((alert) => ({
    id: alert.id,
    confidence: alert.confidence,
    severity: alert.severity,
    at: formatDateTime(alert.created_at),
  }));
  return (
    <div role="img" aria-label={`Confidence of the ${alerts.length} most recent network alerts`} className="h-48 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} margin={{ top: 4, right: 8, bottom: 0, left: -18 }}>
          <XAxis dataKey="id" hide />
          <YAxis domain={[0, 100]} tick={{ fill: "var(--muted-foreground)", fontSize: 11 }} tickLine={false} axisLine={false} />
          <Tooltip
            cursor={{ fill: "var(--secondary)" }}
            contentStyle={{ background: "var(--popover)", border: "1px solid var(--border)", borderRadius: 6, fontSize: 12 }}
            formatter={(value) => [`${value}%`, "Confidence"]}
            labelFormatter={(_, items) => items[0]?.payload.at ?? ""}
          />
          <Bar dataKey="confidence" radius={[2, 2, 0, 0]} isAnimationActive={false}>
            {data.map((point) => (
              <Cell key={point.id} fill={SEVERITY_COLOR[point.severity]} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

export function NetworkView() {
  const { state, retry } = useAlerts({ category: ["network_anomaly"], sort: "newest", limit: 200 });

  return (
    <div className="space-y-5">
      <header className="space-y-1">
        <h1 className="text-2xl font-semibold">Network Analysis</h1>
        <p className="text-sm text-muted-foreground">
          What the two network detectors flagged, and how well the supervised model performed in testing.
        </p>
      </header>

      <QueryView state={state} retry={retry} rows={6}>
        {(page) =>
          page.alerts.length === 0 ? (
            <div className="grid gap-4 lg:grid-cols-2">
              <Plate>
                <EmptyNotice title="No network anomalies stored">
                  Network alerts come from flows scored through the API (<span className="font-mono">POST /api/v1/analyze/network</span>).
                  See the README for generating labelled demo flows.
                </EmptyNotice>
              </Plate>
              <ModelPanel />
            </div>
          ) : (
            <div className="grid gap-4 lg:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)]">
              <Reveal>
                <Plate title="Anomaly confidence by alert" id="scores">
                  <ScoreChart alerts={page.alerts} />
                  <p className="mt-2 text-xs text-muted-foreground">
                    Oldest to newest, coloured by severity. Alerts flagged only by the Isolation Forest carry a fixed confidence of 40.
                  </p>
                </Plate>
              </Reveal>
              <Reveal delay={staggerDelay(1)}>
                <ModelPanel />
              </Reveal>
              <Reveal delay={staggerDelay(2)}>
                <Plate title="Recent network anomalies" id="recent">
                  <div className="overflow-x-auto">
                    <table className="w-full min-w-[28rem] text-left text-sm">
                      <thead className="text-xs text-muted-foreground">
                        <tr>
                          <th className="pb-2 font-medium">Time</th>
                          <th className="pb-2 font-medium">Anomaly</th>
                          <th className="pb-2 text-right font-medium">Confidence</th>
                          <th className="pb-2 pl-3 font-medium">Severity</th>
                        </tr>
                      </thead>
                      <tbody>
                        {page.alerts.slice(0, 6).map((alert) => (
                          <tr key={alert.id} className="border-t border-border/60">
                            <td className="py-2 font-mono text-xs text-muted-foreground">{formatDateTime(alert.created_at)}</td>
                            <td className="py-2">
                              <Link href={`/investigations/${alert.id}`} className="hover:text-accent hover:underline">{alert.title}</Link>
                            </td>
                            <td className="py-2 text-right font-mono tabular-nums">{alert.confidence}%</td>
                            <td className="py-2 pl-3"><SeverityTag severity={alert.severity} /></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </Plate>
              </Reveal>
              <Reveal delay={staggerDelay(3)}>
                <Plate title="Most common evidence" id="factors">
                  <ul className="space-y-3">
                    {topFactors(page.alerts).map((factor) => (
                      <li key={factor.name}>
                        <div className="flex justify-between gap-3 text-sm">
                          <span className="truncate">{factor.name}</span>
                          <span className="font-mono tabular-nums text-muted-foreground">{Math.round(factor.share * 100)}%</span>
                        </div>
                        <div className="mt-1 h-1.5 rounded-full bg-secondary">
                          <div className="h-full rounded-full bg-accent" style={{ width: `${factor.share * 100}%` }} />
                        </div>
                      </li>
                    ))}
                  </ul>
                  <p className="mt-3 text-xs text-muted-foreground">
                    Share of the {page.alerts.length} network alerts that cite each item. Traffic volume and protocol charts need stored flows, which the product does not keep yet.
                  </p>
                </Plate>
              </Reveal>
            </div>
          )
        }
      </QueryView>
    </div>
  );
}
