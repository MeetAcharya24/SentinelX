"use client";

import { useSearchParams } from "next/navigation";
import { useState } from "react";
import { AlertDetail } from "@/components/alerts/alert-detail";
import { AlertList } from "@/components/alerts/alert-list";
import { LogUpload } from "@/components/alerts/log-upload";
import { Button } from "@/components/ui/button";
import { Select, TextInput } from "@/components/ui/field";
import { Plate } from "@/components/ui/plate";
import { EmptyNotice, QueryView } from "@/components/ui/query-view";
import {
  type Alert,
  type AlertCategory,
  type AlertStatus,
  CATEGORIES,
  SEVERITIES,
  type Severity,
  STATUSES,
} from "@/lib/api/alerts";
import { useAlerts } from "@/lib/api/use-alerts";
import { CATEGORY_LABELS, STATUS_LABELS } from "@/lib/format";

const PAGE_SIZE = 10;

function pick<T extends string>(value: string | null, allowed: readonly T[]): T | "" {
  return allowed.find((item) => item === value) ?? "";
}

export function AlertsView() {
  const params = useSearchParams();
  const [severity, setSeverity] = useState<Severity | "">(pick(params.get("severity"), SEVERITIES));
  const [status, setStatus] = useState<AlertStatus | "">(pick(params.get("status"), STATUSES));
  const [category, setCategory] = useState<AlertCategory | "">("");
  const [source, setSource] = useState("");
  const [offset, setOffset] = useState(0);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [updated, setUpdated] = useState<Record<number, Alert>>({});

  const { state, retry } = useAlerts({
    severity: severity ? [severity] : undefined,
    status: status ? [status] : undefined,
    category: category ? [category] : undefined,
    source: source.trim() || undefined,
    sort: "newest",
    limit: PAGE_SIZE,
    offset,
  });

  const filtered = Boolean(severity || status || category || source.trim());
  const reset = <T,>(set: (value: T) => void) => (value: T) => {
    set(value);
    setOffset(0);
  };

  return (
    <div className="space-y-5">
      <header className="space-y-1">
        <h1 className="text-2xl font-semibold">Threat Alerts</h1>
        <p className="text-sm text-muted-foreground">
          Triage what the detectors flagged, with the evidence behind each alert.
        </p>
      </header>

      <Plate title="Analyse a log file">
        <LogUpload onAnalyzed={() => { setOffset(0); retry(); }} />
      </Plate>

      <div className="flex flex-wrap items-center gap-3">
        <Select label="Severity" value={severity} onChange={(e) => reset(setSeverity)(e.target.value as Severity | "")}>
          <option value="">All</option>
          {SEVERITIES.map((item) => <option key={item} value={item}>{item[0].toUpperCase() + item.slice(1)}</option>)}
        </Select>
        <Select label="Status" value={status} onChange={(e) => reset(setStatus)(e.target.value as AlertStatus | "")}>
          <option value="">All</option>
          {STATUSES.map((item) => <option key={item} value={item}>{STATUS_LABELS[item]}</option>)}
        </Select>
        <Select label="Type" value={category} onChange={(e) => reset(setCategory)(e.target.value as AlertCategory | "")}>
          <option value="">All</option>
          {CATEGORIES.map((item) => <option key={item} value={item}>{CATEGORY_LABELS[item]}</option>)}
        </Select>
        <div className="min-w-48 flex-1 sm:max-w-sm">
          <TextInput
            label="Source (exact match)"
            placeholder="Source, exact match, e.g. 203.0.113.45"
            value={source}
            onChange={(e) => reset(setSource)(e.target.value)}
          />
        </div>
      </div>

      <QueryView state={state} retry={retry} rows={6}>
        {(page) => {
          const alerts = page.alerts.map((alert) => updated[alert.id] ?? alert);
          if (alerts.length === 0) {
            return (
              <Plate>
                <EmptyNotice title={filtered ? "No alerts match these filters" : "No alerts yet"}>
                  {filtered
                    ? "Clear a filter to see more."
                    : "Analyse a log file above to generate evidence-backed alerts."}
                </EmptyNotice>
              </Plate>
            );
          }
          const selected = alerts.find((alert) => alert.id === selectedId) ?? alerts[0];
          const from = page.offset + 1;
          const to = page.offset + alerts.length;
          return (
            <div className="grid gap-4 lg:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)]">
              <Plate className="p-0 pt-2">
                <AlertList alerts={alerts} selectedId={selected.id} onSelect={(alert) => setSelectedId(alert.id)} />
                <div className="flex flex-wrap items-center justify-between gap-3 border-t border-border px-3 py-3 text-sm">
                  <p className="text-muted-foreground">
                    Showing {from}–{to} of {page.total} alerts
                  </p>
                  <div className="flex gap-2">
                    <Button variant="outline" size="sm" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}>
                      Previous
                    </Button>
                    <Button variant="outline" size="sm" disabled={to >= page.total} onClick={() => setOffset(offset + PAGE_SIZE)}>
                      Next
                    </Button>
                  </div>
                </div>
              </Plate>
              <Plate className="h-fit lg:sticky lg:top-4">
                <AlertDetail
                  key={selected.id}
                  alert={selected}
                  onUpdated={(alert) => setUpdated((current) => ({ ...current, [alert.id]: alert }))}
                />
              </Plate>
            </div>
          );
        }}
      </QueryView>
    </div>
  );
}
