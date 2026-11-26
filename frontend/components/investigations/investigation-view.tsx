"use client";

import { useCallback, useState } from "react";
import { EvidenceList, Facts, Timeline } from "@/components/alerts/alert-parts";
import { StatusActions } from "@/components/alerts/status-actions";
import { AnalystPanel } from "@/components/investigations/analyst-panel";
import { NotesPanel } from "@/components/investigations/notes-panel";
import { SuggestedChecks } from "@/components/investigations/suggested-checks";
import { Plate } from "@/components/ui/plate";
import { EmptyNotice, ErrorNotice, LoadingRows } from "@/components/ui/query-view";
import Reveal, { staggerDelay } from "@/components/ui/reveal";
import { SeverityTag } from "@/components/ui/severity-tag";
import { StatusTag } from "@/components/ui/status-tag";
import { TabPanel, Tabs } from "@/components/ui/tabs";
import { type Alert, getAlert } from "@/lib/api/alerts";
import { useApiQuery } from "@/lib/api/use-api-query";
import { alertRef, CATEGORY_LABELS } from "@/lib/format";

const TABS = [
  { id: "overview", label: "Overview" },
  { id: "analyst", label: "AI Analyst" },
  { id: "evidence", label: "Evidence" },
  { id: "timeline", label: "Timeline" },
  { id: "assets", label: "Affected Assets" },
  { id: "notes", label: "Notes" },
] as const;
type TabId = (typeof TABS)[number]["id"];

function Assets({ alert }: { alert: Alert }) {
  const assets = [
    alert.asset ? { name: alert.asset, role: "Asset" } : null,
    { name: alert.source, role: "Source" },
  ].filter((item): item is { name: string; role: string } => item !== null);
  return (
    <ul className="space-y-2">
      {assets.map((item) => (
        <li key={`${item.role}-${item.name}`} className="flex items-center justify-between gap-3 text-sm">
          <span className="min-w-0 truncate font-mono">{item.name}</span>
          <span className="text-xs text-muted-foreground">{item.role}</span>
        </li>
      ))}
    </ul>
  );
}

function Overview({ alert }: { alert: Alert }) {
  const cards = [
    <Plate key="timeline" title="Incident timeline"><Timeline alert={alert} /></Plate>,
    <Plate key="evidence" title={`Evidence (${alert.evidence.length})`}><EvidenceList evidence={alert.evidence} /></Plate>,
    <Plate key="assets" title="Affected assets"><Assets alert={alert} /></Plate>,
  ];
  return (
    <div className="space-y-4">
      <div className="grid gap-4 lg:grid-cols-3">
        {cards.map((card, index) => (
          <Reveal key={card.key} delay={staggerDelay(index)}>{card}</Reveal>
        ))}
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        <Reveal delay={staggerDelay(3)}>
          <Plate title="Why it was flagged"><Facts alert={alert} /></Plate>
        </Reveal>
        <Reveal delay={staggerDelay(4)}>
          <Plate title="Suggested checks"><SuggestedChecks category={alert.category} /></Plate>
        </Reveal>
      </div>
    </div>
  );
}

export function InvestigationView({ id }: { id: number }) {
  const fetcher = useCallback((signal: AbortSignal) => getAlert(id, signal), [id]);
  const { state, retry } = useApiQuery(fetcher);
  const [override, setOverride] = useState<Alert | null>(null);
  const [tab, setTab] = useState<TabId>("overview");

  if (!Number.isInteger(id) || id < 1) {
    return <Plate><EmptyNotice title="That is not a valid alert id" /></Plate>;
  }
  if (state.status === "loading") return <LoadingRows rows={6} />;
  if (state.status === "error") {
    return state.error.code === "alert_not_found" ? (
      <Plate><EmptyNotice title="Alert not found">It may have been removed with a reset database.</EmptyNotice></Plate>
    ) : (
      <ErrorNotice message={state.error.message} onRetry={retry} />
    );
  }

  const alert = override && override.id === id ? override : state.data;
  return (
    <div className="space-y-4">
      <header className="flex flex-wrap items-start justify-between gap-4">
        <div className="space-y-1">
          <div className="flex flex-wrap items-center gap-3">
            <h1 className="text-2xl font-semibold">Investigation: {alertRef(alert.id)}</h1>
            <SeverityTag severity={alert.severity} />
            <StatusTag status={alert.status} />
          </div>
          <p className="text-sm text-muted-foreground">
            {alert.title} · {CATEGORY_LABELS[alert.category]}
            {alert.demo && " · Demo data"}
          </p>
        </div>
        <StatusActions alert={alert} onUpdated={setOverride} />
      </header>

      <Tabs tabs={[...TABS]} active={tab} onChange={setTab} label="Investigation sections" idPrefix="inv" />
      <TabPanel idPrefix="inv" id={tab}>
        {tab === "overview" && <Overview alert={alert} />}
        {tab === "analyst" && (
          <Plate title="AI Security Analyst"><AnalystPanel alertId={alert.id} /></Plate>
        )}
        {tab === "evidence" && <Plate title="Evidence"><EvidenceList evidence={alert.evidence} /></Plate>}
        {tab === "timeline" && <Plate title="Incident timeline"><Timeline alert={alert} /></Plate>}
        {tab === "assets" && <Plate title="Affected assets"><Assets alert={alert} /></Plate>}
        {tab === "notes" && <Plate title="Notes"><NotesPanel alert={alert} onUpdated={setOverride} /></Plate>}
      </TabPanel>
    </div>
  );
}
