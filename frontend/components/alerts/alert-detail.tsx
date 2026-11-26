"use client";

import Link from "next/link";
import { useState } from "react";
import { EvidenceList, Facts, Timeline } from "@/components/alerts/alert-parts";
import { StatusActions } from "@/components/alerts/status-actions";
import GlowButton from "@/components/ui/glow-button";
import { SeverityTag } from "@/components/ui/severity-tag";
import { StatusTag } from "@/components/ui/status-tag";
import { TabPanel, Tabs } from "@/components/ui/tabs";
import type { Alert } from "@/lib/api/alerts";
import { alertRef } from "@/lib/format";

const TABS = [
  { id: "overview", label: "Overview" },
  { id: "evidence", label: "Evidence" },
  { id: "timeline", label: "Timeline" },
] as const;
type TabId = (typeof TABS)[number]["id"];

export function AlertDetail({ alert, onUpdated }: { alert: Alert; onUpdated: (alert: Alert) => void }) {
  const [tab, setTab] = useState<TabId>("overview");
  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-lg font-semibold leading-snug">{alert.title}</h2>
        <div className="mt-2 flex flex-wrap items-center gap-3">
          <span className="font-mono text-xs text-muted-foreground">{alertRef(alert.id)}</span>
          <SeverityTag severity={alert.severity} />
          <StatusTag status={alert.status} />
          {alert.demo && (
            <span className="rounded border border-border px-1.5 py-0.5 text-xs text-muted-foreground">
              Demo data
            </span>
          )}
        </div>
      </div>

      <Tabs tabs={[...TABS]} active={tab} onChange={setTab} label="Alert details" idPrefix="alert" />
      <TabPanel idPrefix="alert" id={tab}>
        {tab === "overview" && <Facts alert={alert} />}
        {tab === "evidence" && <EvidenceList evidence={alert.evidence} />}
        {tab === "timeline" && <Timeline alert={alert} />}
      </TabPanel>

      <div className="flex flex-wrap items-center gap-3 border-t border-border pt-4">
        <GlowButton as={Link} href={`/investigations/${alert.id}`} className="font-medium">
          Investigate
        </GlowButton>
      </div>
      <StatusActions alert={alert} onUpdated={onUpdated} />
    </div>
  );
}
