"use client";

import Link from "next/link";
import Reveal, { staggerDelay } from "@/components/ui/reveal";
import { Plate } from "@/components/ui/plate";
import { EmptyNotice, QueryView } from "@/components/ui/query-view";
import { SeverityTag } from "@/components/ui/severity-tag";
import { useAlerts } from "@/lib/api/use-alerts";
import { alertRef, timeAgo } from "@/lib/format";

/** Investigations are alerts an analyst has acknowledged and is working on. */
export function InvestigationsIndex() {
  const { state, retry } = useAlerts({ status: ["acknowledged"], sort: "severity", limit: 50 });
  return (
    <div className="space-y-5">
      <header className="space-y-1">
        <h1 className="text-2xl font-semibold">Investigations</h1>
        <p className="text-sm text-muted-foreground">Alerts you have acknowledged and are working through.</p>
      </header>
      <QueryView state={state} retry={retry} rows={4}>
        {(page) =>
          page.alerts.length === 0 ? (
            <Plate>
              <EmptyNotice title="Nothing under investigation">
                Acknowledge an alert in <Link className="text-accent underline underline-offset-2" href="/alerts">Threat Alerts</Link> to start one.
              </EmptyNotice>
            </Plate>
          ) : (
            <ul className="grid gap-3 md:grid-cols-2">
              {page.alerts.map((alert, index) => (
                <li key={alert.id}>
                  <Reveal delay={staggerDelay(index)}>
                    <Link href={`/investigations/${alert.id}`} className="block">
                      <Plate hover>
                        <div className="flex items-center justify-between gap-3">
                          <span className="font-mono text-xs text-muted-foreground">{alertRef(alert.id)}</span>
                          <SeverityTag severity={alert.severity} />
                        </div>
                        <p className="mt-2 text-sm font-medium">{alert.title}</p>
                        <p className="mt-1 text-xs text-muted-foreground">
                          {alert.notes.length} notes · detected {timeAgo(alert.created_at)}
                        </p>
                      </Plate>
                    </Link>
                  </Reveal>
                </li>
              ))}
            </ul>
          )
        }
      </QueryView>
    </div>
  );
}
