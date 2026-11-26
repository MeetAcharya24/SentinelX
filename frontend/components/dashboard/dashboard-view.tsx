"use client";

import Link from "next/link";
import { useCallback, useMemo, useState } from "react";
import { ActivityChart } from "@/components/dashboard/activity-chart";
import { SystemHealth } from "@/components/dashboard/system-health";
import GlowButton from "@/components/ui/glow-button";
import { Select } from "@/components/ui/field";
import { Plate } from "@/components/ui/plate";
import { EmptyNotice, QueryView } from "@/components/ui/query-view";
import Reveal, { staggerDelay } from "@/components/ui/reveal";
import { SeverityTag } from "@/components/ui/severity-tag";
import { useApiQuery } from "@/lib/api/use-api-query";
import {
  bucketAlerts,
  type DashboardData,
  loadDashboard,
  RANGES,
  RECENT_LIMIT,
  type RangeId,
  topSources,
} from "@/lib/dashboard";
import { timeAgo } from "@/lib/format";

type Stat = { label: string; value: number; note: string; href: string };

function Stats({ data }: { data: DashboardData }) {
  const stats: Stat[] = [
    { label: "Open alerts", value: data.open, note: "Not yet acknowledged or closed", href: "/alerts?status=open" },
    { label: "Critical and high", value: data.urgent, note: "Open, highest severity", href: "/alerts?status=open&severity=critical" },
    { label: "Affected sources", value: data.affected, note: "Distinct assets or sources, open alerts", href: "/alerts?status=open" },
    { label: "False positives", value: data.falsePositives, note: "Marked by an analyst", href: "/alerts?status=false_positive" },
  ];
  return (
    <ul className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
      {stats.map((stat, index) => (
        <li key={stat.label}>
          <Reveal delay={staggerDelay(index)}>
            <Link href={stat.href} className="block">
              <Plate hover>
                <p className="text-sm text-muted-foreground">{stat.label}</p>
                <p className="mt-1 font-mono text-3xl font-semibold tabular-nums">{stat.value.toLocaleString("en")}</p>
                <p className="mt-1 text-xs text-muted-foreground">{stat.note}</p>
              </Plate>
            </Link>
          </Reveal>
        </li>
      ))}
    </ul>
  );
}

function Queue({ data }: { data: DashboardData }) {
  return (
    <Plate title="Alert queue" id="queue" action={<Link href="/alerts?status=open" className="text-sm text-accent hover:underline">View all</Link>}>
      {data.queue.length === 0 ? (
        <EmptyNotice title="No open alerts in this period" />
      ) : (
        <ul>
          {data.queue.map((alert, index) => (
            <li key={alert.id} className="border-b border-border/60 last:border-b-0">
              <Reveal delay={staggerDelay(index)} duration={400}>
                <Link href={`/investigations/${alert.id}`} className="grid grid-cols-[6.25rem_minmax(0,1fr)_auto] items-center gap-3 py-2.5 hover:bg-secondary/50">
                  <span><SeverityTag severity={alert.severity} /></span>
                  <span className="truncate text-sm">{alert.title}</span>
                  <span className="text-xs text-muted-foreground">{timeAgo(alert.created_at)}</span>
                </Link>
              </Reveal>
            </li>
          ))}
        </ul>
      )}
    </Plate>
  );
}

function Sources({ data }: { data: DashboardData }) {
  const sources = useMemo(() => topSources(data.recent), [data.recent]);
  const max = sources[0]?.count ?? 1;
  return (
    <Plate title="Top sources" id="sources">
      {sources.length === 0 ? (
        <EmptyNotice title="No sources yet" />
      ) : (
        <ul className="space-y-3">
          {sources.map((item) => (
            <li key={item.source}>
              <div className="flex justify-between gap-3 text-sm">
                <span className="truncate font-mono text-[0.8125rem]">{item.source}</span>
                <span className="font-mono tabular-nums text-muted-foreground">{item.count}</span>
              </div>
              <div className="mt-1 h-1.5 rounded-full bg-secondary">
                <div className="h-full rounded-full bg-accent" style={{ width: `${(item.count / max) * 100}%` }} />
              </div>
            </li>
          ))}
        </ul>
      )}
      <p className="mt-4 text-xs text-muted-foreground">
        A geographic threat map needs address-to-location data, which is not part of the product yet.
      </p>
    </Plate>
  );
}

export function DashboardView() {
  const [range, setRange] = useState<RangeId>("24h");
  const fetcher = useCallback((signal: AbortSignal) => loadDashboard(range, signal), [range]);
  const { state, retry } = useApiQuery(fetcher);

  return (
    <div className="space-y-5">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div className="space-y-1">
          <h1 className="text-2xl font-semibold">SOC Dashboard</h1>
          <p className="text-sm text-muted-foreground">Overview of alerts from the analysis you have run.</p>
        </div>
        <Select label="Period" value={range} onChange={(e) => setRange(e.target.value as RangeId)}>
          {Object.entries(RANGES).map(([id, item]) => (
            <option key={id} value={id}>{item.label}</option>
          ))}
        </Select>
      </header>

      <QueryView state={state} retry={retry} rows={6}>
        {(data) =>
          data.recentTotal === 0 ? (
            <Plate>
              <EmptyNotice title="No alerts in this period">
                <p>Analyse a security log to generate evidence-backed alerts.</p>
                <div className="mt-4 flex justify-center">
                  <GlowButton as={Link} href="/alerts" className="font-medium">Analyse a log file</GlowButton>
                </div>
              </EmptyNotice>
            </Plate>
          ) : (
            <div className="space-y-4">
              {data.hasDemo && (
                <p role="note" className="rounded-md border border-border bg-secondary/60 px-3 py-2 text-sm">
                  Some of these alerts come from labelled demo input, not real activity.
                </p>
              )}
              <Stats data={data} />
              <div className="grid gap-4 lg:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)]">
                <Plate title="Alert activity" id="activity">
                  <ActivityChart buckets={bucketAlerts(data.recent, range, data.loadedAt)} />
                  {data.recentTotal > RECENT_LIMIT && (
                    <p className="mt-2 text-xs text-muted-foreground">
                      Chart and sources use the {RECENT_LIMIT} most recent of {data.recentTotal} alerts.
                    </p>
                  )}
                </Plate>
                <Sources data={data} />
              </div>
              <div className="grid gap-4 lg:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)]">
                <Queue data={data} />
                <SystemHealth />
              </div>
            </div>
          )
        }
      </QueryView>
    </div>
  );
}
