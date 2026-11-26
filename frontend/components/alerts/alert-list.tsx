"use client";

import Reveal, { staggerDelay } from "@/components/ui/reveal";
import { SeverityTag } from "@/components/ui/severity-tag";
import { StatusTag } from "@/components/ui/status-tag";
import type { Alert } from "@/lib/api/alerts";
import { timeAgo } from "@/lib/format";
import { cn } from "@/lib/utils";

const COLUMNS = "grid-cols-[6.25rem_minmax(0,1fr)] md:grid-cols-[6.25rem_minmax(0,2fr)_minmax(0,1.2fr)_minmax(0,1fr)_5.5rem]";

/** Alert rows as a list of buttons; each row cascades in with a 60 ms stagger. */
export function AlertList({
  alerts,
  selectedId,
  onSelect,
}: {
  alerts: Alert[];
  selectedId: number | null;
  onSelect: (alert: Alert) => void;
}) {
  return (
    <div>
      <div aria-hidden className={cn("hidden gap-3 border-b border-border px-3 pb-2 text-xs font-medium text-muted-foreground md:grid", COLUMNS)}>
        <span>Severity</span>
        <span>Alert</span>
        <span>Source</span>
        <span>Asset</span>
        <span className="text-right">Detected</span>
      </div>
      <ul>
        {alerts.map((alert, index) => (
          <li key={alert.id} className="border-b border-border/60 last:border-b-0">
            <Reveal delay={staggerDelay(Math.min(index, 10))} duration={400}>
              <button
                type="button"
                onClick={() => onSelect(alert)}
                aria-pressed={alert.id === selectedId}
                className={cn(
                  "grid w-full items-center gap-x-3 gap-y-1 px-3 py-2.5 text-left transition-colors hover:bg-secondary/60",
                  COLUMNS,
                  alert.id === selectedId && "bg-secondary shadow-[inset_2px_0_0_var(--accent)]",
                )}
              >
                <span><SeverityTag severity={alert.severity} /></span>
                <span className="min-w-0">
                  <span className="block truncate text-sm font-medium">{alert.title}</span>
                  <span className="mt-0.5 flex items-center gap-2 md:hidden">
                    <StatusTag status={alert.status} />
                    <span className="truncate font-mono text-xs text-muted-foreground">{alert.source}</span>
                  </span>
                </span>
                <span className="hidden truncate font-mono text-[0.8125rem] md:block">{alert.source}</span>
                <span className="hidden truncate font-mono text-[0.8125rem] text-muted-foreground md:block">
                  {alert.asset ?? "Not reported"}
                </span>
                <span className="hidden text-right text-xs text-muted-foreground md:block">
                  {timeAgo(alert.created_at)}
                </span>
              </button>
            </Reveal>
          </li>
        ))}
      </ul>
    </div>
  );
}
