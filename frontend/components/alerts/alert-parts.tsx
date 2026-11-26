import { Fragment } from "react";
import type { Alert, Evidence } from "@/lib/api/alerts";
import { CATEGORY_LABELS, formatDateTime } from "@/lib/format";

const KIND_LABELS: Record<Evidence["kind"], string> = {
  model_score: "Model score",
  rule_match: "Rule match",
  phishing_signal: "Email signal",
  model_term: "Model term",
  caveat: "Caveat",
};

export function EvidenceList({ evidence }: { evidence: Evidence[] }) {
  if (evidence.length === 0) {
    return <p className="text-sm text-muted-foreground">This alert carries no evidence items.</p>;
  }
  return (
    <ul className="space-y-3">
      {evidence.map((item, index) => (
        <li key={`${item.name}-${index}`} className="border-l-2 border-border pl-3">
          <div className="flex flex-wrap items-baseline justify-between gap-x-3">
            <p className="text-sm font-medium">{item.name}</p>
            <p className="font-mono text-xs text-muted-foreground">
              {KIND_LABELS[item.kind]}
              {item.value !== null && ` · ${Number.isInteger(item.value) ? item.value : item.value.toFixed(3)}`}
            </p>
          </div>
          <p className="mt-0.5 text-sm text-muted-foreground">{item.description}</p>
          {item.examples.length > 0 && (
            <ul className="mt-1.5 flex flex-wrap gap-1.5">
              {item.examples.map((example) => (
                <li key={example} className="rounded bg-secondary px-1.5 py-0.5 font-mono text-xs">
                  {example}
                </li>
              ))}
            </ul>
          )}
        </li>
      ))}
    </ul>
  );
}

type TimelineEvent = { at: string; text: string };

export function timelineEvents(alert: Alert): TimelineEvent[] {
  const events: TimelineEvent[] = [];
  if (alert.occurred_at) events.push({ at: alert.occurred_at, text: "Activity occurred" });
  events.push({
    at: alert.created_at,
    text: `Alert generated (${alert.severity}, ${alert.confidence}% confidence)`,
  });
  for (const note of alert.notes) events.push({ at: note.created_at, text: `Note: ${note.text}` });
  return events.sort((a, b) => a.at.localeCompare(b.at));
}

/** Vertical timeline; the spine draws once on mount and stays still under reduced motion. */
export function Timeline({ alert }: { alert: Alert }) {
  const events = timelineEvents(alert);
  return (
    <ol className="relative space-y-4 pl-6">
      <span aria-hidden className="timeline-spine absolute bottom-1 left-[5px] top-1 w-px bg-border" />
      {events.map((event, index) => (
        <li key={`${event.at}-${index}`} className="relative">
          <span aria-hidden className="absolute -left-6 top-1.5 size-[11px] rounded-full border-2 border-accent bg-background" />
          <p className="font-mono text-xs text-muted-foreground">{formatDateTime(event.at)}</p>
          <p className="text-sm">{event.text}</p>
        </li>
      ))}
    </ol>
  );
}

export function Facts({ alert }: { alert: Alert }) {
  const rows: [string, string][] = [
    ["Category", CATEGORY_LABELS[alert.category] ?? alert.category],
    ["Source", alert.source],
    ["Asset", alert.asset ?? "Not reported"],
    ["Confidence", `${alert.confidence}%`],
    ["Detected", formatDateTime(alert.created_at)],
  ];
  return (
    <dl className="grid grid-cols-[auto_1fr] gap-x-5 gap-y-2 text-sm">
      {rows.map(([label, value]) => (
        <Fragment key={label}>
          <dt className="text-muted-foreground">{label}</dt>
          <dd className="min-w-0 break-words font-mono text-[0.8125rem]">{value}</dd>
        </Fragment>
      ))}
    </dl>
  );
}
