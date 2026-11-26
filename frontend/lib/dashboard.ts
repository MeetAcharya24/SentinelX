import { type Alert, getAlerts, SEVERITIES, type Severity } from "@/lib/api/alerts";

export type RangeId = "24h" | "7d" | "30d";

export const RANGES: Record<RangeId, { label: string; hours: number; bucketHours: number }> = {
  "24h": { label: "Last 24 hours", hours: 24, bucketHours: 1 },
  "7d": { label: "Last 7 days", hours: 24 * 7, bucketHours: 24 },
  "30d": { label: "Last 30 days", hours: 24 * 30, bucketHours: 24 },
};

const HOUR_MS = 3_600_000;
export const RECENT_LIMIT = 200;

export type Bucket = { start: number; label: string } & Record<Severity, number>;

/** Counts alerts per time bucket, oldest first, by detection time. */
export function bucketAlerts(alerts: Alert[], range: RangeId, now: number): Bucket[] {
  const { hours, bucketHours } = RANGES[range];
  const size = bucketHours * HOUR_MS;
  const count = Math.ceil(hours / bucketHours);
  const end = Math.ceil(now / size) * size;
  const buckets: Bucket[] = Array.from({ length: count }, (_, i) => {
    const start = end - (count - i) * size;
    const date = new Date(start);
    const label =
      bucketHours === 1
        ? `${String(date.getUTCHours()).padStart(2, "0")}:00`
        : `${date.getUTCMonth() + 1}/${date.getUTCDate()}`;
    return { start, label, critical: 0, high: 0, medium: 0, low: 0 };
  });
  for (const alert of alerts) {
    const index = Math.floor((new Date(alert.created_at).getTime() - (end - count * size)) / size);
    if (index >= 0 && index < count) buckets[index][alert.severity] += 1;
  }
  return buckets;
}

export function topSources(alerts: Alert[], limit = 5): { source: string; count: number }[] {
  const counts = new Map<string, number>();
  for (const alert of alerts) counts.set(alert.source, (counts.get(alert.source) ?? 0) + 1);
  return [...counts]
    .map(([source, count]) => ({ source, count }))
    .sort((a, b) => b.count - a.count || a.source.localeCompare(b.source))
    .slice(0, limit);
}

export function distinctAffected(alerts: Alert[]): number {
  return new Set(alerts.map((alert) => alert.asset ?? alert.source)).size;
}

export type DashboardData = {
  recent: Alert[];
  recentTotal: number;
  open: number;
  urgent: number;
  falsePositives: number;
  queue: Alert[];
  affected: number;
  hasDemo: boolean;
  loadedAt: number;
};

/** One round of real API calls for the dashboard; every figure comes from stored alerts. */
export async function loadDashboard(range: RangeId, signal: AbortSignal): Promise<DashboardData> {
  const loadedAt = Date.now();
  const created_from = new Date(loadedAt - RANGES[range].hours * HOUR_MS).toISOString();
  const [recent, open, urgent, falsePositives, queue] = await Promise.all([
    getAlerts({ created_from, limit: RECENT_LIMIT }, signal),
    getAlerts({ created_from, status: ["open"], limit: RECENT_LIMIT }, signal),
    getAlerts({ created_from, status: ["open"], severity: ["critical", "high"], limit: 1 }, signal),
    getAlerts({ created_from, status: ["false_positive"], limit: 1 }, signal),
    getAlerts({ created_from, status: ["open"], limit: 5 }, signal),
  ]);
  return {
    recent: recent.alerts,
    recentTotal: recent.total,
    open: open.total,
    urgent: urgent.total,
    falsePositives: falsePositives.total,
    queue: queue.alerts,
    affected: distinctAffected(open.alerts),
    hasDemo: recent.alerts.some((alert) => alert.demo),
    loadedAt,
  };
}

export { SEVERITIES };
