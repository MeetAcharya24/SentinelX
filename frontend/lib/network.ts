import type { Alert } from "@/lib/api/alerts";

/** Share of network alerts in which each evidence item appears, most common first. */
export function topFactors(alerts: Alert[], limit = 5): { name: string; share: number }[] {
  if (alerts.length === 0) return [];
  const counts = new Map<string, number>();
  for (const alert of alerts) {
    const names = new Set(
      alert.evidence.filter((item) => item.kind !== "caveat").map((item) => item.name),
    );
    for (const name of names) counts.set(name, (counts.get(name) ?? 0) + 1);
  }
  return [...counts]
    .map(([name, count]) => ({ name, share: count / alerts.length }))
    .sort((a, b) => b.share - a.share || a.name.localeCompare(b.name))
    .slice(0, limit);
}
