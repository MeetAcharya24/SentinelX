const UNITS: [Intl.RelativeTimeFormatUnit, number][] = [
  ["day", 86_400],
  ["hour", 3_600],
  ["minute", 60],
];

const relative = new Intl.RelativeTimeFormat("en", { numeric: "always", style: "short" });

/** "2 min. ago" style text, computed once at render; never ticks. */
export function timeAgo(iso: string, now: number = Date.now()): string {
  const seconds = Math.round((new Date(iso).getTime() - now) / 1000);
  for (const [unit, size] of UNITS) {
    if (Math.abs(seconds) >= size) return relative.format(Math.round(seconds / size), unit);
  }
  return "just now";
}

export function formatDateTime(iso: string): string {
  return new Intl.DateTimeFormat("en", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
    timeZone: "UTC",
  }).format(new Date(iso)) + " UTC";
}

export const CATEGORY_LABELS: Record<string, string> = {
  network_anomaly: "Network anomaly",
  brute_force: "Brute force",
  known_bad_source: "Known bad source",
  suspicious_activity: "Suspicious activity",
  phishing: "Phishing",
};

export const STATUS_LABELS: Record<string, string> = {
  open: "Open",
  acknowledged: "Acknowledged",
  false_positive: "False positive",
  resolved: "Resolved",
};

export const alertRef = (id: number) => `ALT-${String(id).padStart(4, "0")}`;
