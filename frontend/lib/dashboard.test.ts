import { describe, expect, it } from "vitest";

import type { Alert } from "@/lib/api/alerts";
import { bucketAlerts, distinctAffected, topSources } from "@/lib/dashboard";
import { topFactors } from "@/lib/network";

const NOW = Date.UTC(2026, 10, 26, 12, 30);

function alert(overrides: Partial<Alert>): Alert {
  return {
    id: 1,
    created_at: new Date(NOW - 10 * 60_000).toISOString(),
    occurred_at: null,
    severity: "low",
    confidence: 80,
    category: "brute_force",
    source: "203.0.113.45",
    asset: null,
    title: "t",
    evidence: [],
    status: "open",
    demo: false,
    notes: [],
    ...overrides,
  };
}

describe("bucketAlerts", () => {
  it("returns 24 hourly buckets and counts an alert by severity in its hour", () => {
    const buckets = bucketAlerts([alert({ severity: "high" }), alert({ severity: "high" })], "24h", NOW);

    expect(buckets).toHaveLength(24);
    expect(buckets.at(-1)).toMatchObject({ label: "12:00", high: 2, critical: 0 });
  });

  it("ignores alerts older than the period", () => {
    const old = alert({ created_at: new Date(NOW - 3 * 86_400_000).toISOString() });

    const total = bucketAlerts([old], "24h", NOW).reduce((sum, b) => sum + b.low, 0);

    expect(total).toBe(0);
  });

  it("uses daily buckets for the 7-day period", () => {
    expect(bucketAlerts([], "7d", NOW)).toHaveLength(7);
  });
});

describe("topSources and distinctAffected", () => {
  it("ranks sources by count, then name", () => {
    const alerts = [alert({ source: "b" }), alert({ source: "a" }), alert({ source: "b" })];

    expect(topSources(alerts)).toEqual([
      { source: "b", count: 2 },
      { source: "a", count: 1 },
    ]);
  });

  it("counts an alert's asset, or its source when it has none", () => {
    const alerts = [alert({ asset: "vpn" }), alert({ asset: "vpn" }), alert({ asset: null, source: "x" })];

    expect(distinctAffected(alerts)).toBe(2);
  });
});

describe("topFactors", () => {
  it("returns the share of alerts citing each evidence item and skips caveats", () => {
    const evidence = (name: string, kind: "model_score" | "caveat" = "model_score") => ({
      kind, name, description: "", value: null, examples: [],
    });
    const alerts = [
      alert({ evidence: [evidence("Random Forest"), evidence("note", "caveat")] }),
      alert({ evidence: [evidence("Random Forest"), evidence("Isolation Forest")] }),
    ];

    expect(topFactors(alerts)).toEqual([
      { name: "Random Forest", share: 1 },
      { name: "Isolation Forest", share: 0.5 },
    ]);
  });

  it("is empty without alerts", () => {
    expect(topFactors([])).toEqual([]);
  });
});
