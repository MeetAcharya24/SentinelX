import { describe, expect, it } from "vitest";

import { alertRef, timeAgo } from "@/lib/format";

const NOW = Date.UTC(2026, 10, 26, 12, 0);

describe("timeAgo", () => {
  it("reports minutes, hours and days in the past", () => {
    expect(timeAgo(new Date(NOW - 2 * 60_000).toISOString(), NOW)).toContain("2");
    expect(timeAgo(new Date(NOW - 2 * 60_000).toISOString(), NOW)).toMatch(/min/);
    expect(timeAgo(new Date(NOW - 3 * 3_600_000).toISOString(), NOW)).toMatch(/hr/);
    expect(timeAgo(new Date(NOW - 2 * 86_400_000).toISOString(), NOW)).toMatch(/day/);
  });

  it("says just now under a minute", () => {
    expect(timeAgo(new Date(NOW - 20_000).toISOString(), NOW)).toBe("just now");
  });
});

describe("alertRef", () => {
  it("pads the id", () => {
    expect(alertRef(12)).toBe("ALT-0012");
  });
});
