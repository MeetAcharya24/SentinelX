import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { EvidenceList } from "@/components/alerts/alert-parts";
import type { Evidence } from "@/lib/api/alerts";

const match: Evidence = {
  kind: "threat_intel_match",
  name: "feodo_tracker",
  description: "Source address 203.0.113.45 is listed in Feodo Tracker (abuse.ch).",
  value: null,
  examples: ["203.0.113.45"],
};

describe("EvidenceList", () => {
  afterEach(cleanup);

  it("labels a feed match and credits abuse.ch beneath it", () => {
    render(<EvidenceList evidence={[match]} />);

    expect(screen.getByText("Threat intelligence")).toBeTruthy();
    expect(screen.getByRole("link", { name: "ThreatFox" }).getAttribute("href")).toBe("https://threatfox.abuse.ch/");
    expect(screen.getByRole("link", { name: "Feodo Tracker" })).toBeTruthy();
  });

  it("shows no credit when no evidence came from the feeds", () => {
    render(<EvidenceList evidence={[{ ...match, kind: "rule_match" }]} />);

    expect(screen.queryByRole("link", { name: "ThreatFox" })).toBeNull();
  });
});
