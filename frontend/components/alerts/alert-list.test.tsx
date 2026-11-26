import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { AlertList } from "@/components/alerts/alert-list";
import type { Alert } from "@/lib/api/alerts";

const alert: Alert = {
  id: 7,
  created_at: new Date().toISOString(),
  occurred_at: null,
  severity: "critical",
  confidence: 90,
  category: "brute_force",
  source: "203.0.113.45",
  asset: null,
  title: "Brute-force burst",
  evidence: [],
  status: "open",
  demo: false,
  notes: [],
};

describe("AlertList", () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("selects an alert when its row is activated and marks the selected row", () => {
    vi.stubGlobal("IntersectionObserver", undefined);
    const onSelect = vi.fn();

    render(<AlertList alerts={[alert]} selectedId={7} onSelect={onSelect} />);
    const row = screen.getByRole("button", { name: /Brute-force burst/ });
    fireEvent.click(row);

    expect(row.getAttribute("aria-pressed")).toBe("true");
    expect(onSelect).toHaveBeenCalledWith(alert);
    expect(screen.getAllByText("Critical").length).toBeGreaterThan(0);
  });
});
