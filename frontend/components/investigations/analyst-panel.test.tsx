import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { citeLabel, ReportBody } from "@/components/investigations/analyst-panel";
import type { AnalystReport } from "@/lib/api/analyst";

const report: AnalystReport = {
  summary: { statement: "A high-severity brute force alert.", cites: ["alert:severity", "alert:category"] },
  findings: [{ statement: "8 failed logins from 203.0.113.45.", cites: ["evidence:failed_login_burst"] }],
  limits: ["Only one evidence item supports this alert."],
  suggested_checks: [{ text: "Review the targeted accounts.", cites: ["alert:category"] }],
  mode: "deterministic",
  provider: "built-in-v1",
  model: null,
  generated_at: "2026-11-26T12:00:00Z",
  evidence_hash: "abc",
  fallback_reason: null,
  advisory: "Advisory only: this explanation never changes an alert's status or severity.",
  cached: false,
};

describe("ReportBody", () => {
  afterEach(cleanup);

  it("shows each statement with the evidence it cites, the limits and the advisory note", () => {
    render(<ReportBody report={report} onRefresh={vi.fn()} refreshing={false} refreshError={null} />);

    expect(screen.getByText("8 failed logins from 203.0.113.45.")).toBeTruthy();
    expect(screen.getByText("evidence · failed_login_burst")).toBeTruthy();
    expect(screen.getByText("Only one evidence item supports this alert.")).toBeTruthy();
    expect(screen.getByText(/Advisory only/)).toBeTruthy();
    expect(screen.getByText(/Built-in explanation/)).toBeTruthy();
  });

  it("says when a hosted answer was replaced and offers to regenerate", () => {
    const onRefresh = vi.fn();
    const fallback = { ...report, fallback_reason: "The hosted analyst is rate limited right now. Showing the built-in explanation instead." };

    render(<ReportBody report={fallback} onRefresh={onRefresh} refreshing={false} refreshError={null} />);
    fireEvent.click(screen.getByRole("button", { name: "Regenerate" }));

    expect(screen.getByRole("status").textContent).toContain("rate limited");
    expect(onRefresh).toHaveBeenCalledOnce();
  });

  it("labels hosted output with the model and disables the button while regenerating", () => {
    const hosted = { ...report, mode: "llm" as const, model: "openai/gpt-oss-120b", cached: true };

    render(<ReportBody report={hosted} onRefresh={vi.fn()} refreshing refreshError="Could not regenerate." />);

    expect(screen.getByText(/Hosted model openai\/gpt-oss-120b/)).toBeTruthy();
    expect(screen.getByText(/saved from an earlier view/)).toBeTruthy();
    expect((screen.getByRole("button", { name: "Regenerating…" }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByRole("alert").textContent).toBe("Could not regenerate.");
  });

  it("formats citation keys", () => {
    expect(citeLabel("alert:severity")).toBe("alert · severity");
    expect(citeLabel("evidence:feodo_tracker#2")).toBe("evidence · feodo_tracker#2");
  });
});
