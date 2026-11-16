import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { SystemStatus } from "@/components/system-status";
import type { HealthStatus } from "@/lib/api/health";

const healthyNoKey: HealthStatus = {
  status: "ok",
  version: "0.1.0",
  environment: "development",
  analyst: { mode: "deterministic", provider: null },
  threat_intel_configured: false,
};

function envelope(data: HealthStatus) {
  return new Response(JSON.stringify({ success: true, data, error: null }));
}

afterEach(cleanup);

describe("SystemStatus", () => {
  it("shows a loading state before the API responds", () => {
    vi.stubGlobal("fetch", vi.fn(() => new Promise<Response>(() => {})));

    render(<SystemStatus />);

    expect(screen.getByRole("status").textContent).toContain("Checking API");
  });

  it("shows API status and the no-API-key analyst mode", async () => {
    vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(envelope(healthyNoKey))));

    render(<SystemStatus />);

    expect(await screen.findByText("Online · v0.1.0")).toBeTruthy();
    expect(screen.getByText("Built-in explanations (no API key configured)")).toBeTruthy();
    expect(screen.getByText("Not configured")).toBeTruthy();
  });

  it("shows an error with a retry that recovers once the API is back", async () => {
    const fetchMock = vi
      .fn()
      .mockRejectedValueOnce(new TypeError("Failed to fetch"))
      .mockResolvedValueOnce(envelope(healthyNoKey));
    vi.stubGlobal("fetch", fetchMock);

    render(<SystemStatus />);
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("Cannot reach the SentinelX API");

    fireEvent.click(screen.getByRole("button", { name: "Try again" }));

    expect(await screen.findByText("Online · v0.1.0")).toBeTruthy();
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});
