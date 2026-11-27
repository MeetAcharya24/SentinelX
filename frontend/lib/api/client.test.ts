import { describe, expect, it, vi } from "vitest";

import { API_BASE_URL, ApiError, apiGet, apiPatch, apiPost } from "@/lib/api/client";

function stubFetch(response: Response | Error) {
  const fetchMock = vi.fn(() =>
    response instanceof Error ? Promise.reject(response) : Promise.resolve(response),
  );
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status });
}

describe("apiGet", () => {
  it("returns the data payload of a successful envelope", async () => {
    const fetchMock = stubFetch(
      jsonResponse({ success: true, data: { status: "ok" }, error: null }),
    );

    const data = await apiGet<{ status: string }>("/health");

    expect(data).toEqual({ status: "ok" });
    expect(fetchMock.mock.calls[0]).toContain(`${API_BASE_URL}/health`);
  });

  it("throws an ApiError carrying the backend error code and status", async () => {
    stubFetch(
      jsonResponse(
        {
          success: false,
          data: null,
          error: { code: "http_404", message: "Not Found", details: null },
        },
        404,
      ),
    );

    const error = await apiGet("/missing").catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({ code: "http_404", message: "Not Found", status: 404 });
  });

  it("reports a network error when the backend is unreachable", async () => {
    stubFetch(new TypeError("Failed to fetch"));

    await expect(apiGet("/health")).rejects.toMatchObject({ code: "network_error" });
  });

  it("rejects a failure envelope that carries no error object", async () => {
    stubFetch(jsonResponse({ success: false, data: null, error: null }, 500));

    await expect(apiGet("/health")).rejects.toMatchObject({
      code: "invalid_response",
      status: 500,
    });
  });

  it("rejects responses that are not a valid envelope", async () => {
    stubFetch(new Response("<html>Bad gateway</html>", { status: 502 }));

    await expect(apiGet("/health")).rejects.toMatchObject({
      code: "invalid_response",
      status: 502,
    });
  });
});

describe("write token", () => {
  const ok = () => jsonResponse({ success: true, data: {}, error: null });
  // A Response body can be read once, so each call gets a fresh one.
  const stubFreshFetch = () => {
    const fetchMock = vi.fn(() => Promise.resolve(ok()));
    vi.stubGlobal("fetch", fetchMock);
    return fetchMock;
  };

  it("is sent on writes and not on reads when configured", async () => {
    vi.stubEnv("NEXT_PUBLIC_DEMO_WRITE_TOKEN", "demo-token-value");
    const fetchMock = stubFreshFetch();

    await apiGet("/api/v1/alerts");
    await apiPost("/api/v1/alerts/1/analysis/refresh");
    await apiPatch("/api/v1/alerts/1", { status: "resolved" });

    const sent = (call: number) =>
      (fetchMock.mock.calls[call] as unknown as [string, RequestInit])[1].headers as Record<
        string,
        string
      >;
    expect(sent(0)["X-Demo-Write-Token"]).toBeUndefined();
    expect(sent(1)["X-Demo-Write-Token"]).toBe("demo-token-value");
    expect(sent(2)["X-Demo-Write-Token"]).toBe("demo-token-value");
    vi.unstubAllEnvs();
  });

  it("is omitted when not configured", async () => {
    vi.stubEnv("NEXT_PUBLIC_DEMO_WRITE_TOKEN", "");
    const fetchMock = stubFreshFetch();

    await apiPost("/api/v1/alerts/1/analysis/refresh");

    const init = (fetchMock.mock.calls[0] as unknown as [string, RequestInit])[1];
    expect(init.headers).not.toHaveProperty("X-Demo-Write-Token");
    vi.unstubAllEnvs();
  });
});
