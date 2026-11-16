import { describe, expect, it, vi } from "vitest";

import { API_BASE_URL, ApiError, apiGet } from "@/lib/api/client";

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
