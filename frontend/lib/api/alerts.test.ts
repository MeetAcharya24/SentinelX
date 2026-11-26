import { afterEach, describe, expect, it, vi } from "vitest";

import { alertQueryString, updateAlert } from "@/lib/api/alerts";

describe("alertQueryString", () => {
  it("repeats array filters and drops empty values", () => {
    expect(
      alertQueryString({ status: ["open"], severity: ["critical", "high"], source: "", limit: 10 }),
    ).toBe("?status=open&severity=critical&severity=high&limit=10");
  });

  it("is empty with no filters", () => {
    expect(alertQueryString({})).toBe("");
  });
});

describe("updateAlert", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("PATCHes JSON and returns the unwrapped alert", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ success: true, data: { id: 3, status: "resolved" }, error: null })),
    );
    vi.stubGlobal("fetch", fetchMock);

    const result = await updateAlert(3, { status: "resolved" });

    expect(result).toMatchObject({ id: 3, status: "resolved" });
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toContain("/api/v1/alerts/3");
    expect(init).toMatchObject({ method: "PATCH", body: JSON.stringify({ status: "resolved" }) });
  });
});
