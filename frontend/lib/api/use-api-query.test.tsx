import { act, cleanup, renderHook } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { useApiQuery } from "@/lib/api/use-api-query";

type Fetcher = (signal: AbortSignal) => Promise<string>;

function deferred() {
  let resolve!: (value: string) => void;
  const promise = new Promise<string>((settle) => {
    resolve = settle;
  });
  return { promise, resolve };
}

afterEach(cleanup);

describe("useApiQuery", () => {
  it("ignores a response that arrives after a retry superseded it", async () => {
    const first = deferred();
    const second = deferred();
    const fetcher = vi
      .fn<Fetcher>()
      .mockReturnValueOnce(first.promise)
      .mockReturnValueOnce(second.promise);

    const { result } = renderHook(() => useApiQuery(fetcher));
    act(() => result.current.retry());
    await act(async () => first.resolve("stale"));

    expect(result.current.state).toEqual({ status: "loading" });

    await act(async () => second.resolve("fresh"));

    expect(result.current.state).toEqual({ status: "success", data: "fresh" });
  });

  it("aborts the in-flight request on unmount", () => {
    const fetcher = vi.fn<Fetcher>(() => new Promise<string>(() => {}));

    const { unmount } = renderHook(() => useApiQuery(fetcher));
    const signal = fetcher.mock.calls[0][0];
    expect(signal.aborted).toBe(false);

    unmount();

    expect(signal.aborted).toBe(true);
  });
});
