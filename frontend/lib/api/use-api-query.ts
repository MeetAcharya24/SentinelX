"use client";

import { useCallback, useEffect, useState } from "react";

import { type ApiError, toApiError } from "@/lib/api/client";

export type QueryState<T> =
  | { status: "loading" }
  | { status: "success"; data: T }
  | { status: "error"; error: ApiError };

type Fetcher<T> = (signal: AbortSignal) => Promise<T>;

/**
 * Runs a fetcher on mount and exposes loading / success / error state plus a
 * retry. `fetcher` must be referentially stable (module-level or memoised).
 */
export function useApiQuery<T>(fetcher: Fetcher<T>) {
  const [state, setState] = useState<QueryState<T>>({ status: "loading" });
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    fetcher(controller.signal).then(
      (data) => {
        if (controller.signal.aborted) return;
        setState({ status: "success", data });
      },
      (error: unknown) => {
        if (controller.signal.aborted) return;
        setState({ status: "error", error: toApiError(error) });
      },
    );
    return () => controller.abort();
  }, [fetcher, attempt]);

  const retry = useCallback(() => {
    setState({ status: "loading" });
    setAttempt((current) => current + 1);
  }, []);

  return { state, retry };
}
