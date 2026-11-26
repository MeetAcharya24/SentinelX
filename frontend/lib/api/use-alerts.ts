"use client";

import { useCallback } from "react";

import { type AlertPage, alertQueryString, type AlertQuery } from "@/lib/api/alerts";
import { apiGet } from "@/lib/api/client";
import { useApiQuery } from "@/lib/api/use-api-query";

/** Fetches one page of alerts; refetches when the query's serialised form changes. */
export function useAlerts(query: AlertQuery) {
  const suffix = alertQueryString(query);
  const fetcher = useCallback(
    (signal: AbortSignal) => apiGet<AlertPage>(`/api/v1/alerts${suffix}`, signal),
    [suffix],
  );
  return useApiQuery(fetcher);
}
