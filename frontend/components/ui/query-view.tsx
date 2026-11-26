"use client";

import type { ReactNode } from "react";
import { Button } from "@/components/ui/button";
import type { QueryState } from "@/lib/api/use-api-query";

export function Skeleton({ className = "h-4 w-full" }: { className?: string }) {
  return <div aria-hidden className={`skeleton ${className}`} />;
}

export function LoadingRows({ rows = 4 }: { rows?: number }) {
  return (
    <div role="status" aria-live="polite" className="space-y-3 py-1">
      <span className="sr-only">Loading…</span>
      {Array.from({ length: rows }, (_, i) => (
        <Skeleton key={i} className="h-5 w-full" />
      ))}
    </div>
  );
}

export function ErrorNotice({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div role="alert" className="space-y-3 py-2">
      <p className="text-sm">{message}</p>
      {onRetry && (
        <Button variant="outline" size="sm" onClick={onRetry}>
          Try again
        </Button>
      )}
    </div>
  );
}

export function EmptyNotice({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="space-y-1 py-6 text-center">
      <p className="text-sm font-medium">{title}</p>
      {children && <div className="text-sm text-muted-foreground">{children}</div>}
    </div>
  );
}

/** Renders the three request states; `children` runs only on success. */
export function QueryView<T>({
  state,
  retry,
  rows,
  children,
}: {
  state: QueryState<T>;
  retry: () => void;
  rows?: number;
  children: (data: T) => ReactNode;
}) {
  if (state.status === "loading") return <LoadingRows rows={rows} />;
  if (state.status === "error") return <ErrorNotice message={state.error.message} onRetry={retry} />;
  return <>{children(state.data)}</>;
}
