"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { type Alert, type AlertStatus, updateAlert } from "@/lib/api/alerts";
import { toApiError } from "@/lib/api/client";

const ACTIONS: { status: AlertStatus; label: string }[] = [
  { status: "acknowledged", label: "Acknowledge" },
  { status: "false_positive", label: "Mark false positive" },
  { status: "resolved", label: "Resolve" },
  { status: "open", label: "Reopen" },
];

/** Status changes go to the API; the alert shown is always the one the API returns. */
export function StatusActions({ alert, onUpdated }: { alert: Alert; onUpdated: (alert: Alert) => void }) {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function change(status: AlertStatus) {
    setPending(true);
    setError(null);
    try {
      onUpdated(await updateAlert(alert.id, { status }));
    } catch (failure) {
      setError(toApiError(failure).message);
    } finally {
      setPending(false);
    }
  }

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap gap-2">
        {ACTIONS.filter((action) => action.status !== alert.status).map((action) => (
          <Button
            key={action.status}
            variant="outline"
            size="sm"
            disabled={pending}
            onClick={() => change(action.status)}
          >
            {action.label}
          </Button>
        ))}
      </div>
      {error && (
        <p role="alert" className="text-sm text-sev-critical">
          {error}
        </p>
      )}
    </div>
  );
}
