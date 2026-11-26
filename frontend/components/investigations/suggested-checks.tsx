"use client";

import { useState } from "react";
import type { AlertCategory } from "@/lib/api/alerts";

/** General defensive guidance per category. Nothing here is automated or touches a system. */
const CHECKS: Record<AlertCategory, string[]> = {
  network_anomaly: [
    "Confirm the flow's source and destination belong to expected hosts",
    "Compare its volume and timing with the asset's usual traffic",
    "Check firewall and proxy logs for the same time window",
  ],
  brute_force: [
    "Review the targeted accounts for any successful sign-in",
    "Check whether the source address is expected for these users",
    "Consider enforcing multi-factor sign-in for the affected accounts",
  ],
  known_bad_source: [
    "Confirm the address matches your own blocklist entry and its reason",
    "Look for other events from the same source",
    "Review what the source reached before it was flagged",
  ],
  suspicious_activity: [
    "Confirm the change was authorised and who requested it",
    "Compare against the change calendar",
    "Review the account's other activity that day",
  ],
  phishing: [
    "Do not open links or attachments from the message",
    "Check whether other users received the same message",
    "Report the sender and domain through your mail provider",
  ],
};

export function SuggestedChecks({ category }: { category: AlertCategory }) {
  const [done, setDone] = useState<Record<string, boolean>>({});
  return (
    <div className="space-y-3">
      <ul className="space-y-2">
        {CHECKS[category].map((check) => (
          <li key={check}>
            <label className="flex items-start gap-2.5 text-sm">
              <input
                type="checkbox"
                className="mt-1"
                checked={done[check] ?? false}
                onChange={(e) => setDone((current) => ({ ...current, [check]: e.target.checked }))}
              />
              <span>{check}</span>
            </label>
          </li>
        ))}
      </ul>
      <p className="text-xs text-muted-foreground">
        General guidance for this alert type. Ticks are not saved.
      </p>
    </div>
  );
}
