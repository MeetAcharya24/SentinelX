"use client";

import { useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { analyzeLogFile } from "@/lib/api/alerts";
import { ApiError, toApiError } from "@/lib/api/client";

/** Uploads a CSV/JSON security log for analysis. Nothing is analysed until the operator submits. */
export function LogUpload({ onAnalyzed }: { onAnalyzed: () => void }) {
  const input = useRef<HTMLInputElement>(null);
  const [demo, setDemo] = useState(false);
  const [pending, setPending] = useState(false);
  const [message, setMessage] = useState<{ tone: "ok" | "error"; text: string } | null>(null);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    const file = input.current?.files?.[0];
    if (!file) {
      setMessage({ tone: "error", text: "Choose a CSV or JSON log file first." });
      return;
    }
    setPending(true);
    setMessage(null);
    try {
      const result = await analyzeLogFile(file, demo);
      const added = result.alerts.length - result.duplicates;
      setMessage({
        tone: "ok",
        text:
          `Analysed ${result.analyzed} events: ${added} new ${added === 1 ? "alert" : "alerts"} stored` +
          (result.duplicates > 0 ? `, ${result.duplicates} already on file.` : "."),
      });
      onAnalyzed();
    } catch (failure) {
      const error = toApiError(failure);
      const first = error instanceof ApiError ? error.details?.[0] : undefined;
      setMessage({ tone: "error", text: first ? `${error.message} ${first.field}: ${first.message}` : error.message });
    } finally {
      setPending(false);
    }
  }

  return (
    <form onSubmit={submit} className="flex flex-wrap items-center gap-3" aria-label="Analyse a log file">
      <input
        ref={input}
        type="file"
        accept=".csv,.json,text/csv,application/json"
        aria-label="Security log file"
        className="max-w-full text-sm text-muted-foreground file:mr-3 file:rounded-md file:border file:border-input file:bg-card file:px-3 file:py-1.5 file:text-sm file:text-foreground"
      />
      <label className="flex items-center gap-2 text-sm text-muted-foreground">
        <input type="checkbox" checked={demo} onChange={(e) => setDemo(e.target.checked)} />
        Label as demo data
      </label>
      <Button type="submit" size="sm" disabled={pending}>
        {pending ? "Analysing…" : "Analyse log"}
      </Button>
      {message && (
        <p role={message.tone === "error" ? "alert" : "status"} className={message.tone === "error" ? "w-full text-sm text-sev-critical" : "w-full text-sm text-sev-low"}>
          {message.text}
        </p>
      )}
    </form>
  );
}
