"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { type Alert, updateAlert } from "@/lib/api/alerts";
import { toApiError } from "@/lib/api/client";
import { formatDateTime } from "@/lib/format";

const MAX_NOTE = 2000;

/** Notes are append-only: this form adds one, and there is no edit or delete. */
export function NotesPanel({ alert, onUpdated }: { alert: Alert; onUpdated: (alert: Alert) => void }) {
  const [text, setText] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    if (!text.trim()) return;
    setPending(true);
    setError(null);
    try {
      onUpdated(await updateAlert(alert.id, { note: text.trim() }));
      setText("");
    } catch (failure) {
      setError(toApiError(failure).message);
    } finally {
      setPending(false);
    }
  }

  return (
    <div className="space-y-4">
      {alert.notes.length === 0 ? (
        <p className="text-sm text-muted-foreground">No notes yet. Notes cannot be edited or deleted once added.</p>
      ) : (
        <ul className="space-y-3">
          {alert.notes.map((note) => (
            <li key={note.id} className="border-l-2 border-border pl-3">
              <p className="font-mono text-xs text-muted-foreground">{formatDateTime(note.created_at)}</p>
              <p className="whitespace-pre-wrap text-sm">{note.text}</p>
            </li>
          ))}
        </ul>
      )}
      <form onSubmit={submit} className="space-y-2">
        <label className="block text-sm font-medium" htmlFor="note-text">Add a note</label>
        <textarea
          id="note-text"
          value={text}
          maxLength={MAX_NOTE}
          rows={3}
          onChange={(e) => setText(e.target.value)}
          className="w-full rounded-md border border-input bg-card p-2 text-sm"
        />
        <div className="flex items-center gap-3">
          <Button type="submit" size="sm" disabled={pending || !text.trim()}>
            {pending ? "Saving…" : "Add note"}
          </Button>
          <span className="font-mono text-xs text-muted-foreground">{text.length}/{MAX_NOTE}</span>
        </div>
        {error && <p role="alert" className="text-sm text-sev-critical">{error}</p>}
      </form>
    </div>
  );
}
