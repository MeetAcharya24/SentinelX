import type { AlertStatus } from "@/lib/api/alerts";
import { STATUS_LABELS } from "@/lib/format";
import { cn } from "@/lib/utils";

const TONE: Record<AlertStatus, string> = {
  open: "text-accent",
  acknowledged: "text-sev-medium",
  false_positive: "text-muted-foreground",
  resolved: "text-sev-low",
};

/** Status reads as a hollow ring plus text, so it never competes with the severity tag. */
export function StatusTag({ status }: { status: AlertStatus }) {
  return (
    <span className={cn("inline-flex items-center gap-1.5 text-xs font-medium", TONE[status])}>
      <span aria-hidden className="size-2 rounded-full border-2 border-current" />
      {STATUS_LABELS[status]}
    </span>
  );
}
