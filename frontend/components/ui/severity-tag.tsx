import type { CSSProperties } from "react";
import type { Severity } from "@/lib/api/alerts";

const LABELS: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
};

export function SeverityTag({ severity }: { severity: Severity }) {
  const style = {
    "--tag-edge": `var(--sev-${severity}-edge)`,
    "--tag-bg": `var(--sev-${severity}-bg)`,
    "--tag-fg": `var(--sev-${severity})`,
  } as CSSProperties;
  return (
    <span className="sev-tag" style={style}>
      {LABELS[severity]}
    </span>
  );
}

export const SEVERITY_COLOR: Record<Severity, string> = {
  critical: "var(--sev-critical-edge)",
  high: "var(--sev-high-edge)",
  medium: "var(--sev-medium-edge)",
  low: "var(--sev-low-edge)",
};
