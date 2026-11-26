const LINK = "underline decoration-border underline-offset-2 hover:text-foreground";

/** Attribution required by abuse.ch for the threat-intelligence feeds. */
export function IntelCredit({ className }: { className?: string }) {
  return (
    <p className={className}>
      Threat intelligence from{" "}
      <a href="https://threatfox.abuse.ch/" target="_blank" rel="noopener noreferrer" className={LINK}>
        ThreatFox
      </a>{" "}
      and{" "}
      <a href="https://feodotracker.abuse.ch/" target="_blank" rel="noopener noreferrer" className={LINK}>
        Feodo Tracker
      </a>{" "}
      by{" "}
      <a href="https://abuse.ch/" target="_blank" rel="noopener noreferrer" className={LINK}>
        abuse.ch
      </a>
      .
    </p>
  );
}
