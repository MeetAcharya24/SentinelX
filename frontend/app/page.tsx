import { SystemStatus } from "@/components/system-status";

export default function Home() {
  return (
    <main className="mx-auto flex w-full max-w-xl flex-1 flex-col justify-center gap-8 px-4 py-16">
      <header className="space-y-2">
        <h1 className="text-3xl font-semibold tracking-tight">SentinelX</h1>
        <p className="text-muted-foreground">
          Defensive security analytics for authorised logs and network datasets.
        </p>
      </header>
      <SystemStatus />
    </main>
  );
}
