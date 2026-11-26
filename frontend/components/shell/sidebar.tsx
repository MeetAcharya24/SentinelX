"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Activity,
  Bell,
  FileText,
  LayoutDashboard,
  type LucideIcon,
  Search,
  Server,
  Settings,
  Sparkles,
  Waypoints,
} from "lucide-react";
import { cn } from "@/lib/utils";

type NavItem = { label: string; href?: string; icon: LucideIcon; note?: string };

const NAV: NavItem[] = [
  { label: "SOC Dashboard", href: "/", icon: LayoutDashboard },
  { label: "Threat Alerts", href: "/alerts", icon: Bell },
  { label: "Investigations", href: "/investigations", icon: Search },
  { label: "Network Analysis", href: "/network", icon: Waypoints },
  { label: "Anomaly Detection", icon: Activity, note: "Not built yet" },
  { label: "Assets & Inventory", icon: Server, note: "Not built yet" },
  { label: "Reports", icon: FileText, note: "Not built yet" },
  { label: "AI Security Analyst", icon: Sparkles, note: "In each investigation" },
];

function isActive(pathname: string, href: string) {
  return href === "/" ? pathname === "/" : pathname.startsWith(href);
}

function Logo() {
  return (
    <Link href="/" className="flex items-center gap-2.5 px-2 py-1" aria-label="SentinelX home">
      <svg viewBox="0 0 24 24" className="size-7" aria-hidden>
        <path
          d="M12 2 4 5.5v5.8c0 4.7 3.3 8.7 8 10.2 4.7-1.5 8-5.5 8-10.2V5.5L12 2Z"
          fill="none"
          stroke="var(--accent)"
          strokeWidth="1.6"
          strokeLinejoin="round"
        />
        <path
          d="m8.6 12.2 2.4 2.4 4.4-4.9"
          fill="none"
          stroke="var(--accent)"
          strokeWidth="1.8"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </svg>
      <span className="text-lg font-semibold tracking-tight">SentinelX</span>
    </Link>
  );
}

const ITEM = "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium";

export function Sidebar() {
  const pathname = usePathname();
  return (
    <aside className="relative border-b border-sidebar-border bg-sidebar/85 backdrop-blur md:sticky md:top-0 md:h-screen md:w-60 md:shrink-0 md:border-b-0 md:border-r">
      <div className="p-3 md:p-4">
        <Logo />
        <nav
          aria-label="Primary"
          className="mt-2 flex gap-1 overflow-x-auto md:mt-6 md:flex-col md:overflow-visible"
        >
          {NAV.map(({ label, href, icon: Icon, note }) => {
            const body = (
              <>
                <Icon className="size-[1.0625rem] shrink-0" aria-hidden />
                <span className="whitespace-nowrap">{label}</span>
              </>
            );
            if (!href) {
              return (
                <span
                  key={label}
                  aria-disabled="true"
                  title={note}
                  className={cn(ITEM, "hidden cursor-not-allowed text-muted-foreground/60 md:flex")}
                >
                  {body}
                </span>
              );
            }
            const active = isActive(pathname, href);
            return (
              <Link
                key={label}
                href={href}
                aria-current={active ? "page" : undefined}
                className={cn(
                  ITEM,
                  "transition-colors",
                  active
                    ? "bg-primary text-primary-foreground"
                    : "text-muted-foreground hover:bg-sidebar-accent hover:text-foreground",
                )}
              >
                {body}
              </Link>
            );
          })}
        </nav>
      </div>
      <div className="absolute bottom-0 left-0 hidden w-full px-4 pb-4 md:block">
        <span
          aria-disabled="true"
          title="Not built yet"
          className={cn(ITEM, "cursor-not-allowed text-muted-foreground/60")}
        >
          <Settings className="size-[1.0625rem]" aria-hidden /> Settings
        </span>
      </div>
    </aside>
  );
}
