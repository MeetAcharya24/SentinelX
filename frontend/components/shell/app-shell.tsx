"use client";

import { type ReactNode, Suspense } from "react";
import { Atmosphere } from "@/components/shell/atmosphere";
import { Sidebar } from "@/components/shell/sidebar";
import { Topbar } from "@/components/shell/topbar";

export function AppShell({ children }: { children: ReactNode }) {
  return (
    <>
      <Atmosphere />
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:fixed focus:left-3 focus:top-3 focus:z-50 focus:rounded focus:bg-primary focus:px-3 focus:py-2 focus:text-primary-foreground"
      >
        Skip to content
      </a>
      <div className="flex min-h-screen flex-col md:flex-row">
        <Suspense fallback={<aside className="border-b border-sidebar-border bg-sidebar md:h-screen md:w-60 md:shrink-0 md:border-r" />}>
          <Sidebar />
        </Suspense>
        <div className="flex min-w-0 flex-1 flex-col">
          <Topbar />
          <main id="main" className="mx-auto w-full max-w-[1400px] flex-1 px-4 pb-10 pt-5 md:px-6">
            {children}
          </main>
        </div>
      </div>
    </>
  );
}
