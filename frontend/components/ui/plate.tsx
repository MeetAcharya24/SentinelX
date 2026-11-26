import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

export function Plate({
  title,
  action,
  children,
  className,
  hover = false,
  id,
}: {
  title?: string;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
  /** Lifts on hover (shadow only under reduced motion). Use for cards that open something. */
  hover?: boolean;
  id?: string;
}) {
  const headingId = id ? `${id}-heading` : undefined;
  return (
    <section
      aria-labelledby={title ? headingId : undefined}
      className={cn(
        "plate p-4",
        hover &&
          "transition-[transform,box-shadow] duration-200 hover:shadow-lg hover:shadow-black/40 motion-safe:hover:-translate-y-1",
        className,
      )}
    >
      {(title || action) && (
        <header className="mb-3 flex items-center justify-between gap-3">
          {title && (
            <h2 id={headingId} className="text-[0.9375rem] font-semibold">
              {title}
            </h2>
          )}
          {action}
        </header>
      )}
      {children}
    </section>
  );
}
