"use client";
import type { ReactNode } from "react";
import { useEffect, useRef, useState } from "react";
import { cn } from "@/lib/utils";
import { usePrefersReducedMotion } from "@/lib/hooks/use-prefers-reduced-motion";

function useInView<T extends Element>(threshold = 0.2) {
  const ref = useRef<T>(null);
  const [inView, setInView] = useState(false);

  useEffect(() => {
    const node = ref.current;
    if (!node || inView) return;

    const box = node.getBoundingClientRect();
    const onScreen =
      box.top < window.innerHeight && box.bottom > 0 && box.width + box.height > 0;
    if (onScreen || typeof IntersectionObserver === "undefined") {
      setInView(true);
      return;
    }

    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setInView(true);
          observer.disconnect();
        }
      },
      { threshold },
    );
    observer.observe(node);
    return () => observer.disconnect();
  }, [threshold, inView]);

  return { ref, inView };
}

export type RevealDirection = "up" | "down" | "left" | "right" | "none";

const HIDDEN: Record<RevealDirection, string> = {
  up: "translate-y-4",
  down: "-translate-y-4",
  left: "translate-x-4",
  right: "-translate-x-4",
  none: "",
};

export interface RevealProps {
  children: ReactNode;
  direction?: RevealDirection;
  delay?: number;
  duration?: number;
  className?: string;
}

function Reveal({ children, direction = "up", delay = 0, duration = 500, className }: RevealProps) {
  const { ref, inView } = useInView<HTMLDivElement>();
  const reduced = usePrefersReducedMotion();
  const shown = inView || reduced;

  return (
    <div
      ref={ref}
      style={reduced ? undefined : { transitionDuration: `${duration}ms`, transitionDelay: `${delay}ms` }}
      className={cn(
        "transition-all ease-out",
        shown ? "translate-x-0 translate-y-0 opacity-100" : cn("opacity-0", HIDDEN[direction]),
        className,
      )}
    >
      {children}
    </div>
  );
}

export default Reveal;

/** Stagger step for cascading groups: item index × 60 ms. */
export const STAGGER_MS = 60;
export const staggerDelay = (index: number) => index * STAGGER_MS;
