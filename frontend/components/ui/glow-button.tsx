"use client";
import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { cn } from "@/lib/utils";
import { usePrefersReducedMotion } from "@/lib/hooks/use-prefers-reduced-motion";

type Direction = "TOP" | "LEFT" | "BOTTOM" | "RIGHT";

const movingMap: Record<Direction, string> = {
  TOP: "radial-gradient(20.7% 50% at 50% 0%, var(--accent) 0%, transparent 100%)",
  LEFT: "radial-gradient(16.6% 43.1% at 0% 50%, var(--accent) 0%, transparent 100%)",
  BOTTOM: "radial-gradient(20.7% 50% at 50% 100%, var(--accent) 0%, transparent 100%)",
  RIGHT: "radial-gradient(16.2% 41.2% at 100% 50%, var(--accent) 0%, transparent 100%)",
};
const highlight = "radial-gradient(75% 181% at 50% 50%, var(--accent) 0%, transparent 100%)";

export type GlowButtonProps = React.PropsWithChildren<
    {
      as?: React.ElementType;
      containerClassName?: string;
      className?: string;
      duration?: number;
      clockwise?: boolean;
      href?: string;
      type?: "button" | "submit";
      disabled?: boolean;
  } & React.HTMLAttributes<HTMLElement>
>;

function GlowButton({
  children,
  containerClassName,
  className,
  as: Element = "button",
  duration = 1,
  clockwise = true,
  ...props
}: GlowButtonProps) {
  const [hovered, setHovered] = useState(false);
  const [direction, setDirection] = useState<Direction>("BOTTOM");
  const reduced = usePrefersReducedMotion();

  useEffect(() => {
    if (hovered || reduced) return; // idle rotation is decorative; skip it under reduced motion
    const directions: Direction[] = ["TOP", "LEFT", "BOTTOM", "RIGHT"];
    const interval = setInterval(
      () =>
        setDirection((prev) => {
          const i = directions.indexOf(prev);
          const next = clockwise
            ? (i - 1 + directions.length) % directions.length
            : (i + 1) % directions.length;
          return directions[next];
        }),
      duration * 1000,
    );
    return () => clearInterval(interval);
  }, [hovered, reduced, duration, clockwise]);

  return (
    <Element
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      className={cn(
        "relative flex h-min w-fit flex-nowrap content-center items-center justify-center overflow-visible rounded-full border border-border bg-card/40 p-px backdrop-blur-sm transition-colors duration-500 hover:bg-card/70 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent",
        containerClassName,
      )}
      {...props}
    >
      <div className={cn("z-10 w-auto rounded-[inherit] bg-background px-4 py-2 text-foreground", className)}>
        {children}
      </div>
      <motion.div
        className="absolute inset-0 z-0 flex-none overflow-hidden rounded-[inherit]"
        style={{ filter: "blur(2px)", position: "absolute", width: "100%", height: "100%" }}
        initial={{ background: reduced ? highlight : movingMap[direction] }}
        animate={
          reduced ? undefined : { background: hovered ? [movingMap[direction], highlight] : movingMap[direction] }
        }
        transition={{ ease: "linear", duration }}
      />
      <div className="absolute inset-0.5 z-[1] flex-none rounded-[100px] bg-background" />
    </Element>
  );
}

export default GlowButton;
