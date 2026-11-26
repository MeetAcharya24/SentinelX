import type { InputHTMLAttributes, SelectHTMLAttributes } from "react";
import { cn } from "@/lib/utils";

const FIELD =
  "h-9 rounded-md border border-input bg-card px-3 text-sm text-foreground placeholder:text-muted-foreground";

export function Select({
  label,
  className,
  children,
  ...props
}: SelectHTMLAttributes<HTMLSelectElement> & { label: string }) {
  return (
    <label className="flex items-center gap-2 text-sm text-muted-foreground">
      <span>{label}</span>
      <select {...props} className={cn(FIELD, "min-w-0 pr-7", className)}>
        {children}
      </select>
    </label>
  );
}

export function TextInput({
  label,
  className,
  ...props
}: InputHTMLAttributes<HTMLInputElement> & { label: string }) {
  return (
    <label className="flex items-center gap-2 text-sm text-muted-foreground">
      <span className="sr-only">{label}</span>
      <input {...props} aria-label={label} className={cn(FIELD, "w-full", className)} />
    </label>
  );
}
