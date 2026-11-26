"use client";

import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { SEVERITY_COLOR } from "@/components/ui/severity-tag";
import { SEVERITIES } from "@/lib/api/alerts";
import type { Bucket } from "@/lib/dashboard";

const STACK_ORDER = [...SEVERITIES].reverse(); // low at the base, critical on top

/** Alerts per time bucket, stacked by severity. Static: it only moves when the data does. */
export function ActivityChart({ buckets }: { buckets: Bucket[] }) {
  const total = buckets.reduce((sum, b) => sum + b.critical + b.high + b.medium + b.low, 0);
  return (
    <div role="img" aria-label={`Alerts over time, ${total} in total, stacked by severity`} className="h-56 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={buckets} margin={{ top: 6, right: 8, bottom: 0, left: -18 }}>
          <CartesianGrid stroke="var(--border)" strokeDasharray="2 4" vertical={false} />
          <XAxis dataKey="label" tick={{ fill: "var(--muted-foreground)", fontSize: 11 }} tickLine={false} axisLine={false} minTickGap={24} />
          <YAxis allowDecimals={false} tick={{ fill: "var(--muted-foreground)", fontSize: 11 }} tickLine={false} axisLine={false} />
          <Tooltip
            contentStyle={{ background: "var(--popover)", border: "1px solid var(--border)", borderRadius: 6, fontSize: 12 }}
            labelStyle={{ color: "var(--foreground)" }}
          />
          {STACK_ORDER.map((severity) => (
            <Area
              key={severity}
              type="monotone"
              dataKey={severity}
              name={severity[0].toUpperCase() + severity.slice(1)}
              stackId="alerts"
              stroke={SEVERITY_COLOR[severity]}
              fill={SEVERITY_COLOR[severity]}
              fillOpacity={0.22}
              strokeWidth={1.5}
              isAnimationActive={false}
            />
          ))}
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
