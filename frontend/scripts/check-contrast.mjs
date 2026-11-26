// WCAG 2.x contrast check for the colour tokens in app/globals.css.
// Run: npm run contrast. Exits 1 if any text pair is under 4.5:1.
import { readFileSync } from "node:fs";

const css = readFileSync(new URL("../app/globals.css", import.meta.url), "utf8");
const root = css.slice(css.indexOf(":root {"), css.indexOf("@layer base"));
const tokens = Object.fromEntries(
  [...root.matchAll(/--([\w-]+):\s*(#[0-9a-fA-F]{6})/g)].map(([, name, hex]) => [name, hex]),
);

const channel = (v) => {
  const s = v / 255;
  return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
};
const luminance = (hex) => {
  const n = parseInt(hex.slice(1), 16);
  return 0.2126 * channel(n >> 16) + 0.7152 * channel((n >> 8) & 255) + 0.0722 * channel(n & 255);
};
const ratio = (a, b) => {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
};

const surfaces = ["background", "card", "plate-raised", "popover", "secondary", "sidebar"];
const text = [];
for (const surface of surfaces) {
  text.push(["foreground", surface], ["muted-foreground", surface], ["accent", surface]);
}
for (const sev of ["critical", "high", "medium", "low"]) {
  text.push([`sev-${sev}`, `sev-${sev}-bg`]);
  for (const surface of ["background", "card", "plate-raised", "secondary"]) {
    text.push([`sev-${sev}`, surface]);
  }
}
text.push(
  ["primary-foreground", "primary"],
  ["accent-foreground", "accent"],
  ["destructive", "card"],
  ["foreground", "primary"],
);
// Non-text: component boundaries and focus ring need 3:1 (WCAG 1.4.11).
const nonText = [
  ["input", "card"],
  ["ring", "background"],
  ["ring", "card"],
];

let failed = 0;
const report = (kind, min, pairs) => {
  for (const [fg, bg] of pairs) {
    if (!tokens[fg] || !tokens[bg]) throw new Error(`Unknown token in pair ${fg} / ${bg}`);
    const value = ratio(tokens[fg], tokens[bg]);
    const ok = value >= min;
    if (!ok) failed += 1;
    console.log(`${ok ? "pass" : "FAIL"}  ${kind}  ${value.toFixed(2)}:1  ${fg} ${tokens[fg]} on ${bg} ${tokens[bg]}`);
  }
};
report("text", 4.5, text);
report("ui  ", 3, nonText);
console.log(failed === 0 ? "\nAll pairs pass." : `\n${failed} pair(s) below threshold.`);
process.exit(failed === 0 ? 0 : 1);
