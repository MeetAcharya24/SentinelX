import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import GlowButton from "@/components/ui/glow-button";

describe("GlowButton", () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("does not start the idle rotation under reduced motion", () => {
    vi.stubGlobal("matchMedia", vi.fn().mockReturnValue({ matches: true, addEventListener: vi.fn(), removeEventListener: vi.fn() }));
    const interval = vi.spyOn(globalThis, "setInterval");

    render(<GlowButton>Investigate</GlowButton>);

    expect(screen.getByRole("button", { name: "Investigate" })).toBeTruthy();
    const rotation = interval.mock.calls.filter(([, delay]) => delay === 1000);
    expect(rotation).toHaveLength(0);
  });

  it("rotates the highlight every second when motion is allowed", () => {
    vi.stubGlobal("matchMedia", vi.fn().mockReturnValue({ matches: false, addEventListener: vi.fn(), removeEventListener: vi.fn() }));
    const interval = vi.spyOn(globalThis, "setInterval");

    render(<GlowButton>Investigate</GlowButton>);

    expect(interval.mock.calls.filter(([, delay]) => delay === 1000)).toHaveLength(1);
  });
});
