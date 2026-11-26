import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import Reveal from "@/components/ui/reveal";

function mockReducedMotion(matches: boolean) {
  vi.stubGlobal(
    "matchMedia",
    vi.fn().mockImplementation(() => ({
      matches,
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
    })),
  );
}

describe("Reveal", () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("applies the delay as a transition delay when motion is allowed", () => {
    mockReducedMotion(false);
    vi.stubGlobal("IntersectionObserver", undefined);

    render(<Reveal delay={120}><p>card</p></Reveal>);

    expect(screen.getByText("card").parentElement!.style.transitionDelay).toBe("120ms");
  });

  it("shows content immediately with no transition timing under reduced motion", () => {
    mockReducedMotion(true);
    vi.stubGlobal("IntersectionObserver", class { observe() {} disconnect() {} });

    render(<Reveal delay={120}><p>card</p></Reveal>);

    const wrapper = screen.getByText("card").parentElement!;
    expect(wrapper.className).toContain("opacity-100");
    expect(wrapper.style.transitionDelay).toBe("");
  });
});
