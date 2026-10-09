import { beforeEach, describe, expect, it, vi } from "vitest";

// A minimal session history: pushState drops forward entries, go() lands a
// tick later and fires popstate, the way browsers traverse.
function fakeHistory() {
  const entries: unknown[] = [null];
  let index = 0;
  const listeners = new Set<() => void>();
  const history = {
    get state() {
      return entries[index];
    },
    /** 1-based place of the current entry. */
    get position() {
      return index + 1;
    },
    pushState(state: unknown) {
      entries.splice(index + 1);
      entries.push(state);
      index += 1;
    },
    go(delta: number) {
      setTimeout(() => {
        index = Math.max(0, index + delta);
        for (const l of listeners) l();
      });
    },
    back() {
      history.go(-1);
    },
  };
  return { history, listeners };
}

// Our pops are queued in a microtask and then traverse a tick later.
const settle = () => new Promise((resolve) => setTimeout(resolve, 5));

let openOverlay: typeof import("../useEscapeToClose").openOverlay;
let nav: ReturnType<typeof fakeHistory>;

beforeEach(async () => {
  vi.resetModules();
  nav = fakeHistory();
  vi.stubGlobal("window", {
    history: nav.history,
    addEventListener: (type: string, l: () => void) => type === "popstate" && nav.listeners.add(l),
    removeEventListener: (type: string, l: () => void) =>
      type === "popstate" && nav.listeners.delete(l),
  });
  vi.stubGlobal("document", { addEventListener: () => {}, removeEventListener: () => {} });
  ({ openOverlay } = await import("../useEscapeToClose"));
});

describe("overlay history", () => {
  it("an open overlay adds a history entry, and closing it takes the entry off", async () => {
    const dispose = openOverlay(() => {});
    expect(nav.history.position).toBe(2);
    dispose();
    await settle();
    expect(nav.history.position).toBe(1);
  });

  it("Back closes only the top overlay and keeps the one under it", async () => {
    const lower = vi.fn();
    const upper = vi.fn();
    openOverlay(lower);
    const disposeUpper = openOverlay(upper);
    nav.history.back();
    await settle();
    expect(upper).toHaveBeenCalledTimes(1);
    expect(lower).not.toHaveBeenCalled();
    // The overlay closes in response, which pops its entry for good.
    disposeUpper();
    await settle();
    expect(nav.history.position).toBe(2);
  });

  it("an overlay that refuses to close keeps its entry", async () => {
    const close = vi.fn(); // e.g. the editor asking about unsaved changes
    openOverlay(close);
    nav.history.back();
    await settle();
    expect(close).toHaveBeenCalledTimes(1);
    expect(nav.history.position).toBe(2);
    // A second Back asks again.
    nav.history.back();
    await settle();
    expect(close).toHaveBeenCalledTimes(2);
  });

  it("two overlays closing together take both entries off", async () => {
    const a = openOverlay(() => {});
    const b = openOverlay(() => {});
    b();
    a();
    await settle();
    expect(nav.history.position).toBe(1);
  });

  it("one overlay closing as another opens reuses the entry", async () => {
    const add = openOverlay(() => {});
    add();
    openOverlay(() => {});
    await settle();
    expect(nav.history.position).toBe(2);
  });

  it("an overlay closed after navigating elsewhere leaves that navigation alone", async () => {
    const dispose = openOverlay(() => {});
    nav.history.pushState(null); // a tab switch sets a new hash
    dispose();
    await settle();
    expect(nav.history.position).toBe(3);
  });

  it("history: false registers for Escape only", async () => {
    openOverlay(() => {}, { history: false });
    expect(nav.history.position).toBe(1);
  });
});
