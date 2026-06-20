import { useSyncExternalStore } from "react";

// Desktop breakpoint — kept in lock-step with the @media (min-width: 900px)
// rules in globals.css. Above it the shell switches to a side rail + wide
// layout; below it the mobile bottom-nav layout. Reacts to live window resize.
const QUERY = "(min-width: 900px)";

export function useIsWide(): boolean {
  return useSyncExternalStore(
    (onChange) => {
      const mq = window.matchMedia(QUERY);
      mq.addEventListener("change", onChange);
      return () => mq.removeEventListener("change", onChange);
    },
    () => window.matchMedia(QUERY).matches,
    () => false,
  );
}
