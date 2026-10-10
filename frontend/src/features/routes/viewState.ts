// ============================================================
// features/routes/viewState.ts
// Which route the Routing page shows. Kept outside the page so it survives
// leaving Settings, and so other screens (the active profile's route chip on
// Overview, the profile editor) can open the page on a given route.
// ============================================================

import { create } from "zustand";

type RoutesView = {
  /** The route shown; `null` (or one that is gone) shows the default route. */
  routeId: string | null;
  setRouteId: (id: string | null) => void;
};

export const useRoutesView = create<RoutesView>((set) => ({
  routeId: null,
  setRouteId: (routeId) => set({ routeId }),
}));

/** Open Settings → Routing on `routeId`. */
export function openRoute(routeId: string) {
  useRoutesView.setState({ routeId });
  window.location.hash = "settings/routing";
}
