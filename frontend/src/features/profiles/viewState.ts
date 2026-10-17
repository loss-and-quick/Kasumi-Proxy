import { create } from "zustand";
import type { SortMode } from "./types";

/**
 * How the Profiles screen is filtered and sorted. Kept outside the screen so
 * that a trip to another tab, which unmounts it, doesn't throw the view away.
 */
type ProfilesView = {
  /** A group id, or "all". */
  groupFilter: string;
  sort: SortMode;
  query: string;
  searchOpen: boolean;
  /** A profile id to scroll to and highlight when Profiles opens. */
  locateTargetId: string | null;
  setGroupFilter: (groupFilter: string) => void;
  setSort: (sort: SortMode) => void;
  setQuery: (query: string) => void;
  setSearchOpen: (searchOpen: boolean) => void;
  setFilters: (filters: { groupFilter?: string; query?: string }) => void;
  requestLocate: (id: string) => void;
  clearLocate: () => void;
};

export const useProfilesView = create<ProfilesView>()((set) => ({
  groupFilter: "all",
  sort: "name",
  query: "",
  searchOpen: false,
  locateTargetId: null,
  setGroupFilter: (groupFilter) => set({ groupFilter }),
  setSort: (sort) => set({ sort }),
  setQuery: (query) => set({ query }),
  setSearchOpen: (searchOpen) => set({ searchOpen }),
  setFilters: (filters) => set((state) => ({ ...state, ...filters })),
  requestLocate: (id) => set({ locateTargetId: id }),
  clearLocate: () => set({ locateTargetId: null }),
}));
