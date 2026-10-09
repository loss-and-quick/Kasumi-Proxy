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
  setGroupFilter: (groupFilter: string) => void;
  setSort: (sort: SortMode) => void;
  setQuery: (query: string) => void;
  setSearchOpen: (searchOpen: boolean) => void;
};

export const useProfilesView = create<ProfilesView>()((set) => ({
  groupFilter: "all",
  sort: "name",
  query: "",
  searchOpen: false,
  setGroupFilter: (groupFilter) => set({ groupFilter }),
  setSort: (sort) => set({ sort }),
  setQuery: (query) => set({ query }),
  setSearchOpen: (searchOpen) => set({ searchOpen }),
}));
