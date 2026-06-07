import { profileAddress, profilePort, profileSearchText } from "../lib/profile";
import type { Profile } from "../lib/schema";

export function profileFilterRegex(filter: string): RegExp | null {
  const trimmed = filter.trim();
  if (!trimmed) return null;

  let source = trimmed;
  let flags = "";
  if (source.startsWith("(?i)")) {
    source = source.slice(4);
    flags += "i";
  }

  try {
    return new RegExp(source, flags);
  } catch {
    return null;
  }
}

export function profileMatchesFilter(profile: Profile, filter: RegExp | null): boolean {
  if (!filter) return true;

  const haystack = [
    profileSearchText(profile),
    "uuid" in profile ? profile.uuid : "",
    "password" in profile ? profile.password : "",
  ].join(" ");

  return filter.test(haystack);
}

export function sameProfileIdentity(a: Profile, b: Profile): boolean {
  return (
    a.protocol === b.protocol &&
    profileAddress(a) === profileAddress(b) &&
    profilePort(a) === profilePort(b) &&
    a.remarks === b.remarks
  );
}
