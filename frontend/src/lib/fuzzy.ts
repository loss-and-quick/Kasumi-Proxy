// ============================================================
// lib/fuzzy.ts
// Lightweight fuzzy subsequence matching with relevance scoring.
// Used to filter + rank lists (apps, profiles) as the user types.
// ============================================================

const SEPARATORS = new Set([" ", ".", "-", "_", "/", ":", "@"]);

/**
 * Score returned when `query` is not a subsequence of the text. Distinct from
 * any real match score, which can be negative due to gap penalties — so callers
 * must test `score > NO_MATCH` rather than `score >= 0` to decide a match.
 */
export const NO_MATCH = Number.NEGATIVE_INFINITY;

/**
 * Fuzzy-match `query` against `text` as a subsequence and return a relevance
 * score (higher = better match) or `NO_MATCH` if not all query characters are
 * found in order. An empty query returns `0` (matches everything, neutral
 * score). Note: a real match may still score below `0` because of gap
 * penalties; use `score > NO_MATCH` to test for a match.
 *
 * Scoring favours: matches at the start of the text, matches right after a
 * separator (word boundary), and consecutive matches; gaps are penalised.
 */
export function fuzzyScore(text: string, query: string): number {
  const q = query.trim().toLowerCase();
  if (!q) return 0;
  const t = text.toLowerCase();

  let score = 0;
  let qi = 0;
  let prevMatch = -2; // index of previous matched char in `t`

  for (let ti = 0; ti < t.length && qi < q.length; ti++) {
    if (t[ti] !== q[qi]) continue;

    let bonus = 1;
    if (ti === 0) {
      bonus += 5; // very start of the string
    } else if (SEPARATORS.has(t[ti - 1])) {
      bonus += 4; // start of a word
    }
    if (ti === prevMatch + 1) {
      bonus += 3; // consecutive with previous match
    } else if (prevMatch >= 0) {
      bonus -= Math.min(3, ti - prevMatch - 1); // gap penalty (capped)
    }

    score += bonus;
    prevMatch = ti;
    qi++;
  }

  return qi === q.length ? score : NO_MATCH;
}

/**
 * Filter `items` to those matching `query` and sort by descending relevance.
 * With an empty query the original order is preserved. `getText` extracts the
 * searchable haystack for an item. The sort is stable for equal scores.
 */
export function fuzzyFilterSort<T>(
  items: readonly T[],
  query: string,
  getText: (item: T) => string,
): T[] {
  if (!query.trim()) return [...items];
  const scored: { item: T; score: number; index: number }[] = [];
  items.forEach((item, index) => {
    const score = fuzzyScore(getText(item), query);
    if (score > NO_MATCH) scored.push({ item, score, index });
  });
  scored.sort((a, b) => b.score - a.score || a.index - b.index);
  return scored.map((s) => s.item);
}
