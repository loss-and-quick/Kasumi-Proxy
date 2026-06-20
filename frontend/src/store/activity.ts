// ============================================================
// store/activity.ts
// In-memory activity feed.  Each entry is pushed by store actions;
// the feed is capped so it never grows unboundedly.
// ============================================================

export interface ActivityEvent {
  /** Material icon name */
  icon: string;
  /** Optional tint; falls back to var(--on-surface-variant) */
  color?: string;
  /** Human-readable description (already translated at push time) */
  text: string;
  /** Unix timestamp set automatically by ActivityService.add() */
  at: number;
}

const MAX_EVENTS = 10;

export class ActivityService {
  private events: ActivityEvent[] = [];

  add(icon: string, text: string, color?: string): ActivityEvent[] {
    const entry: ActivityEvent = { icon, color, text, at: Date.now() };
    this.events = [entry, ...this.events].slice(0, MAX_EVENTS);
    return this.events;
  }

  snapshot(): ActivityEvent[] {
    return this.events;
  }
}
