import { useEffect, useState } from "react";
import { type LinkInput, looksLikeJson, resolveLinkInput } from "../../lib/add-input";
import { bridge } from "../../lib/bridge-provider";

/** `text` read as links once typing settles, for sheets that import JSON:
 *  `undefined` while the reading is pending, `null` when it holds no links. */
export function useLinkInput(text: string): LinkInput | null | undefined {
  const [read, setRead] = useState<{ text: string; link: LinkInput | null } | null>(null);
  const skip = !text.trim() || looksLikeJson(text);

  useEffect(() => {
    if (skip) return;
    let alive = true;
    const timer = window.setTimeout(async () => {
      const link = await resolveLinkInput(text, bridge);
      if (alive) setRead({ text, link });
    }, 250);
    return () => {
      alive = false;
      window.clearTimeout(timer);
    };
  }, [text, skip]);

  if (skip) return null;
  return read?.text === text ? read.link : undefined;
}
