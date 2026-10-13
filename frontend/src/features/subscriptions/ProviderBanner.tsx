import { type CSSProperties, type ReactNode, useLayoutEffect, useRef, useState } from "react";
import { Btn, Icon } from "../../components";
import type { NoticeColor, ProviderInfo } from "../../generated/bindings";
import { useT } from "../../i18n";

const ANNOUNCE_LINES = 4;

// Provider colours map onto the app's container roles, never raw hues.
const NOTICE_TONE: Record<NoticeColor, { bg: string; fg: string; icon: string }> = {
  red: { bg: "var(--error-container)", fg: "var(--on-error-container)", icon: "var(--error)" },
  blue: {
    bg: "var(--primary-container)",
    fg: "var(--on-primary-container)",
    icon: "var(--primary)",
  },
  green: {
    bg: "var(--running-container)",
    fg: "var(--on-running-container)",
    icon: "var(--running)",
  },
  default: { bg: "var(--sc)", fg: "var(--on-surface)", icon: "var(--on-surface-variant)" },
};

// Provider text may be right-to-left whatever the UI language is.
const providerText: CSSProperties = {
  whiteSpace: "pre-wrap",
  unicodeBidi: "plaintext",
  overflowWrap: "anywhere",
  fontSize: 13,
  lineHeight: 1.45,
};

function Banner({
  icon,
  tone,
  children,
  action,
}: {
  icon: string;
  tone: { bg: string; fg: string; icon: string };
  children: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: 10,
        padding: "10px 12px",
        background: tone.bg,
        color: tone.fg,
        border: "1px solid transparent",
        borderRadius: 12,
      }}
    >
      <Icon
        name={icon}
        // Beside a button the row is button-high; alone, the icon heads the text.
        style={{
          fontSize: 18,
          color: tone.icon,
          flexShrink: 0,
          alignSelf: action ? "center" : "flex-start",
          marginTop: action ? 0 : 1,
        }}
      />
      <div style={{ flex: 1, minWidth: 0 }}>{children}</div>
      {action && <div style={{ flexShrink: 0 }}>{action}</div>}
    </div>
  );
}

function Announcement({ text }: { text: string }) {
  const t = useT();
  const ref = useRef<HTMLDivElement>(null);
  const [open, setOpen] = useState(false);
  const [clamped, setClamped] = useState(false);
  // biome-ignore lint/correctness/useExhaustiveDependencies: re-measure when the text changes.
  useLayoutEffect(() => {
    const el = ref.current;
    if (el && !open) setClamped(el.scrollHeight > el.clientHeight + 1);
  }, [text, open]);
  return (
    <Banner icon="campaign" tone={NOTICE_TONE.default}>
      <div
        ref={ref}
        dir="auto"
        style={{
          ...providerText,
          ...(open
            ? {}
            : {
                display: "-webkit-box",
                WebkitBoxOrient: "vertical",
                WebkitLineClamp: ANNOUNCE_LINES,
                overflow: "hidden",
              }),
        }}
      >
        {text}
      </div>
      {(clamped || open) && (
        <button
          type="button"
          className="btn-reset"
          onClick={() => setOpen((o) => !o)}
          style={{ marginTop: 4, fontSize: 12.5, fontWeight: 500, color: "var(--primary)" }}
        >
          {open ? t("subs.provider.showLess") : t("subs.provider.showMore")}
        </button>
      )}
    </Banner>
  );
}

/** The provider's notice, announcement and expiry, above the subscription's URL. */
export function ProviderBanners({
  provider,
  expired,
  onOpen,
}: {
  provider: ProviderInfo;
  /** The provider said so, or the expiry date has passed. */
  expired: boolean;
  onOpen: (url: string) => void;
}) {
  const t = useT();
  const { notice, announce, renewUrl } = provider;
  if (!notice && !announce && !expired) return null;
  const tone = NOTICE_TONE[notice?.color ?? "default"];
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8, marginTop: 12 }}>
      {expired && (
        <Banner
          icon="event"
          tone={NOTICE_TONE.red}
          action={
            renewUrl ? (
              <Btn variant="tonal" sm onClick={() => onOpen(renewUrl)}>
                {t("subs.provider.renew")}
              </Btn>
            ) : undefined
          }
        >
          <div style={{ fontSize: 13, lineHeight: 1.45 }}>{t("subs.provider.expiredBanner")}</div>
        </Banner>
      )}
      {notice && (
        <Banner
          icon="info"
          tone={tone}
          action={
            notice.buttonUrl ? (
              <Btn
                // A tonal button would vanish into the blue container.
                variant={notice.color === "blue" ? "filled" : "tonal"}
                sm
                onClick={() => notice.buttonUrl && onOpen(notice.buttonUrl)}
              >
                <span dir="auto" className="truncate" style={{ maxWidth: 140 }}>
                  {notice.buttonText || t("subs.provider.open")}
                </span>
              </Btn>
            ) : undefined
          }
        >
          <div dir="auto" style={providerText}>
            {notice.text}
          </div>
        </Banner>
      )}
      {announce && <Announcement text={announce} />}
    </div>
  );
}
