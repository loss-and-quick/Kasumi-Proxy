import { SectionLabel } from "../../../components";
import { useT } from "../../../i18n";

export function SharePreview({ shareText }: { shareText: string }) {
  const t = useT();

  return (
    <>
      <SectionLabel>{t("editor.sharePreview")}</SectionLabel>
      <div
        style={{
          fontFamily: "var(--font-mono)",
          fontSize: 11,
          color: "var(--on-surface-faint)",
          background: "var(--sc-lowest)",
          padding: 10,
          borderRadius: 10,
          wordBreak: "break-all",
        }}
      >
        {shareText}
      </div>
    </>
  );
}
