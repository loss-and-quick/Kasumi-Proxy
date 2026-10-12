import { Card, Field, Icon, SectionLabel } from "../../../components";
import { useT } from "../../../i18n";
import type { FieldErrors } from "../types";

export function RawConfigSection({
  raw,
  onChange,
  errors,
  provider,
}: {
  raw: string;
  onChange: (value: string) => void;
  errors: FieldErrors;
  /** A subscription's config: the backend sanitises it, so it isn't edited here. */
  provider: boolean;
}) {
  const t = useT();

  return (
    <>
      <SectionLabel>{t("editor.rawConfig")}</SectionLabel>
      {provider && (
        <Card
          style={{
            display: "flex",
            alignItems: "flex-start",
            gap: 12,
            padding: "10px 16px",
            marginBottom: 10,
            background: "var(--primary-container)",
            border: "1px solid transparent",
            borderRadius: "var(--card-radius)",
          }}
        >
          <Icon
            name="cloud_sync"
            style={{ fontSize: 20, color: "var(--on-primary-container)", marginTop: 1 }}
          />
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontSize: 13, fontWeight: 600, color: "var(--on-primary-container)" }}>
              {t("editor.custom.provider")}
            </div>
            <div
              style={{
                fontSize: 12,
                marginTop: 2,
                color: "var(--on-primary-container-variant)",
              }}
            >
              {t("editor.custom.providerSub")}
            </div>
          </div>
        </Card>
      )}
      <Field
        area
        mono
        value={raw}
        readOnly={provider}
        placeholder={t("editor.rawPlaceholder")}
        onChange={onChange}
        error={errors.raw}
      />
    </>
  );
}
