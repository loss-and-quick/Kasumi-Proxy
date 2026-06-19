import { Field, SectionLabel } from "../../../components";
import { useT } from "../../../i18n";
import type { FieldErrors } from "../types";

export function RawConfigSection({
  raw,
  onChange,
  errors,
}: {
  raw: string;
  onChange: (value: string) => void;
  errors: FieldErrors;
}) {
  const t = useT();

  return (
    <>
      <SectionLabel>{t("editor.rawConfig")}</SectionLabel>
      <Field
        area
        mono
        value={raw}
        placeholder={t("editor.rawPlaceholder")}
        onChange={onChange}
        error={errors.raw}
      />
    </>
  );
}
