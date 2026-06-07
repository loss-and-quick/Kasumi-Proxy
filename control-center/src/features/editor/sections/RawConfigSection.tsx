import { Field, SectionLabel } from "../../../components";
import { useT } from "../../../i18n";
import type { FieldErrors, ProfileSetter, ProfileView } from "../types";

export function RawConfigSection({
  v,
  set,
  errors,
}: {
  v: ProfileView;
  set: ProfileSetter;
  errors: FieldErrors;
}) {
  const t = useT();

  return (
    <>
      <SectionLabel>{t("editor.rawConfig")}</SectionLabel>
      <Field
        area
        mono
        value={v.raw ?? ""}
        placeholder={t("editor.rawPlaceholder")}
        onChange={(value) => set({ raw: value })}
        error={errors.raw}
      />
    </>
  );
}
