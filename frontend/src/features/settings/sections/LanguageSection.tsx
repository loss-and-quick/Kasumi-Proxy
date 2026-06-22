import { Card, SectionLabel, Select } from "../../../components";
import { type Lang, LOCALES, useT } from "../../../i18n";

export function LanguageSection({ lang, setLang }: { lang: Lang; setLang: (lang: Lang) => void }) {
  const t = useT();

  return (
    <>
      <SectionLabel>{t("settings.language")}</SectionLabel>
      <Card style={{ padding: 14 }}>
        <Select
          value={lang}
          onChange={(v) => setLang(v as Lang)}
          options={Object.entries(LOCALES).map(([code, { label }]) => ({
            value: code,
            label,
          }))}
        />
      </Card>
    </>
  );
}
