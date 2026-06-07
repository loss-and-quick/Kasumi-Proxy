import { Card, SectionLabel } from "../../../components";
import { type Lang, LOCALES, useT } from "../../../i18n";

export function LanguageSection({ lang, setLang }: { lang: Lang; setLang: (lang: Lang) => void }) {
  const t = useT();

  return (
    <>
      <SectionLabel>{t("settings.language")}</SectionLabel>
      <Card style={{ padding: 14 }}>
        <select
          className="select-box"
          value={lang}
          onChange={(e) => setLang(e.target.value as Lang)}
        >
          {Object.entries(LOCALES).map(([code, { label }]) => (
            <option key={code} value={code}>
              {label}
            </option>
          ))}
        </select>
      </Card>
    </>
  );
}
