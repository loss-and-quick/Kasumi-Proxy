// ============================================================
// i18n/index.ts
// Minimal i18n engine: registry, translate fn, React context/hook.
// No external deps. Fallback chain: lang → en → raw key.
// Lang stored in localStorage("kasumi-proxy.lang"), default from browser.
// Non-English locale dictionaries are lazy-loaded to keep the initial
// bundle smaller.
// ============================================================
import {
  createContext,
  createElement,
  type ReactNode,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";
import en from "./en";
import type { I18nFormatters, MessageRuntime, MessageValue, Vars } from "./runtime";
import type { Dict, DictKey } from "./types";

type LocaleModule = { default: Partial<Dict> };
type LocaleCache = Partial<Record<Lang, Partial<Dict>>>;
type LocaleLoader = () => Promise<LocaleModule>;

// ---- locale registry -----------------------------------------
// Single source of truth: add a locale here (autonym label + BCP-47 tag +
// lazy loader) and it is wired everywhere — `Lang`, browser-language detection,
// translation lookup, formatters, and the language picker all derive from it.
export interface LocaleMeta {
  label: string;
  load: LocaleLoader;
  tag: string;
}

export const LOCALES = {
  ar: { label: "العربية", load: () => import("./ar"), tag: "ar" },
  en: { label: "English", load: async () => ({ default: en }), tag: "en" },
  es: { label: "Español", load: () => import("./es"), tag: "es" },
  hi: { label: "हिन्दी", load: () => import("./hi"), tag: "hi" },
  pt: { label: "Português", load: () => import("./pt"), tag: "pt" },
  ru: { label: "Русский", load: () => import("./ru"), tag: "ru" },
  vi: { label: "Tiếng Việt", load: () => import("./vi"), tag: "vi" },
  zh: { label: "简体中文", load: () => import("./zh"), tag: "zh" },
} as const satisfies Record<string, LocaleMeta>;

export type Lang = keyof typeof LOCALES;

const DEFAULT_LANG: Lang = "en";
const LANG_STORAGE_KEY = "kasumi-proxy.lang";
const DICT_CACHE: LocaleCache = { en };

function isLang(value: string): value is Lang {
  return value in LOCALES;
}

export function resolvePreferredLang(candidates: readonly string[]): Lang | null {
  for (const rawCandidate of candidates) {
    const candidate = rawCandidate.toLowerCase();
    if (isLang(candidate)) return candidate;

    const base = candidate.split("-")[0];
    if (isLang(base)) return base;
  }

  return null;
}

function detectBrowserLang(): Lang | null {
  if (typeof navigator === "undefined") return null;

  return resolvePreferredLang([navigator.language, ...(navigator.languages ?? [])].filter(Boolean));
}

function detectLang(): Lang {
  try {
    const stored = localStorage.getItem(LANG_STORAGE_KEY);
    if (stored && isLang(stored)) return stored;
  } catch {
    // SSR / restricted env — fall through
  }

  return detectBrowserLang() ?? DEFAULT_LANG;
}

// ---- translate -----------------------------------------------

function interpolate(template: string, vars?: Vars): string {
  if (!vars) return template;
  return template.replace(/\{(\w+)\}/g, (_, k) => (k in vars ? String(vars[k]) : `{${k}}`));
}

function createFormatters(lang: Lang): I18nFormatters {
  const locale = LOCALES[lang].tag;

  return {
    formatDateTime: (value, options) =>
      new Intl.DateTimeFormat(locale, {
        dateStyle: "medium",
        timeStyle: "short",
        ...options,
      }).format(value instanceof Date ? value : new Date(value)),
    formatList: (values, options) =>
      new Intl.ListFormat(locale, {
        style: "short",
        type: "conjunction",
        ...options,
      }).format(Array.from(values)),
    formatNumber: (value, options) => new Intl.NumberFormat(locale, options).format(value),
  };
}

function createRuntime(lang: Lang, dicts: LocaleCache): MessageRuntime {
  const formatters = createFormatters(lang);
  return {
    formatters,
    interpolate,
    locale: LOCALES[lang].tag,
    t: (key, vars) => translateWithDicts(lang, key as DictKey, vars, dicts),
  };
}

function renderMessage(
  message: MessageValue,
  vars: Vars | undefined,
  runtime: MessageRuntime,
): string {
  return typeof message === "function"
    ? message(vars, runtime)
    : runtime.interpolate(message, vars);
}

function translateWithDicts(
  lang: Lang,
  key: DictKey,
  vars: Vars | undefined,
  dicts: LocaleCache,
): string {
  const raw = dicts[lang]?.[key] ?? en[key] ?? key;
  if (typeof raw === "string" && raw === key && !vars) return raw;
  return renderMessage(raw as MessageValue, vars, createRuntime(lang, dicts));
}

export async function loadLocale(lang: Lang): Promise<Partial<Dict>> {
  const cached = DICT_CACHE[lang];
  if (cached) return cached;

  const { default: dict } = await LOCALES[lang].load();
  DICT_CACHE[lang] = dict;
  return dict;
}

export function translate(lang: Lang, key: DictKey, vars?: Vars): string {
  return translateWithDicts(lang, key, vars, DICT_CACHE);
}

export function translateCurrent(key: DictKey, vars?: Vars): string {
  const lang = detectLang();
  if (!DICT_CACHE[lang]) {
    void loadLocale(lang);
  }
  return translate(lang, key, vars);
}

// ---- context -------------------------------------------------

interface I18nCtx {
  formatters: I18nFormatters;
  lang: Lang;
  setLang: (l: Lang) => void;
  t: (key: DictKey, vars?: Vars) => string;
}

export type Translate = I18nCtx["t"];

const I18nContext = createContext<I18nCtx>({
  formatters: createFormatters(DEFAULT_LANG),
  lang: DEFAULT_LANG,
  setLang: () => {},
  t: (key) => key,
});

// ---- provider ------------------------------------------------

export function I18nProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<Lang>(detectLang);
  const [dicts, setDicts] = useState<LocaleCache>(() => ({ ...DICT_CACHE }));

  const syncLoadedLocale = useCallback((targetLang: Lang, dict: Partial<Dict>) => {
    setDicts((current) =>
      current[targetLang] === dict ? current : { ...current, [targetLang]: dict },
    );
  }, []);

  useEffect(() => {
    let cancelled = false;

    void loadLocale(lang).then((dict) => {
      if (!cancelled) syncLoadedLocale(lang, dict);
    });

    return () => {
      cancelled = true;
    };
  }, [lang, syncLoadedLocale]);

  const setLang = useCallback(
    (nextLang: Lang) => {
      setLangState(nextLang);
      try {
        localStorage.setItem(LANG_STORAGE_KEY, nextLang);
      } catch {
        /* ignore */
      }

      void loadLocale(nextLang).then((dict) => syncLoadedLocale(nextLang, dict));
    },
    [syncLoadedLocale],
  );

  const t = useCallback(
    (key: DictKey, vars?: Vars) => translateWithDicts(lang, key, vars, dicts),
    [dicts, lang],
  );
  const formatters = useMemo(() => createFormatters(lang), [lang]);

  const ctx = useMemo<I18nCtx>(
    () => ({ formatters, lang, setLang, t }),
    [formatters, lang, setLang, t],
  );

  return createElement(I18nContext.Provider, { value: ctx }, children);
}

// ---- hook ----------------------------------------------------

export function useT(): (key: DictKey, vars?: Vars) => string {
  return useContext(I18nContext).t;
}

export function useLang(): { lang: Lang; setLang: (l: Lang) => void } {
  const { lang, setLang } = useContext(I18nContext);
  return { lang, setLang };
}

export function useFormatters(): I18nFormatters {
  return useContext(I18nContext).formatters;
}

export function useI18n(): I18nCtx {
  return useContext(I18nContext);
}

export type { I18nFormatters, MessageRuntime, MessageValue, Vars } from "./runtime";
export type { Dict, DictKey } from "./types";
