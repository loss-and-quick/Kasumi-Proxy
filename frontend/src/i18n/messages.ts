import type { MessageRuntime, MessageValue, Vars } from "./runtime";

export type PluralForms = Partial<Record<Intl.LDMLPluralRule | "zero", string>> & {
  other: string;
};

export type SelectForms = Record<string, string> & {
  other: string;
};

function numericVar(vars: Vars | undefined, name: string): number {
  const raw = vars?.[name];
  return typeof raw === "number" ? raw : Number(raw ?? 0);
}

export function pluralPart(
  value: number,
  forms: PluralForms,
  runtime: MessageRuntime,
  numberOptions?: Intl.NumberFormatOptions,
): string {
  const category =
    value === 0 && forms.zero ? "zero" : new Intl.PluralRules(runtime.locale).select(value);
  const template = forms[category] ?? forms.other;
  const count = runtime.formatters.formatNumber(value, numberOptions);
  return runtime.interpolate(template.split("#").join(count), { count: value });
}

export function selectPart(value: string, forms: SelectForms, runtime: MessageRuntime): string {
  return runtime.interpolate(forms[value] ?? forms.other, { value });
}

export function plural(
  name: string,
  forms: PluralForms,
  numberOptions?: Intl.NumberFormatOptions,
): MessageValue {
  return (vars, runtime) => pluralPart(numericVar(vars, name), forms, runtime, numberOptions);
}

export function select(name: string, forms: SelectForms): MessageValue {
  return (vars, runtime) => selectPart(String(vars?.[name] ?? "other"), forms, runtime);
}
