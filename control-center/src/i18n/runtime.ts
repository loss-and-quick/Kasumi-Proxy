export type Vars = Record<string, string | number>;

export interface I18nFormatters {
  formatDateTime: (value: number | Date, options?: Intl.DateTimeFormatOptions) => string;
  formatList: (values: Iterable<string>, options?: Intl.ListFormatOptions) => string;
  formatNumber: (value: number, options?: Intl.NumberFormatOptions) => string;
}

export interface MessageRuntime {
  formatters: I18nFormatters;
  interpolate: (template: string, vars?: Vars) => string;
  locale: string;
  t: (key: string, vars?: Vars) => string;
}

export type MessageValue = string | ((vars: Vars | undefined, runtime: MessageRuntime) => string);
