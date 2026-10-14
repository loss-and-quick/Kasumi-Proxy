// ============================================================
// features/profiles/ProfilePicker.tsx
// Choosing one profile out of possibly hundreds, many sharing a name: a
// full-height sheet with search, the profiles under their groups in the
// Profiles screen's order, each row with its protocol, host:port and ping.
// ============================================================

import { type ReactNode, useDeferredValue, useMemo, useRef, useState } from "react";
import { BesideSheet, Icon, Ping, SectionLabel, Sheet } from "../../components";
import type { Group, Profile } from "../../generated/bindings";
import { useT } from "../../i18n";
import { fuzzyFilterSort, fuzzyScore, NO_MATCH } from "../../lib/fuzzy";
import { profileSearchText } from "../../lib/profile-utils";
import { useIsWide } from "../../lib/useIsWide";
import { type ProfileTest, useAppStore } from "../../store/useAppStore";
import { useProfileLabels } from "./labels";
import { groupSections, useOrderedProfiles } from "./order";
import { ProfileMetaLine } from "./ProfileRow";

/** A choice listed above the profiles, such as a built-in outbound. */
export type PickerChoice = { value: string; label: string; icon: string };

export type PickerSection = { group: Pick<Group, "id" | "name">; profiles: Profile[] };

/** What a search leaves, under its groups; matches rank best first, as on the Profiles screen. */
export function pickerSections(
  profiles: Profile[],
  groups: Pick<Group, "id" | "name">[],
  query: string,
): PickerSection[] {
  const found = query.trim() ? fuzzyFilterSort(profiles, query, profileSearchText) : profiles;
  return groupSections(found, groups);
}

export function ProfilePickerList({
  sections,
  choices,
  value,
  tests,
  blocked,
  onPick,
}: {
  sections: PickerSection[];
  choices: PickerChoice[];
  value: string;
  tests: Record<string, Pick<ProfileTest, "ping">>;
  /** Profiles shown but not pickable, each with why. */
  blocked?: ReadonlyMap<string, string>;
  onPick: (value: string) => void;
}) {
  const t = useT();
  return (
    <div role="listbox">
      {choices.map((choice) => (
        <PickerRow
          key={choice.value}
          selected={choice.value === value}
          onClick={() => onPick(choice.value)}
        >
          <Icon name={choice.icon} className="picker-row-icon" />
          <span className="picker-row-text picker-row-name truncate">{choice.label}</span>
        </PickerRow>
      ))}
      {sections.map(({ group, profiles }) => (
        <div key={group.id}>
          <SectionLabel action={<span className="group-count">{profiles.length}</span>}>
            {group.name}
          </SectionLabel>
          {profiles.map((p) => {
            const selected = p.meta.id === value;
            const ping = tests[p.meta.id]?.ping;
            const why = selected ? undefined : blocked?.get(p.meta.id);
            return (
              <PickerRow
                key={p.meta.id}
                selected={selected}
                disabled={why != null}
                onClick={() => onPick(p.meta.id)}
              >
                <span className="picker-row-text">
                  <span className="picker-row-name truncate" dir="auto">
                    {p.meta.remarks}
                  </span>
                  <ProfileMetaLine profile={p} active={selected} />
                  {why && <span className="picker-row-why">{why}</span>}
                </span>
                {ping != null && <Ping value={ping} />}
              </PickerRow>
            );
          })}
        </div>
      ))}
      {sections.length === 0 && choices.length === 0 && (
        <div className="select-empty">{t("common.noMatches")}</div>
      )}
    </div>
  );
}

function PickerRow({
  selected,
  disabled,
  onClick,
  children,
}: {
  selected: boolean;
  disabled?: boolean;
  onClick: () => void;
  children: ReactNode;
}) {
  return (
    <button
      type="button"
      role="option"
      aria-selected={selected}
      disabled={disabled}
      className={`btn-reset picker-row${selected ? " selected" : ""}`}
      onClick={onClick}
    >
      {children}
      {selected && <Icon name="check_circle" className="picker-check" />}
    </button>
  );
}

export function ProfilePickerSheet({
  title,
  value,
  choices = [],
  only,
  blocked,
  onPick,
  onClose,
}: {
  title?: string;
  value: string;
  choices?: PickerChoice[];
  /** Offer just these profiles (e.g. the ones a chain may go through). */
  only?: ReadonlySet<string>;
  /** Profiles shown but not pickable, each with why (e.g. a core conflict). */
  blocked?: ReadonlyMap<string, string>;
  onPick: (value: string) => void;
  onClose: () => void;
}) {
  const t = useT();
  const isWide = useIsWide();
  const ordered = useOrderedProfiles();
  const groups = useAppStore((s) => s.groups);
  const tests = useAppStore((s) => s.testResults);
  const [query, setQuery] = useState("");
  // Typing stays responsive while a long list filters behind it.
  const deferred = useDeferredValue(query);
  const sections = useMemo(
    () =>
      pickerSections(only ? ordered.filter((p) => only.has(p.meta.id)) : ordered, groups, deferred),
    [ordered, only, groups, deferred],
  );
  const shownChoices = deferred.trim()
    ? choices.filter((c) => fuzzyScore(c.label, deferred) > NO_MATCH)
    : choices;

  // Open on the current pick, which may sit hundreds of rows down. A callback
  // ref, because the list mounts only once the sheet has a place beside its host.
  const scrolled = useRef(false);
  const onListMounted = (el: HTMLDivElement | null) => {
    if (!el || scrolled.current) return;
    scrolled.current = true;
    // Only the sheet's body scrolls: scrollIntoView would also shift the
    // containers the sheet is positioned in.
    const row = el.querySelector<HTMLElement>('[aria-selected="true"]');
    const body = el.closest<HTMLElement>(".sheet-body");
    if (row && body)
      body.scrollTop = row.offsetTop - body.offsetTop - (body.clientHeight - row.offsetHeight) / 2;
  };

  return (
    <BesideSheet>
      <Sheet open full title={title ?? t("profilePicker.title")} onClose={onClose}>
        <div className="picker-search">
          <Icon name="search" />
          <input
            className="input"
            type="search"
            // A phone keyboard would cover the list the sheet just scrolled to.
            // biome-ignore lint/a11y/noAutofocus: on a desktop the filter is the way in
            autoFocus={isWide}
            value={query}
            placeholder={t("profiles.searchPlaceholder")}
            aria-label={t("profiles.searchPlaceholder")}
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>
        <div ref={onListMounted}>
          <ProfilePickerList
            sections={sections}
            choices={shownChoices}
            value={value}
            tests={tests}
            blocked={blocked}
            onPick={(next) => {
              onPick(next);
              onClose();
            }}
          />
        </div>
      </Sheet>
    </BesideSheet>
  );
}

/** The field showing the current pick; a profile is named apart from its namesakes. */
export function ProfilePickerTrigger({
  value,
  choices = [],
  deletedLabel,
  expanded,
  onClick,
}: {
  value: string;
  choices?: PickerChoice[];
  /** What a value naming no existing profile reads as. */
  deletedLabel?: string;
  expanded: boolean;
  onClick: () => void;
}) {
  const t = useT();
  const labels = useProfileLabels();
  const choice = choices.find((c) => c.value === value);
  const label = labels.get(value);
  const name = choice?.label ?? label?.name ?? deletedLabel ?? t("profiles.label.deleted");
  const detail = label?.detail.join(" · ");
  return (
    <button
      type="button"
      className="select-trigger"
      aria-haspopup="dialog"
      aria-expanded={expanded}
      onClick={onClick}
    >
      <span className="select-value picker-trigger-value">
        <span
          className="truncate"
          dir="auto"
          style={!choice && !label ? { color: "var(--warn)" } : undefined}
        >
          {name}
        </span>
        {detail && <span className="picker-trigger-detail truncate">{detail}</span>}
      </span>
      <Icon name="expand_more" className="select-arrow" />
    </button>
  );
}

export function ProfilePickerField({
  label,
  hint,
  title,
  value,
  choices,
  only,
  blocked,
  deletedLabel,
  onChange,
}: {
  label?: string;
  hint?: string;
  /** The sheet's title; defaults to the field label. */
  title?: string;
  value: string;
  choices?: PickerChoice[];
  only?: ReadonlySet<string>;
  blocked?: ReadonlyMap<string, string>;
  deletedLabel?: string;
  onChange: (value: string) => void;
}) {
  const [open, setOpen] = useState(false);
  return (
    <div className="field">
      {label && <div className="field-label">{label}</div>}
      <ProfilePickerTrigger
        value={value}
        choices={choices}
        deletedLabel={deletedLabel}
        expanded={open}
        onClick={() => setOpen(true)}
      />
      {hint && (
        <div className="hint" style={{ marginTop: 5 }}>
          {hint}
        </div>
      )}
      {open && (
        <ProfilePickerSheet
          title={title ?? label}
          value={value}
          choices={choices}
          only={only}
          blocked={blocked}
          onPick={onChange}
          onClose={() => setOpen(false)}
        />
      )}
    </div>
  );
}
