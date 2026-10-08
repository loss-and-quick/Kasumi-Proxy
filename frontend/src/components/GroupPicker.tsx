import { type CSSProperties, useState } from "react";
import { useT } from "../i18n";
import type { Group } from "../lib/bridge";
import { type GroupChoice, groupNamed } from "../lib/groups";
import { Select } from "./forms";

/** Select value standing for "a group that doesn't exist yet"; generated ids
 *  never start with a control character. */
const NEW = "\u0000new";

/**
 * Pick a group, or name a new one, in any form that files things into a group.
 * Choosing "New group…" opens a name field under the list; the group is only
 * created when the form saves (see the store's `resolveGroup`), so cancelling
 * the form leaves nothing behind. An empty name stands for `suggestedName`
 * (a subscription's name), and a name that matches an existing group reuses it.
 */
export function GroupPicker({
  label,
  groups,
  value,
  onChange,
  suggestedName,
  style,
  selectStyle,
}: {
  label?: string;
  groups: Group[];
  value: GroupChoice;
  onChange: (v: GroupChoice) => void;
  suggestedName?: string;
  style?: CSSProperties;
  /** Sizing for the dropdown trigger (compact toolbars). */
  selectStyle?: CSSProperties;
}) {
  const t = useT();
  // Focus the name field only when the user picks "New group…", not when a
  // form opens with it preselected.
  const [focusName, setFocusName] = useState(false);
  const pending = "newName" in value ? value.newName : null;
  const effective = pending === null ? "" : pending.trim() || (suggestedName ?? "").trim();
  const reused = pending === null ? undefined : groupNamed(groups, effective);

  const newLabel =
    pending !== null && effective
      ? t("groups.picker.newNamed", { name: effective })
      : t("groups.picker.new");
  const options = [
    ...groups.map((g) => ({ value: g.id, label: g.name })),
    { value: NEW, label: newLabel },
  ];

  return (
    <div className="field" style={style}>
      {label && <div className="field-label">{label}</div>}
      <Select
        value={"id" in value ? value.id : NEW}
        options={options}
        style={selectStyle}
        onChange={(v) => {
          if (v === NEW) {
            if (pending === null) onChange({ newName: "" });
            setFocusName(true);
          } else {
            onChange({ id: v });
          }
        }}
      />
      {pending !== null && (
        <div style={{ marginTop: 8 }}>
          <input
            className="input"
            style={{ fontFamily: "var(--font-ui)" }}
            // biome-ignore lint/a11y/noAutofocus: the user just asked for a new group, the name is next
            autoFocus={focusName}
            value={pending}
            placeholder={suggestedName?.trim() || t("groups.picker.namePh")}
            aria-label={t("groups.picker.nameLabel")}
            onChange={(e) => onChange({ newName: e.target.value })}
          />
          <div className="hint" style={{ marginTop: 5 }}>
            {reused
              ? t("groups.picker.reuse", { name: reused.name })
              : effective
                ? t("groups.picker.willCreate")
                : t("groups.picker.needName")}
          </div>
        </div>
      )}
    </div>
  );
}
