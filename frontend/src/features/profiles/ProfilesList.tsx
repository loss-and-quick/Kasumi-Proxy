import { EmptyHint, Icon, SectionLabel } from "../../components";
import type { Group, Profile, TestKind } from "../../generated/bindings";
import { useT } from "../../i18n";
import { ProfileRow } from "./ProfileRow";

export function ProfilesList({
  groups,
  byGroup,
  activeId,
  bulkMode,
  selected,
  emptyText,
  onToggleSelected,
  onToggleGroup,
  onUse,
  onEdit,
  onMore,
  onShowTestLog,
}: {
  groups: Group[];
  byGroup: Record<string, Profile[]>;
  activeId: string | null;
  bulkMode: boolean;
  selected: Record<string, boolean>;
  emptyText: string;
  onToggleSelected: (id: string) => void;
  /** Select (or clear) every listed profile of one group. */
  onToggleGroup: (ids: string[], on: boolean) => void;
  onUse: (id: string) => void;
  onEdit: (id: string) => void;
  onMore: (profile: Profile) => void;
  onShowTestLog: (profile: Profile, kind: TestKind) => void;
}) {
  const t = useT();
  return (
    <div className="scroll with-fab" style={{ paddingTop: 0 }}>
      {groups.length === 0 && <EmptyHint icon="search_off" text={emptyText} />}
      {groups.map((group) => {
        const ids = byGroup[group.id].map((p) => p.meta.id);
        const picked = ids.filter((id) => selected[id]).length;
        const all = picked === ids.length;
        return (
          <div key={group.id}>
            <SectionLabel
              action={
                bulkMode ? (
                  <button
                    type="button"
                    className="btn-reset group-select"
                    aria-pressed={all}
                    title={all ? t("profiles.bulkGroupNone") : t("profiles.bulkGroupAll")}
                    onClick={() => onToggleGroup(ids, !all)}
                  >
                    <span className="group-count">
                      {picked ? `${picked}/${ids.length}` : ids.length}
                    </span>
                    <Icon
                      name={all ? "check_box" : "check_box_outline_blank"}
                      style={{
                        fontSize: 20,
                        color: picked ? "var(--primary)" : undefined,
                      }}
                    />
                  </button>
                ) : (
                  <span className="group-count">{ids.length}</span>
                )
              }
            >
              {group.name}
            </SectionLabel>
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              {byGroup[group.id].map((profile) => (
                <ProfileRow
                  key={profile.meta.id}
                  profile={profile}
                  active={profile.meta.id === activeId}
                  bulkMode={bulkMode}
                  selected={!!selected[profile.meta.id]}
                  onToggleSelected={() => onToggleSelected(profile.meta.id)}
                  onUse={() => onUse(profile.meta.id)}
                  onEdit={() => onEdit(profile.meta.id)}
                  onMore={() => onMore(profile)}
                  onShowTestLog={(kind) => onShowTestLog(profile, kind)}
                />
              ))}
            </div>
          </div>
        );
      })}
      <div style={{ height: 10 }} />
    </div>
  );
}
