import { EmptyHint, SectionLabel } from "../../components";
import type { Group, Profile, TestKind } from "../../generated/bindings";
import { ProfileRow } from "./ProfileRow";

export function ProfilesList({
  groups,
  byGroup,
  activeId,
  bulkMode,
  selected,
  emptyText,
  onToggleSelected,
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
  onUse: (id: string) => void;
  onEdit: (id: string) => void;
  onMore: (profile: Profile) => void;
  onShowTestLog: (profile: Profile, kind: TestKind) => void;
}) {
  return (
    <div className="scroll with-fab" style={{ paddingTop: 0 }}>
      {groups.length === 0 && <EmptyHint icon="search_off" text={emptyText} />}
      {groups.map((group) => (
        <div key={group.id}>
          <SectionLabel action={<span className="group-count">{byGroup[group.id].length}</span>}>
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
      ))}
      <div style={{ height: 10 }} />
    </div>
  );
}
