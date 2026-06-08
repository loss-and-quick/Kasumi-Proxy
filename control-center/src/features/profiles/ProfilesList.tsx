import { EmptyHint, SectionLabel } from "../../components";
import type { Group, Profile } from "../../lib/schema";
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
                key={profile.id}
                profile={profile}
                active={profile.id === activeId}
                bulkMode={bulkMode}
                selected={!!selected[profile.id]}
                onToggleSelected={() => onToggleSelected(profile.id)}
                onUse={() => onUse(profile.id)}
                onEdit={() => onEdit(profile.id)}
                onMore={() => onMore(profile)}
              />
            ))}
          </div>
        </div>
      ))}
      <div style={{ height: 10 }} />
    </div>
  );
}
