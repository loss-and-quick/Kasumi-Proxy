import { useEffect, useRef, useState } from "react";
import { EmptyHint, SectionLabel } from "../../components";
import { Icon } from "../../components/icons";
import { useT } from "../../i18n";
import type { Group, Profile } from "../../lib/schema";
import { ProfileRow } from "./ProfileRow";

export function ProfilesList({
  orderedGroups,
  byGroup,
  activeId,
  bulkMode,
  selected,
  emptyText,
  onToggleSelected,
  onUse,
  onEdit,
  onMore,
  onRenameGroup,
  onRemoveGroup,
}: {
  orderedGroups: Group[];
  byGroup: Record<string, Profile[]>;
  activeId: string | null;
  bulkMode: boolean;
  selected: Record<string, boolean>;
  emptyText: string;
  onToggleSelected: (id: string) => void;
  onUse: (id: string) => void;
  onEdit: (id: string) => void;
  onMore: (profile: Profile) => void;
  onRenameGroup: (id: string, name: string) => void;
  onRemoveGroup: (id: string) => void;
}) {
  const t = useT();
  const [editingGroupId, setEditingGroupId] = useState<string | null>(null);
  const [editingName, setEditingName] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (editingGroupId) inputRef.current?.focus();
  }, [editingGroupId]);

  function startEdit(group: Group) {
    setEditingGroupId(group.id);
    setEditingName(group.name);
  }

  function commitEdit(id: string) {
    const trimmed = editingName.trim();
    if (trimmed) onRenameGroup(id, trimmed);
    setEditingGroupId(null);
  }

  return (
    <div className="scroll" style={{ paddingTop: 0 }}>
      {orderedGroups.length === 0 && <EmptyHint icon="search_off" text={emptyText} />}
      {orderedGroups.map((group) => (
        <div key={group.id}>
          <SectionLabel
            action={
              <>
                {editingGroupId !== group.id && (
                  <button
                    type="button"
                    onClick={() => startEdit(group)}
                    title={t("profiles.renameGroup")}
                    style={{
                      background: "none",
                      border: "none",
                      cursor: "pointer",
                      padding: "0 4px",
                      color: "var(--on-surface-faint)",
                      display: "flex",
                      alignItems: "center",
                    }}
                  >
                    <Icon name="edit" style={{ fontSize: 14 }} />
                  </button>
                )}
                {editingGroupId !== group.id && group.id !== "g-main" && (
                  <button
                    type="button"
                    onClick={() => onRemoveGroup(group.id)}
                    title={t("profiles.removeGroup")}
                    style={{
                      background: "none",
                      border: "none",
                      cursor: "pointer",
                      padding: "0 4px",
                      color: "var(--on-surface-faint)",
                      display: "flex",
                      alignItems: "center",
                    }}
                  >
                    <Icon name="delete" style={{ fontSize: 14 }} />
                  </button>
                )}
                <span
                  style={{
                    marginLeft: "auto",
                    fontSize: 11,
                    color: "var(--on-surface-faint)",
                    fontWeight: 600,
                  }}
                >
                  {byGroup[group.id].length}
                </span>
              </>
            }
          >
            {editingGroupId === group.id ? (
              <input
                ref={inputRef}
                className="input"
                value={editingName}
                onChange={(e) => setEditingName(e.target.value)}
                onBlur={() => commitEdit(group.id)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") commitEdit(group.id);
                  if (e.key === "Escape") setEditingGroupId(null);
                }}
                style={{ height: 20, padding: "0 4px", fontSize: 11, fontWeight: 600 }}
              />
            ) : (
              group.name
            )}
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
