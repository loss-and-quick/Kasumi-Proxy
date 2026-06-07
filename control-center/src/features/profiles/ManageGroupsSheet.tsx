import { lazy, Suspense, useEffect, useRef, useState } from "react";
import { Icon, IconBtn, Sheet } from "../../components";
import { useT } from "../../i18n";
import type { Group } from "../../lib/schema";
import { useAppStore } from "../../store/useAppStore";

const DeleteGroupDialog = lazy(() =>
  import("./DeleteGroupDialog").then((module) => ({ default: module.DeleteGroupDialog })),
);

export function ManageGroupsSheet({ open, onClose }: { open: boolean; onClose: () => void }) {
  const t = useT();
  const groups = useAppStore((s) => s.groups);
  const profiles = useAppStore((s) => s.profiles);
  const activeId = useAppStore((s) => s.activeId);
  const addGroup = useAppStore((s) => s.addGroup);
  const renameGroup = useAppStore((s) => s.renameGroup);
  const removeGroup = useAppStore((s) => s.removeGroup);

  const [newName, setNewName] = useState("");
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editingName, setEditingName] = useState("");
  const [confirmDel, setConfirmDel] = useState<Group | null>(null);
  const editRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (editingId) editRef.current?.focus();
  }, [editingId]);

  const activeGroupId = profiles.find((p) => p.id === activeId)?.groupId ?? null;
  const countOf = (id: string) => profiles.filter((p) => p.groupId === id).length;

  function createGroup() {
    const name = newName.trim();
    if (!name) return;
    addGroup(name);
    setNewName("");
  }

  function commitEdit(id: string) {
    const name = editingName.trim();
    if (name) renameGroup(id, name);
    setEditingId(null);
  }

  return (
    <Sheet open={open} title={t("profiles.groups.title")} onClose={onClose}>
      <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
        <input
          className="input"
          value={newName}
          placeholder={t("profiles.groups.newPlaceholder")}
          onChange={(e) => setNewName(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") createGroup();
          }}
          style={{ flex: 1, fontFamily: "var(--font-ui)" }}
        />
        <IconBtn name="add" title={t("profiles.add.newGroup")} onClick={createGroup} />
      </div>

      {groups.map((group) => {
        const locked = group.id === "g-main" || group.id === activeGroupId;
        const isEditing = editingId === group.id;
        return (
          <div className="list-row" key={group.id}>
            <div className="lr-icon">
              <Icon name="folder" />
            </div>
            <div className="lr-main">
              {isEditing ? (
                <input
                  ref={editRef}
                  className="group-rename-input"
                  value={editingName}
                  onChange={(e) => setEditingName(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") commitEdit(group.id);
                    if (e.key === "Escape") setEditingId(null);
                  }}
                  onBlur={() => commitEdit(group.id)}
                />
              ) : (
                <>
                  <div className="lr-title">{group.name}</div>
                  <div className="lr-sub">
                    {t("profiles.groups.count", { count: countOf(group.id) })}
                  </div>
                </>
              )}
            </div>
            {isEditing ? (
              <IconBtn
                name="check"
                sm
                title={t("profiles.renameGroup")}
                onClick={() => commitEdit(group.id)}
              />
            ) : (
              <IconBtn
                name="edit"
                sm
                title={t("profiles.renameGroup")}
                onClick={() => {
                  setEditingId(group.id);
                  setEditingName(group.name);
                }}
              />
            )}
            {!locked && !isEditing && (
              <IconBtn
                name="delete"
                sm
                title={t("profiles.removeGroup")}
                onClick={() => setConfirmDel(group)}
              />
            )}
          </div>
        );
      })}

      {confirmDel && (
        <Suspense fallback={null}>
          <DeleteGroupDialog
            group={confirmDel}
            count={countOf(confirmDel.id)}
            onClose={() => setConfirmDel(null)}
            onConfirm={(group) => {
              void removeGroup(group.id);
              setConfirmDel(null);
            }}
          />
        </Suspense>
      )}
    </Sheet>
  );
}
