import {
  closestCenter,
  DndContext,
  type DragEndEvent,
  type DraggableAttributes,
  KeyboardSensor,
  PointerSensor,
  useSensor,
  useSensors,
} from "@dnd-kit/core";
import {
  SortableContext,
  sortableKeyboardCoordinates,
  useSortable,
  verticalListSortingStrategy,
} from "@dnd-kit/sortable";
import { CSS } from "@dnd-kit/utilities";
import { lazy, type ReactNode, Suspense, useEffect, useRef, useState } from "react";
import { Icon, IconBtn, Sheet } from "../../components";
import type { Group } from "../../generated/bindings";
import { useT } from "../../i18n";
import { useAppStore } from "../../store/useAppStore";

const DeleteGroupDialog = lazy(() =>
  import("./DeleteGroupDialog").then((module) => ({ default: module.DeleteGroupDialog })),
);

type SortableBindings = {
  setNodeRef: (el: HTMLElement | null) => void;
  style: React.CSSProperties;
  attributes: DraggableAttributes;
  listeners: ReturnType<typeof useSortable>["listeners"];
  isDragging: boolean;
};

// Render-prop wrapper so useSortable runs in a real (keyed) component instance,
// keeping the row JSX inline in the map.
function Sortable({ id, children }: { id: string; children: (b: SortableBindings) => ReactNode }) {
  const { attributes, listeners, setNodeRef, transform, transition, isDragging } = useSortable({
    id,
  });
  return children({
    setNodeRef,
    style: { transform: CSS.Transform.toString(transform), transition },
    attributes,
    listeners,
    isDragging,
  });
}

export function ManageGroupsSheet({ open, onClose }: { open: boolean; onClose: () => void }) {
  const t = useT();
  const groups = useAppStore((s) => s.groups);
  const profiles = useAppStore((s) => s.profiles);
  const activeId = useAppStore((s) => s.activeId);
  const addGroup = useAppStore((s) => s.addGroup);
  const renameGroup = useAppStore((s) => s.renameGroup);
  const removeGroup = useAppStore((s) => s.removeGroup);
  const reorderGroups = useAppStore((s) => s.reorderGroups);

  const sensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 4 } }),
    useSensor(KeyboardSensor, { coordinateGetter: sortableKeyboardCoordinates }),
  );

  const [newName, setNewName] = useState("");
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editingName, setEditingName] = useState("");
  const [confirmDel, setConfirmDel] = useState<Group | null>(null);
  const editRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (editingId) editRef.current?.focus();
  }, [editingId]);

  const activeGroupId = profiles.find((p) => p.meta.id === activeId)?.meta.groupId ?? null;
  const countOf = (id: string) => profiles.filter((p) => p.meta.groupId === id).length;
  // g-main stays pinned at the top and out of the sortable set.
  const sortableIds = groups.filter((g) => g.id !== "g-main").map((g) => g.id);

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

  function onDragEnd({ active, over }: DragEndEvent) {
    if (!over || active.id === over.id) return;
    const from = groups.findIndex((g) => g.id === active.id);
    const to = groups.findIndex((g) => g.id === over.id);
    if (from === -1 || to === -1) return;
    void reorderGroups(from, to);
  }

  function renderRow(group: Group, bindings?: SortableBindings) {
    const locked = group.id === "g-main" || group.id === activeGroupId;
    const isEditing = editingId === group.id;
    return (
      <div
        className={`list-row${bindings?.isDragging ? " dragging" : ""}`}
        ref={bindings?.setNodeRef}
        style={bindings?.style}
      >
        {bindings ? (
          <span
            className="lr-drag"
            title={t("profiles.groups.reorder")}
            {...bindings.attributes}
            {...bindings.listeners}
          >
            <Icon name="drag_indicator" />
          </span>
        ) : (
          <span className="lr-drag" aria-hidden="true" />
        )}
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

      <DndContext sensors={sensors} collisionDetection={closestCenter} onDragEnd={onDragEnd}>
        <SortableContext items={sortableIds} strategy={verticalListSortingStrategy}>
          {groups.map((group) =>
            group.id === "g-main" ? (
              <div key={group.id}>{renderRow(group)}</div>
            ) : (
              <Sortable key={group.id} id={group.id}>
                {(bindings) => renderRow(group, bindings)}
              </Sortable>
            ),
          )}
        </SortableContext>
      </DndContext>

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
