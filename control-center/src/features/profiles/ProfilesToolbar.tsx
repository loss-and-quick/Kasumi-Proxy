import { AppBar, Btn, Card, Chip, Icon, IconBtn } from "../../components";
import { useT } from "../../i18n";
import type { Group } from "../../lib/schema";
import type { SortMode } from "./types";

export function ProfilesToolbar({
  profileCount,
  groupCount,
  searchOpen,
  query,
  setQuery,
  onToggleSearch,
  onOpenPingSheet,
  bulkMode,
  onToggleBulk,
  onOpenAdd,
  onManageGroups,
  groupFilter,
  setGroupFilter,
  groups,
  sort,
  setSort,
  selectedCount,
  moveGroup,
  setMoveGroup,
  onBulkPing,
  onBulkShare,
  onBulkMove,
  onBulkDelete,
  onBulkDedup,
}: {
  profileCount: number;
  groupCount: number;
  searchOpen: boolean;
  query: string;
  setQuery: (value: string) => void;
  onToggleSearch: () => void;
  onOpenPingSheet: () => void;
  bulkMode: boolean;
  onToggleBulk: () => void;
  onOpenAdd: () => void;
  onManageGroups: () => void;
  groupFilter: string;
  setGroupFilter: (value: string) => void;
  groups: Group[];
  sort: SortMode;
  setSort: (value: SortMode) => void;
  selectedCount: number;
  moveGroup: string;
  setMoveGroup: (value: string) => void;
  onBulkPing: () => void;
  onBulkShare: () => void;
  onBulkMove: () => void;
  onBulkDelete: () => void;
  onBulkDedup: () => void;
}) {
  const t = useT();
  const bulkDisabled = selectedCount === 0;

  return (
    <>
      <AppBar
        title={t("profiles.title")}
        subtitle={t("profiles.subtitle", { servers: profileCount, groups: groupCount })}
        actions={
          <>
            <IconBtn
              name={searchOpen ? "search_off" : "search"}
              title={t("profiles.search")}
              onClick={onToggleSearch}
            />
            <IconBtn name="speed" title={t("profiles.pingAll")} onClick={onOpenPingSheet} />
            <IconBtn
              name="folder_managed"
              title={t("profiles.manageGroups")}
              onClick={onManageGroups}
            />
            <IconBtn
              name={bulkMode ? "close" : "select_all"}
              title={bulkMode ? t("profiles.closeBulk") : t("profiles.bulk")}
              onClick={onToggleBulk}
            />
            <IconBtn name="add" title={t("profiles.newProfile")} onClick={onOpenAdd} />
          </>
        }
      />

      {searchOpen && (
        <div style={{ padding: "0 16px 8px" }}>
          <div style={{ position: "relative" }}>
            <Icon
              name="search"
              style={{
                position: "absolute",
                left: 12,
                top: 13,
                fontSize: 20,
                color: "var(--on-surface-faint)",
              }}
            />
            <input
              className="input"
              placeholder={t("profiles.searchPlaceholder")}
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              style={{
                paddingLeft: 40,
                fontFamily: "var(--font-ui)",
                borderRadius: 12,
                borderBottom: "2px solid var(--primary)",
              }}
            />
          </div>
        </div>
      )}

      {/* Sort row */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 8,
          padding: "2px 16px 8px",
        }}
      >
        <span
          style={{ fontSize: 11, fontWeight: 600, color: "var(--on-surface-faint)", flexShrink: 0 }}
        >
          {t("profiles.filterSort")}
        </span>
        <Chip active={sort === "name"} onClick={() => setSort("name")}>
          {t("profiles.sortName")}
        </Chip>
        <Chip active={sort === "ping"} onClick={() => setSort("ping")}>
          {t("profiles.sortPing")}
        </Chip>
      </div>

      {/* Group filter row */}
      <div
        style={{
          display: "flex",
          alignItems: "flex-start",
          gap: 8,
          padding: "0 16px 12px",
        }}
      >
        <span
          style={{
            fontSize: 11,
            fontWeight: 600,
            color: "var(--on-surface-faint)",
            flexShrink: 0,
            paddingTop: 6,
          }}
        >
          {t("profiles.filterGroup")}
        </span>
        <div style={{ display: "flex", overflowX: "auto", gap: 8, scrollbarWidth: "none" }}>
          <Chip active={groupFilter === "all"} onClick={() => setGroupFilter("all")}>
            {t("profiles.filterAll")}
          </Chip>
          {groups.map((group) => (
            <Chip
              key={group.id}
              active={groupFilter === group.id}
              onClick={() => setGroupFilter(group.id)}
            >
              {group.name}
            </Chip>
          ))}
        </div>
      </div>

      {bulkMode && (
        <div style={{ padding: "0 16px 10px" }}>
          <Card className="flat" style={{ padding: 12 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
              <span style={{ fontSize: 13, color: "var(--on-surface-variant)" }}>
                {t("profiles.bulkSelected")}
              </span>
              <span className="mono" style={{ fontSize: 13, fontWeight: 700 }}>
                {selectedCount}
              </span>
            </div>
            {/* Even two-column grid: Move pairs with its target select; Delete
                stays on its own row, away from the move selector. */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
              <Btn variant="outline" sm block onClick={onBulkPing} disabled={bulkDisabled}>
                {t("profiles.bulkPing")}
              </Btn>
              <Btn variant="outline" sm block onClick={onBulkShare} disabled={bulkDisabled}>
                {t("profiles.bulkShare")}
              </Btn>
              <Btn variant="outline" sm block onClick={onBulkMove} disabled={bulkDisabled}>
                {t("profiles.bulkMove")}
              </Btn>
              <select
                className="select-box"
                value={moveGroup}
                onChange={(e) => setMoveGroup(e.target.value)}
                style={{ width: "100%", height: 34, paddingTop: 6, paddingBottom: 6 }}
              >
                {groups.map((group) => (
                  <option key={group.id} value={group.id}>
                    {group.name}
                  </option>
                ))}
              </select>
              <Btn variant="error" sm block onClick={onBulkDelete} disabled={bulkDisabled}>
                {t("profiles.bulkDelete")}
              </Btn>
              <Btn variant="outline" sm block onClick={onBulkDedup}>
                {t("profiles.bulkDedup")}
              </Btn>
            </div>
          </Card>
        </div>
      )}
    </>
  );
}
