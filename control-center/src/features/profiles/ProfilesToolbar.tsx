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

      <div
        style={{
          display: "flex",
          gap: 8,
          overflowX: "auto",
          padding: "2px 16px 12px",
          flex: "0 0 auto",
          scrollbarWidth: "none",
        }}
      >
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
        <div style={{ marginLeft: "auto" }} />
        <Chip active={sort === "name"} onClick={() => setSort("name")}>
          {t("profiles.sortName")}
        </Chip>
        <Chip active={sort === "ping"} onClick={() => setSort("ping")}>
          {t("profiles.sortPing")}
        </Chip>
        <Chip active={sort === "group"} onClick={() => setSort("group")}>
          {t("profiles.sortGroup")}
        </Chip>
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
            <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
              <Btn variant="outline" sm onClick={onBulkPing} disabled={bulkDisabled}>
                {t("profiles.bulkPing")}
              </Btn>
              <Btn variant="outline" sm onClick={onBulkShare} disabled={bulkDisabled}>
                {t("profiles.bulkShare")}
              </Btn>
              <Btn variant="outline" sm onClick={onBulkMove} disabled={bulkDisabled}>
                {t("profiles.bulkMove")}
              </Btn>
              <select
                className="select-box"
                value={moveGroup}
                onChange={(e) => setMoveGroup(e.target.value)}
                style={{ width: 160, height: 34, paddingTop: 6, paddingBottom: 6 }}
              >
                {groups.map((group) => (
                  <option key={group.id} value={group.id}>
                    {group.name}
                  </option>
                ))}
              </select>
              <Btn variant="outline" sm onClick={onBulkDedup}>
                {t("profiles.bulkDedup")}
              </Btn>
              <Btn variant="error" sm onClick={onBulkDelete} disabled={bulkDisabled}>
                {t("profiles.bulkDelete")}
              </Btn>
            </div>
          </Card>
        </div>
      )}
    </>
  );
}
