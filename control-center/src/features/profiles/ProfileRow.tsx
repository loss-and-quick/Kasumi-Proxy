import { Card, EngineTag, Icon, Ping, ProtoTag, Speed } from "../../components";
import { useT } from "../../i18n";
import { profileEndpointLabel, profileNetwork, profileSecurity } from "../../lib/profile";
import type { Profile } from "../../lib/schema";
import { resolveCore } from "../../lib/schema";
import { useAppStore } from "../../store/useAppStore";

export function ProfileRow({
  profile,
  active,
  bulkMode,
  selected,
  onToggleSelected,
  onUse,
  onEdit,
  onMore,
}: {
  profile: Profile;
  active: boolean;
  bulkMode: boolean;
  selected: boolean;
  onToggleSelected: () => void;
  onUse: () => void;
  onEdit: () => void;
  onMore: () => void;
}) {
  const settings = useAppStore((s) => s.settings);
  const engine = resolveCore(profile, settings);
  const t = useT();

  return (
    <Card
      className="flat"
      style={{
        padding: 0,
        overflow: "hidden",
        display: "flex",
        alignItems: "stretch",
        border: active ? "1px solid var(--primary)" : "1px solid oklch(1 0 0 / 0.04)",
        background: active
          ? "var(--primary-container)"
          : selected
            ? "var(--sc)"
            : "var(--sc-lowest)",
        transition: "background 0.2s, border-color 0.2s",
      }}
    >
      {bulkMode && (
        <button
          type="button"
          className="icon-btn sm"
          style={{ borderRadius: 0, width: 44, borderRight: "1px solid oklch(1 0 0 / 0.05)" }}
          onClick={onToggleSelected}
          title={t("profiles.row.select")}
        >
          <Icon
            name={selected ? "check_box" : "check_box_outline_blank"}
            style={{ fontSize: 20 }}
          />
        </button>
      )}
      <button
        type="button"
        className="btn-reset"
        onClick={bulkMode ? onToggleSelected : onUse}
        style={{
          display: "flex",
          alignItems: "center",
          flex: 1,
          gap: 12,
          minWidth: 0,
          padding: "12px 4px 12px 14px",
        }}
      >
        <div
          style={{
            width: 4,
            alignSelf: "stretch",
            borderRadius: 3,
            background: active ? "var(--primary)" : "transparent",
            flex: "0 0 auto",
          }}
        />
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span
              className="truncate"
              style={{
                fontSize: 14.5,
                fontWeight: 600,
                color: active ? "var(--on-primary-container)" : "var(--on-surface)",
              }}
            >
              {profile.remarks}
            </span>
            {active && (
              <Icon
                name="check_circle"
                style={{ fontSize: 16, color: "var(--primary)", flex: "0 0 auto" }}
              />
            )}
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 7, marginTop: 6 }}>
            <ProtoTag protocol={profile.protocol} />
            {engine === "sing-box" && <EngineTag engine={engine} />}
            <span
              className="mono truncate"
              style={{
                fontSize: 11.5,
                color: active ? "oklch(0.86 0.04 var(--seed-h))" : "var(--on-surface-variant)",
                flex: 1,
              }}
            >
              {profileEndpointLabel(profile)}
            </span>
            <span
              style={{
                fontSize: 10.5,
                fontWeight: 600,
                color: "var(--on-surface-faint)",
                textTransform: "uppercase",
                flex: "0 0 auto",
              }}
            >
              {profileNetwork(profile)}
              {profileSecurity(profile) !== "none" ? ` · ${profileSecurity(profile)}` : ""}
            </span>
          </div>
        </div>
        <div style={{ textAlign: "right", flex: "0 0 auto", paddingRight: 4 }}>
          <Ping value={profile.ping} />
          {profile.speed != null && (
            <div style={{ marginTop: 2 }}>
              <Speed value={profile.speed} />
            </div>
          )}
        </div>
      </button>
      {!bulkMode && (
        <div
          style={{
            display: "flex",
            flexDirection: "column",
            borderLeft: "1px solid oklch(1 0 0 / 0.05)",
          }}
        >
          <button
            type="button"
            className="icon-btn sm"
            style={{ borderRadius: 0, flex: 1, width: 44 }}
            onClick={onEdit}
            title={t("profiles.row.edit")}
          >
            <Icon name="edit" style={{ fontSize: 19 }} />
          </button>
          <button
            type="button"
            className="icon-btn sm"
            style={{
              borderRadius: 0,
              flex: 1,
              width: 44,
              borderTop: "1px solid oklch(1 0 0 / 0.05)",
            }}
            onClick={onMore}
            title={t("profiles.row.more")}
          >
            <Icon name="more_vert" style={{ fontSize: 19 }} />
          </button>
        </div>
      )}
    </Card>
  );
}
