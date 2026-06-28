import { type ReactNode, useEffect, useRef } from "react";
import { Card, EngineTag, Icon, Ping, ProtoTag, Speed, Spinner } from "../../components";
import type { Profile, TestKind } from "../../generated/bindings";
import { useT } from "../../i18n";
import {
  profileEndpointLabel,
  profileNetwork,
  profileSecurity,
  resolveCore,
} from "../../lib/profile-utils";
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
  onShowTestLog,
}: {
  profile: Profile;
  active: boolean;
  bulkMode: boolean;
  selected: boolean;
  onToggleSelected: () => void;
  onUse: () => void;
  onEdit: () => void;
  onMore: () => void;
  onShowTestLog: (kind: TestKind) => void;
}) {
  const settings = useAppStore((s) => s.settings);
  const isPinging = useAppStore((s) => s.pinging.has(profile.meta.id));
  const isSpeedTesting = useAppStore((s) => s.speedTesting.has(profile.meta.id));
  // Pop the value in only when a test just finished (spinner → value), not on
  // every list mount — so opening the screen doesn't flash every row's metric.
  const wasPinging = useRef(isPinging);
  const wasSpeedTesting = useRef(isSpeedTesting);
  const pingJustFinished = wasPinging.current && !isPinging;
  const speedJustFinished = wasSpeedTesting.current && !isSpeedTesting;
  useEffect(() => {
    wasPinging.current = isPinging;
    wasSpeedTesting.current = isSpeedTesting;
  });
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
              {profile.meta.remarks}
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
      </button>
      {/* The metrics sit outside the "use profile" button so an `err` can be its own
          button (opening the test-core log) without nesting interactive elements. */}
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          alignItems: "flex-end",
          justifyContent: "center",
          flex: "0 0 auto",
          textAlign: "right",
          padding: "0 8px",
        }}
      >
        <div>
          {isPinging ? (
            <Spinner />
          ) : (
            <ErrTrigger
              value={profile.meta.ping ?? null}
              title={t("testlog.open")}
              onShow={() => onShowTestLog("realPing")}
            >
              <Ping value={profile.meta.ping ?? null} animate={pingJustFinished} />
            </ErrTrigger>
          )}
          {(isSpeedTesting || profile.meta.speed != null) && (
            <div style={{ marginTop: 2 }}>
              {isSpeedTesting ? (
                <Spinner />
              ) : (
                <ErrTrigger
                  value={profile.meta.speed ?? null}
                  title={t("testlog.open")}
                  onShow={() => onShowTestLog("speed")}
                >
                  <Speed value={profile.meta.speed} animate={speedJustFinished} />
                </ErrTrigger>
              )}
            </div>
          )}
        </div>
      </div>
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

/** Makes an `err` metric tappable (→ its test log); a passing value renders inert. */
function ErrTrigger({
  value,
  title,
  onShow,
  children,
}: {
  value: number | null;
  title: string;
  onShow: () => void;
  children: ReactNode;
}) {
  if (value == null || value >= 0) return <>{children}</>;
  return (
    <button
      type="button"
      className="btn-reset"
      title={title}
      onClick={onShow}
      style={{
        cursor: "pointer",
        textDecoration: "underline",
        textUnderlineOffset: 2,
        font: "inherit",
      }}
    >
      {children}
    </button>
  );
}
