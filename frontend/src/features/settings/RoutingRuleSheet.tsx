import { useEffect, useState } from "react";
import { Btn, Field, RowToggle, Sheet } from "../../components";
import type { RoutingRule } from "../../generated/bindings";
import { useT } from "../../i18n";
import { normalizeList, toText, uid } from "../../lib/utils";

type Draft = {
  remarks: string;
  enabled: boolean;
  outboundTag: string;
  domainText: string;
  ipText: string;
  port: string;
  network: "" | "tcp" | "udp" | "tcp,udp";
  protocolText: string;
};

function makeDraft(rule?: RoutingRule | null): Draft {
  return {
    remarks: rule?.remarks ?? "",
    enabled: rule?.enabled ?? true,
    outboundTag: rule?.outboundTag ?? "proxy",
    domainText: toText(rule?.domain ?? undefined),
    ipText: toText(rule?.ip ?? undefined),
    port: rule?.port ?? "",
    network: rule?.network ?? "",
    protocolText: toText(rule?.protocol ?? undefined),
  };
}

const BUILTIN_OUTBOUNDS = new Set(["proxy", "direct", "block"]);

export function RoutingRuleSheet({
  open,
  rule,
  profiles,
  onClose,
  onSave,
  onDelete,
}: {
  open: boolean;
  rule: RoutingRule | null;
  profiles: { id: string; remarks: string }[];
  onClose: () => void;
  onSave: (rule: RoutingRule) => void;
  onDelete: (id: string) => void;
}) {
  const [draft, setDraft] = useState<Draft>(makeDraft(rule));
  const t = useT();

  useEffect(() => {
    if (open) setDraft(makeDraft(rule));
  }, [open, rule]);

  const save = () => {
    const domain = normalizeList(draft.domainText);
    const ip = normalizeList(draft.ipText);
    const protocol = normalizeList(draft.protocolText);
    const next: RoutingRule = {
      id: rule?.id ?? uid(),
      remarks: draft.remarks.trim() || t("routingSheet.defaultName"),
      enabled: draft.enabled,
      outboundTag: draft.outboundTag.trim() || "proxy",
      ...(domain ? { domain } : {}),
      ...(ip ? { ip } : {}),
      ...(draft.port.trim() ? { port: draft.port.trim() } : {}),
      ...(draft.network ? { network: draft.network } : {}),
      ...(protocol ? { protocol } : {}),
    };
    onSave(next);
    onClose();
  };

  return (
    <Sheet
      open={open}
      title={rule ? t("routingSheet.editTitle") : t("routingSheet.newTitle")}
      onClose={onClose}
      headRight={
        <Btn variant="filled" sm icon="check" onClick={save}>
          {t("routingSheet.save")}
        </Btn>
      }
    >
      <Field
        label={t("routingSheet.name")}
        value={draft.remarks}
        onChange={(value) => setDraft((current) => ({ ...current, remarks: value }))}
        mono={false}
      />
      <div className="field-label">{t("routingSheet.outbound")}</div>
      <select
        className="select-box"
        value={draft.outboundTag}
        onChange={(e) => setDraft((current) => ({ ...current, outboundTag: e.target.value }))}
      >
        <option value="proxy">{t("routingSheet.outbound.proxy")}</option>
        <option value="direct">{t("routingSheet.outbound.direct")}</option>
        <option value="block">{t("routingSheet.outbound.block")}</option>
        {profiles.length > 0 && (
          <optgroup label={t("routingSheet.outbound.profiles")}>
            {profiles.map((profile) => (
              <option key={profile.id} value={profile.id}>
                {profile.remarks}
              </option>
            ))}
          </optgroup>
        )}
      </select>
      {!BUILTIN_OUTBOUNDS.has(draft.outboundTag) && (
        <div style={{ fontSize: 11.5, color: "var(--on-surface-faint)", marginTop: 6 }}>
          {t("routingSheet.outboundProfileHint")}
        </div>
      )}
      <div style={{ height: 12 }} />
      <RowToggle
        icon="toggle_on"
        title={t("routingSheet.enabled")}
        on={draft.enabled}
        onChange={(value) => setDraft((current) => ({ ...current, enabled: value }))}
      />
      <div style={{ height: 12 }} />
      <Field
        area
        label={t("routingSheet.domains")}
        value={draft.domainText}
        onChange={(value) => setDraft((current) => ({ ...current, domainText: value }))}
        placeholder={t("routingSheet.domainsPh")}
        hint={t("routingSheet.listHint")}
      />
      <Field
        area
        label={t("routingSheet.ips")}
        value={draft.ipText}
        onChange={(value) => setDraft((current) => ({ ...current, ipText: value }))}
        placeholder={t("routingSheet.ipsPh")}
        hint={t("routingSheet.listHint")}
      />
      <Field
        label={t("routingSheet.port")}
        value={draft.port}
        onChange={(value) => setDraft((current) => ({ ...current, port: value }))}
        placeholder={t("routingSheet.portPh")}
        mono={false}
      />
      <div className="field-label">{t("routingSheet.network")}</div>
      <select
        className="select-box"
        value={draft.network}
        onChange={(e) =>
          setDraft((current) => ({ ...current, network: e.target.value as Draft["network"] }))
        }
      >
        <option value="">{t("routingSheet.network.any")}</option>
        <option value="tcp">tcp</option>
        <option value="udp">udp</option>
        <option value="tcp,udp">tcp,udp</option>
      </select>
      <div style={{ height: 12 }} />
      <Field
        area
        label={t("routingSheet.protocols")}
        value={draft.protocolText}
        onChange={(value) => setDraft((current) => ({ ...current, protocolText: value }))}
        placeholder={t("routingSheet.protocolsPh")}
        hint={t("routingSheet.protocolsHint")}
      />
      {rule && (
        <div style={{ marginTop: 16 }}>
          <Btn
            variant="error"
            icon="delete"
            onClick={() => {
              onDelete(rule.id);
              onClose();
            }}
          >
            {t("routingSheet.delete")}
          </Btn>
        </div>
      )}
    </Sheet>
  );
}
