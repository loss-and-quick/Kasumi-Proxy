import { useEffect, useState } from "react";
import { Btn, Field, RowToggle, Segmented, Select, Sheet } from "../../components";
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
  // Built-in outbounds are one tap; a specific profile is picked from its own list.
  const outboundKind = BUILTIN_OUTBOUNDS.has(draft.outboundTag)
    ? (draft.outboundTag as "proxy" | "direct" | "block")
    : "profile";
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
      <Segmented
        ariaLabel={t("routingSheet.outbound")}
        value={outboundKind}
        onChange={(kind) => {
          if (kind === "profile") {
            setDraft((current) => ({ ...current, outboundTag: profiles[0]?.id ?? "proxy" }));
          } else {
            setDraft((current) => ({ ...current, outboundTag: kind }));
          }
        }}
        options={[
          { value: "proxy", label: t("routingSheet.outbound.proxy") },
          { value: "direct", label: t("routingSheet.outbound.direct") },
          { value: "block", label: t("routingSheet.outbound.block") },
          {
            value: "profile",
            label: t("routingSheet.outbound.profiles"),
            disabled: profiles.length === 0 && outboundKind !== "profile",
          },
        ]}
      />
      {outboundKind === "profile" && (
        <div style={{ marginTop: 10 }}>
          <Select
            value={draft.outboundTag}
            onChange={(v) => setDraft((current) => ({ ...current, outboundTag: v }))}
            placeholder={draft.outboundTag}
            options={profiles.map((profile) => ({ value: profile.id, label: profile.remarks }))}
          />
          <div className="hint" style={{ marginTop: 6 }}>
            {t("routingSheet.outboundProfileHint")}
          </div>
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
      <Segmented
        ariaLabel={t("routingSheet.network")}
        value={draft.network}
        onChange={(v) => setDraft((current) => ({ ...current, network: v }))}
        options={[
          { value: "", label: t("routingSheet.network.any") },
          { value: "tcp", label: "TCP" },
          { value: "udp", label: "UDP" },
          { value: "tcp,udp", label: "TCP+UDP" },
        ]}
      />
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
