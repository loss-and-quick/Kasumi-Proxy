import { useEffect, useState } from "react";
import { Btn, confirm, Field, RowToggle, Segmented, Sheet } from "../../components";
import type { RoutingRule } from "../../generated/bindings";
import { useT } from "../../i18n";
import { getRuntimeBridgeMode } from "../../lib/ksu-webui";
import { normalizeList, toText, uid } from "../../lib/utils";
import { useAppStore } from "../../store/useAppStore";
import { useProfileLabels } from "../profiles/labels";
import { ProfilePickerSheet, ProfilePickerTrigger } from "../profiles/ProfilePicker";

type Draft = {
  remarks: string;
  enabled: boolean;
  outboundTag: string;
  domainText: string;
  ipText: string;
  port: string;
  network: "" | "tcp" | "udp" | "tcp,udp";
  protocolText: string;
  processText: string;
  packageText: string;
  sourceIpText: string;
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
    processText: toText(rule?.process ?? undefined),
    packageText: toText(rule?.packageName ?? undefined),
    sourceIpText: toText(rule?.sourceIp ?? undefined),
  };
}

const BUILTIN_OUTBOUNDS = new Set(["proxy", "direct", "block"]);

export function RoutingRuleSheet({
  open,
  rule,
  onClose,
  onSave,
  onDelete,
}: {
  open: boolean;
  rule: RoutingRule | null;
  onClose: () => void;
  onSave: (rule: RoutingRule) => void;
  onDelete: (id: string) => void;
}) {
  const [draft, setDraft] = useState<Draft>(makeDraft(rule));
  const [picking, setPicking] = useState(false);
  const hasProfiles = useAppStore((s) => s.profiles.length > 0);
  const labels = useProfileLabels();
  // Built-in outbounds are one tap; a specific profile is picked from its own list.
  const outboundKind = BUILTIN_OUTBOUNDS.has(draft.outboundTag)
    ? (draft.outboundTag as "proxy" | "direct" | "block")
    : "profile";
  const t = useT();
  const isDesktop = getRuntimeBridgeMode() === "tauri";

  useEffect(() => {
    if (open) setDraft(makeDraft(rule));
  }, [open, rule]);

  const save = () => {
    const domain = normalizeList(draft.domainText);
    const ip = normalizeList(draft.ipText);
    const protocol = normalizeList(draft.protocolText);
    const process = normalizeList(draft.processText);
    const packageName = normalizeList(draft.packageText);
    const sourceIp = normalizeList(draft.sourceIpText);
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
      ...(process ? { process } : {}),
      ...(packageName ? { packageName } : {}),
      ...(sourceIp ? { sourceIp } : {}),
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
          // The segment stays where it was until a profile is actually picked.
          if (kind === "profile") {
            setPicking(true);
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
            disabled: !hasProfiles && outboundKind !== "profile",
          },
        ]}
      />
      {outboundKind === "profile" && (
        <div style={{ marginTop: 10 }}>
          <ProfilePickerTrigger
            value={draft.outboundTag}
            deletedLabel={t("routes.out.deleted")}
            expanded={picking}
            onClick={() => setPicking(true)}
          />
          {labels.has(draft.outboundTag) ? (
            <div className="hint" style={{ marginTop: 6 }}>
              {t("routingSheet.outboundProfileHint")}
            </div>
          ) : (
            <div className="hint warn" style={{ marginTop: 6 }}>
              {t("routingSheet.outboundDeletedHint")}
            </div>
          )}
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
      <Field
        area
        label={t("routingSheet.processes")}
        value={draft.processText}
        onChange={(value) => setDraft((current) => ({ ...current, processText: value }))}
        placeholder={t("routingSheet.processesPh")}
        hint={t("routingSheet.processesHint")}
      />
      {/* Android package names match nothing on a desktop; a rule that already
          names some (imported from the phone) still shows them. */}
      {(!isDesktop || draft.packageText.trim() !== "") && (
        <Field
          area
          label={t("routingSheet.packages")}
          value={draft.packageText}
          onChange={(value) => setDraft((current) => ({ ...current, packageText: value }))}
          placeholder={t("routingSheet.packagesPh")}
          hint={t("routingSheet.packagesHint")}
        />
      )}
      <Field
        area
        label={t("routingSheet.sourceIps")}
        value={draft.sourceIpText}
        onChange={(value) => setDraft((current) => ({ ...current, sourceIpText: value }))}
        placeholder={t("routingSheet.sourceIpsPh")}
        hint={t("routingSheet.sourceIpsHint")}
      />
      {picking && (
        <ProfilePickerSheet
          value={draft.outboundTag}
          onPick={(id) => setDraft((current) => ({ ...current, outboundTag: id }))}
          onClose={() => setPicking(false)}
        />
      )}
      {rule && (
        <div style={{ marginTop: 16 }}>
          <Btn
            variant="error"
            icon="delete"
            onClick={async () => {
              const ok = await confirm({
                title: t("confirm.ruleDelete.title"),
                body: rule.remarks || undefined,
                confirmLabel: t("routingSheet.delete"),
              });
              if (!ok) return;
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
