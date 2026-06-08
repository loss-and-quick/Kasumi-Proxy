// ============================================================
// features/editor/Editor.tsx
// Validated profile create/edit form for all protocols. Uses a
// controlled draft + a flat ProfileView for reads; writes merge a
// Partial<ProfileView> and re-narrow to Profile at the boundary.
// Validation runs against the per-protocol Zod schema on save.
// ============================================================
import { useMemo, useState } from "react";
import { Btn, Sheet } from "../../components";
import { useT } from "../../i18n";
import { hasTls, hasTransport } from "../../lib/profile";
import {
  coreLocked,
  emptyProfile,
  type Profile,
  type Protocol,
  resolveCore,
  schemaFor,
} from "../../lib/schema";
import { buildShareLink } from "../../lib/share";
import { useAppStore } from "../../store/useAppStore";
import { BasicsSection } from "./sections/BasicsSection";
import { CredentialsSection } from "./sections/CredentialsSection";
import { RawConfigSection } from "./sections/RawConfigSection";
import { SecuritySection } from "./sections/SecuritySection";
import { SharePreview } from "./sections/SharePreview";
import { TransportSection } from "./sections/TransportSection";
import {
  asView,
  copyViewField,
  type FieldErrors,
  fromView,
  type ProfilePatch,
  type ProfileView,
} from "./types";

export default function Editor({
  profileId,
  onClose,
}: {
  profileId: string | "new";
  onClose: () => void;
}) {
  const groups = useAppStore((s) => s.groups);
  const settings = useAppStore((s) => s.settings);
  const existing = useAppStore((s) => s.profiles.find((p) => p.id === profileId));
  const upsert = useAppStore((s) => s.upsertProfile);
  const t = useT();

  const [draft, setDraft] = useState<Profile>(
    () => existing ?? emptyProfile("vless", groups[0]?.id ?? "g-main"),
  );
  const [errors, setErrors] = useState<FieldErrors>({});

  const v = asView(draft); // read-view
  const set = (patch: ProfilePatch) =>
    setDraft((current) => fromView({ ...asView(current), ...patch }));

  const changeProtocol = (proto: Protocol) => {
    setDraft((current) => {
      const next = asView(emptyProfile(proto, current.groupId));
      const cur = asView(current);
      for (const key of Object.keys(next) as (keyof ProfileView)[]) {
        if (key === "protocol" || key === "id") continue;
        if (cur[key] !== undefined) copyViewField(next, cur, key);
      }
      next.id = cur.id;
      return fromView(next);
    });
  };

  const sharePreview = useMemo(() => {
    try {
      return buildShareLink(draft);
    } catch {
      return "";
    }
  }, [draft]);

  const save = () => {
    const result = schemaFor(draft.protocol).safeParse(draft);
    if (!result.success) {
      const nextErrors: FieldErrors = {};
      for (const issue of result.error.issues) nextErrors[String(issue.path[0])] = issue.message;
      setErrors(nextErrors);
      return;
    }
    upsert(result.data as Profile);
    onClose();
  };

  const groupOpts = groups.map((group) => ({ value: group.id, label: group.name }));
  const proto = draft.protocol;
  const showTransport = hasTransport(draft);
  const showSecurity = hasTls(draft);
  const isReality = v.security === "reality";
  const isTls = v.security === "tls";
  const isQuic = proto === "hysteria2" || proto === "tuic";
  const needsHostPath = ["ws", "grpc", "httpupgrade", "xhttp", "h2"].includes(v.network || "");
  const engineLocked = coreLocked(proto);
  const engineResolved = resolveCore(draft, settings);
  const engineHint = engineLocked
    ? proto === "hysteria2"
      ? t("editor.engineLockedHy2")
      : proto === "tuic"
        ? t("editor.engineLockedTuic")
        : proto === "custom"
          ? t("editor.engineLockedCustom")
          : t("editor.engineLockedSingbox")
    : t("editor.engineResolved", { core: engineResolved });

  return (
    <Sheet
      open
      title={existing ? t("editor.editTitle") : t("editor.newTitle")}
      onClose={onClose}
      headRight={
        <Btn variant="filled" sm icon="check" onClick={save}>
          {t("editor.save")}
        </Btn>
      }
    >
      <BasicsSection
        proto={proto}
        v={v}
        set={set}
        errors={errors}
        groupOpts={groupOpts}
        changeProtocol={changeProtocol}
        engineLocked={engineLocked}
        engineHint={engineHint}
      />

      <CredentialsSection proto={proto} v={v} set={set} errors={errors} />

      {proto === "custom" && <RawConfigSection v={v} set={set} errors={errors} />}

      {showTransport && (
        <TransportSection v={v} set={set} errors={errors} needsHostPath={needsHostPath} />
      )}

      {showSecurity && (
        <SecuritySection
          v={v}
          set={set}
          errors={errors}
          isTls={isTls}
          isReality={isReality}
          isQuic={isQuic}
        />
      )}

      {sharePreview && <SharePreview shareText={sharePreview} />}

      <div style={{ display: "flex", gap: 10, marginTop: 18 }}>
        <Btn variant="outline" block onClick={onClose}>
          {t("editor.cancel")}
        </Btn>
        <Btn variant="filled" block onClick={save}>
          {t("editor.save")}
        </Btn>
      </div>
    </Sheet>
  );
}
