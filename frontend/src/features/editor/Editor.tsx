// ============================================================
// features/editor/Editor.tsx
// Validated profile create/edit form for all protocols. The draft is a nested
// `Profile`; each section binds to one sub-object (meta/endpoint/tls/transport)
// or the protocol-root credential fields and writes nested paths. Validation
// runs against the per-protocol Zod schema on save.
// ============================================================

import { useEffect, useState } from "react";
import { Btn, Sheet } from "../../components";
import type { Endpoint, Meta, Profile, Protocol, Tls, Transport } from "../../generated/bindings";
import { useT } from "../../i18n";
import { bridge } from "../../lib/bridge-provider";
import { emptyProfile, forcedCore, resolveCore, schemaFor } from "../../lib/profile-utils";
import { useAppStore } from "../../store/useAppStore";
import { BasicsSection } from "./sections/BasicsSection";
import { CredentialsSection } from "./sections/CredentialsSection";
import { RawConfigSection } from "./sections/RawConfigSection";
import { SecuritySection } from "./sections/SecuritySection";
import { SharePreview } from "./sections/SharePreview";
import { TransportSection } from "./sections/TransportSection";
import type { FieldErrors } from "./types";

export default function Editor({
  profileId,
  onClose,
}: {
  profileId: string | "new";
  onClose: () => void;
}) {
  const groups = useAppStore((s) => s.groups);
  const settings = useAppStore((s) => s.settings);
  const existing = useAppStore((s) => s.profiles.find((p) => p.meta.id === profileId));
  const upsert = useAppStore((s) => s.upsertProfile);
  const t = useT();

  const [draft, setDraft] = useState<Profile>(
    () => existing ?? emptyProfile("vless", groups[0]?.id ?? "g-main"),
  );
  const [errors, setErrors] = useState<FieldErrors>({});

  const setMeta = (patch: Partial<Meta>) =>
    setDraft((d) => ({ ...d, meta: { ...d.meta, ...patch } }));
  const setEndpoint = (patch: Partial<Endpoint>) =>
    setDraft((d) => ("endpoint" in d ? { ...d, endpoint: { ...d.endpoint, ...patch } } : d));
  const setTls = (patch: Partial<Tls>) =>
    setDraft((d) => ("tls" in d && d.tls ? { ...d, tls: { ...d.tls, ...patch } } : d));
  const setTransport = (next: Transport) =>
    setDraft((d) => ("transport" in d ? { ...d, transport: next } : d));
  const setRoot = (patch: Record<string, unknown>) =>
    setDraft((d) => ({ ...d, ...patch }) as Profile);

  // Switching protocol keeps a fresh per-protocol skeleton but carries over the
  // identity, the endpoint/tls/transport sub-objects, and any overlapping root
  // credential field. Mirrors the per-variant structs in `kasumi-core::mixins`.
  const changeProtocol = (proto: Protocol) => {
    setDraft((cur) => {
      const next = emptyProfile(proto, cur.meta.groupId);
      next.meta = {
        ...next.meta,
        id: cur.meta.id,
        remarks: cur.meta.remarks,
        subId: cur.meta.subId,
        coreType: cur.meta.coreType,
      };
      if ("endpoint" in next && "endpoint" in cur) next.endpoint = { ...cur.endpoint };
      if ("tls" in next && next.tls && "tls" in cur && cur.tls) next.tls = { ...cur.tls };
      if ("transport" in next && "transport" in cur && cur.transport)
        next.transport = cur.transport;
      const skip = new Set(["meta", "endpoint", "tls", "transport", "protocol"]);
      const from = cur as Record<string, unknown>;
      const into = next as Record<string, unknown>;
      for (const key of Object.keys(into)) {
        if (!skip.has(key) && from[key] !== undefined) into[key] = from[key];
      }
      return next;
    });
  };

  // The canonical share-link build lives in Rust; render the preview through the
  // bridge command (async) instead of a flat frontend builder.
  const [sharePreview, setSharePreview] = useState("");
  useEffect(() => {
    let alive = true;
    bridge
      .buildShareLink(draft)
      .then((link) => alive && setSharePreview(link))
      .catch(() => alive && setSharePreview(""));
    return () => {
      alive = false;
    };
  }, [draft]);

  const save = () => {
    const result = schemaFor(draft.protocol).safeParse(draft);
    if (!result.success) {
      const next: FieldErrors = {};
      // Key errors by the leaf field name (sni/path/publicKey/…) so each section
      // can surface them, regardless of the nested sub-object the field lives in.
      for (const issue of result.error.issues)
        next[String(issue.path[issue.path.length - 1])] = issue.message;
      setErrors(next);
      return;
    }
    upsert(result.data as Profile);
    onClose();
  };

  const groupOpts = groups.map((group) => ({ value: group.id, label: group.name }));
  const proto = draft.protocol;
  const security = "tls" in draft && draft.tls ? (draft.tls.security ?? "none") : "none";
  const isReality = security === "reality";
  const isTls = security === "tls";
  const isQuic = proto === "hysteria2" || proto === "tuic";
  const network = "transport" in draft && draft.transport ? draft.transport.kind : "tcp";
  const needsHostPath = ["ws", "grpc", "httpupgrade", "xhttp", "h2"].includes(network);
  const engineForced = forcedCore(draft);
  const engineResolved = resolveCore(draft, settings);
  const engineHint = engineForced
    ? t("editor.engineForced", { core: engineForced })
    : t("editor.engineResolved", { core: engineResolved });
  const mux = "muxEnabled" in draft ? !!draft.muxEnabled : false;

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
        draft={draft}
        setMeta={setMeta}
        setEndpoint={setEndpoint}
        errors={errors}
        groupOpts={groupOpts}
        changeProtocol={changeProtocol}
        engineForced={engineForced}
        engineHint={engineHint}
      />

      <CredentialsSection draft={draft} setRoot={setRoot} errors={errors} />

      {proto === "custom" && (
        <RawConfigSection
          raw={proto === "custom" ? (draft.raw ?? "") : ""}
          onChange={(value) => setRoot({ raw: value })}
          errors={errors}
        />
      )}

      {"transport" in draft && draft.transport && (
        <TransportSection
          transport={draft.transport}
          setTransport={setTransport}
          mux={mux}
          setMux={(value) => setRoot({ muxEnabled: value })}
          errors={errors}
          needsHostPath={needsHostPath}
        />
      )}

      {"tls" in draft && draft.tls && (
        <SecuritySection
          tls={draft.tls}
          setTls={setTls}
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
