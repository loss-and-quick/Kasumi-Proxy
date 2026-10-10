// ============================================================
// features/editor/Editor.tsx
// Validated profile create/edit form for all protocols. The draft is a nested
// `Profile`; each section binds to one sub-object (meta/endpoint/tls/transport)
// or the protocol-root credential fields and writes nested paths. Validation
// runs against the per-protocol Zod schema on save.
// ============================================================

import { useEffect, useRef, useState } from "react";
import { Btn, confirm, Sheet } from "../../components";
import type {
  CoreResolution,
  Endpoint,
  Meta,
  Profile,
  Protocol,
  Tls,
  Transport,
} from "../../generated/bindings";
import { useT } from "../../i18n";
import { bridge } from "../../lib/bridge-provider";
import { type GroupChoice, groupChoiceReady } from "../../lib/groups";
import { emptyProfile, schemaFor } from "../../lib/profile-utils";
import { isDefaultRoute, routeEnabled, routeGroups, routeProfiles } from "../../lib/routes";
import { wasReported } from "../../store/errors";
import { useAppStore } from "../../store/useAppStore";
import { routeName } from "../routes/labels";
import { BasicsSection } from "./sections/BasicsSection";
import { CredentialsSection } from "./sections/CredentialsSection";
import { RawConfigSection } from "./sections/RawConfigSection";
import { SecuritySection } from "./sections/SecuritySection";
import { SharePreview } from "./sections/SharePreview";
import { TransportSection } from "./sections/TransportSection";
import type { FieldErrors } from "./types";

export default function Editor({
  profileId,
  newGroupId,
  onClose,
}: {
  profileId: string | "new";
  /** The group a new profile starts in (the one the user was looking at). */
  newGroupId?: string;
  onClose: () => void;
}) {
  const groups = useAppStore((s) => s.groups);
  const profiles = useAppStore((s) => s.profiles);
  const existing = useAppStore((s) => s.profiles.find((p) => p.meta.id === profileId));
  const upsert = useAppStore((s) => s.upsertProfile);
  const resolveGroup = useAppStore((s) => s.resolveGroup);
  const routes = useAppStore((s) => s.routes);
  const setProfileRoute = useAppStore((s) => s.setProfileRoute);
  const t = useT();

  const [draft, setDraft] = useState<Profile>(
    () => existing ?? emptyProfile("vless", newGroupId ?? groups[0]?.id ?? "g-main"),
  );
  const [errors, setErrors] = useState<FieldErrors>({});
  // The group is picked apart from the draft: a new one is only created on save.
  const [group, setGroup] = useState<GroupChoice>(() => ({ id: draft.meta.groupId }));
  // The route that lists this profile itself; "" follows its group's route.
  const [listedRoute] = useState(
    () => routes.find((r) => routeProfiles(r).includes(draft.meta.id))?.id ?? "",
  );
  const [route, setRoute] = useState(listedRoute);
  const [saving, setSaving] = useState(false);
  const notify = useAppStore((s) => s.notify);
  // What the form opened with, to tell whether closing would lose anything.
  const opened = useRef(JSON.stringify([draft, group, route]));
  const dirty = () => JSON.stringify([draft, group, route]) !== opened.current;

  // Every way out (swipe, scrim, Escape, ✕, Cancel) asks first when there are
  // unsaved changes.
  const mayClose = async () =>
    !dirty() ||
    confirm({
      icon: "edit_note",
      title: t("editor.discard.title"),
      body: t("editor.discard.body"),
      confirmLabel: t("editor.discard.action"),
    });

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
        via: cur.meta.via,
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

  // The core-resolution matrix lives in Rust too; resolve the draft's engine
  // through the bridge on every edit (same pattern as the share preview). `null`
  // until the first reply lands, which just hides the engine hint.
  const [coreResolution, setCoreResolution] = useState<CoreResolution | null>(null);
  useEffect(() => {
    let alive = true;
    bridge
      .resolveCores([draft])
      .then((rs) => alive && setCoreResolution(rs[0] ?? null))
      .catch(() => alive && setCoreResolution(null));
    return () => {
      alive = false;
    };
  }, [draft]);

  // Which profiles the draft may dial through is a backend answer (the same chain
  // check the config builders make), re-asked on every edit like the engine.
  const [viaIds, setViaIds] = useState<string[]>([]);
  useEffect(() => {
    let alive = true;
    bridge
      .chainCandidates(draft)
      .then((ids) => alive && setViaIds(ids))
      .catch(() => alive && setViaIds([]));
    return () => {
      alive = false;
    };
  }, [draft]);

  const save = async () => {
    const result = schemaFor(draft.protocol).safeParse(draft);
    const next: FieldErrors = {};
    if (!result.success) {
      // Key errors by the leaf field name (sni/path/publicKey/…) so each section
      // can surface them, regardless of the nested sub-object the field lives in.
      for (const issue of result.error.issues)
        next[String(issue.path[issue.path.length - 1])] = issue.message;
    }
    if (!groupChoiceReady(group)) next.group = t("groups.picker.needName");
    if (!result.success || Object.keys(next).length) {
      setErrors(next);
      // The offending field may be scrolled out of view.
      notify(t("editor.validation.fix"));
      return;
    }
    const profile = result.data as Profile;
    setSaving(true);
    try {
      const groupId = await resolveGroup(group, "");
      await upsert({ ...profile, meta: { ...profile.meta, groupId } });
      if (route !== listedRoute) await setProfileRoute(profile.meta.id, route || null);
    } catch (e) {
      // Keep the form open so nothing typed is lost.
      if (!wasReported(e))
        notify(t("store.service.error", { error: e instanceof Error ? e.message : String(e) }));
      return;
    } finally {
      setSaving(false);
    }
    onClose();
  };

  // Without a route of its own the profile runs with its group's (or the default).
  const groupId = "id" in group ? group.id : null;
  const groupRoute =
    routes.find((r) => routeEnabled(r) && groupId !== null && routeGroups(r).includes(groupId)) ??
    routes.find(isDefaultRoute);
  const routeOpts =
    routes.length > 1
      ? [
          {
            value: "",
            label: t("editor.routeFollow", { route: groupRoute ? routeName(groupRoute, t) : "" }),
          },
          ...routes
            .filter((r) => !isDefaultRoute(r))
            .map((r) => ({
              value: r.id,
              label: routeEnabled(r) ? r.name : `${r.name} · ${t("routes.off")}`,
            })),
        ]
      : [];

  const viaOpts = viaIds.flatMap((id) => {
    const hop = profiles.find((p) => p.meta.id === id);
    return hop ? [{ value: id, label: hop.meta.remarks }] : [];
  });
  const proto = draft.protocol;
  const security = "tls" in draft && draft.tls ? (draft.tls.security ?? "none") : "none";
  const isReality = security === "reality";
  const isTls = security === "tls";
  const isQuic = proto === "hysteria2" || proto === "tuic";
  const network = "transport" in draft && draft.transport ? draft.transport.kind : "tcp";
  const needsHostPath = ["ws", "grpc", "httpupgrade", "xhttp", "h2"].includes(network);
  const engineForced = coreResolution?.forced ?? null;
  const engineHint = engineForced
    ? t("editor.engineForced", { core: engineForced })
    : coreResolution
      ? t("editor.engineResolved", { core: coreResolution.resolved })
      : "";
  const mux = "muxEnabled" in draft ? !!draft.muxEnabled : false;

  return (
    <Sheet
      open
      title={existing ? t("editor.editTitle") : t("editor.newTitle")}
      onClose={onClose}
      beforeClose={mayClose}
      headRight={
        <Btn variant="filled" sm icon="check" disabled={saving} onClick={() => void save()}>
          {t("editor.save")}
        </Btn>
      }
    >
      <BasicsSection
        draft={draft}
        setMeta={setMeta}
        setEndpoint={setEndpoint}
        errors={errors}
        groups={groups}
        group={group}
        setGroup={setGroup}
        viaOpts={viaOpts}
        changeProtocol={changeProtocol}
        engineForced={engineForced}
        engineHint={engineHint}
        route={route}
        routeOpts={routeOpts}
        setRoute={setRoute}
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
        <Btn
          variant="outline"
          block
          onClick={async () => {
            if (await mayClose()) onClose();
          }}
        >
          {t("editor.cancel")}
        </Btn>
        <Btn variant="filled" block onClick={() => void save()}>
          {t("editor.save")}
        </Btn>
      </div>
    </Sheet>
  );
}
