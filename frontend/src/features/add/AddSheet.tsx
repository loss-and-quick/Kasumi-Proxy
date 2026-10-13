// ============================================================
// features/add/AddSheet.tsx
// One place to add things: paste or scan whatever you have — subscription
// URLs, happ:// links, share links, an exported subscription list — and it's
// sorted out here.
// ============================================================
import { lazy, type ReactNode, Suspense, useEffect, useMemo, useRef, useState } from "react";
import {
  Btn,
  Field,
  GroupPicker,
  Icon,
  IntervalField,
  RowToggle,
  Select,
  SettingGroup,
  Sheet,
  SheetAction,
} from "../../components";
import { useT } from "../../i18n";
import {
  type AddInput,
  addInputFrom,
  appendScanned,
  EMPTY_ADD_INPUT,
  firstSubscriptionUrl,
  parseSubscriptionDump,
  resolveAddText,
  UNSUPPORTED_TEXT,
  withClipboard,
} from "../../lib/add-input";
import type { ResolvedImport } from "../../lib/bridge";
import { bridge } from "../../lib/bridge-provider";
import { BASE_GROUP_ID, type GroupChoice, groupChoiceReady } from "../../lib/groups";
import { wasReported } from "../../store/errors";
import { useAppStore } from "../../store/useAppStore";
import { readText } from "../profiles/clipboard";
import { RoutingImportCard } from "../subscriptions/RoutingImportCard";

const QrScannerSheet = lazy(() =>
  import("../../components/QrScannerSheet").then((module) => ({ default: module.QrScannerSheet })),
);

/** What was added, so the screen can show it. */
export type AddResult = {
  subs: number;
  profiles: number;
  profileGroup: string | null;
  routes: number;
};

type RouteChoice = { groupId: string; activate: boolean };

export function AddSheet({
  open,
  onClose,
  defaultGroup,
  inGroup = false,
  onManualProfile,
  onManualSub,
  onDone,
}: {
  open: boolean;
  onClose: () => void;
  /** Where pasted profiles go unless another group is picked. */
  defaultGroup: GroupChoice;
  /** Added from inside a group: everything, subscriptions too, goes there by
   *  default instead of each subscription getting a group of its own. */
  inGroup?: boolean;
  onManualProfile?: () => void;
  /** Gets the subscription URL typed so far, if the text holds one. */
  onManualSub?: (url: string | null) => void;
  onDone: (result: AddResult) => void;
}) {
  const t = useT();
  const groups = useAppStore((s) => s.groups);
  const existingSubs = useAppStore((s) => s.subscriptions);
  const notify = useAppStore((s) => s.notify);
  const saveSubscription = useAppStore((s) => s.saveSubscription);
  const resolveGroup = useAppStore((s) => s.resolveGroup);
  const addProfiles = useAppStore((s) => s.addProfiles);
  const updateSub = useAppStore((s) => s.updateSub);
  const importRoutingLink = useAppStore((s) => s.importRoutingLink);

  const [text, setText] = useState("");
  const [groupEach, setGroupEach] = useState(true);
  const [group, setGroup] = useState<GroupChoice>(defaultGroup);
  const [autoUpdate, setAutoUpdate] = useState(false);
  const [interval, setIntervalMinutes] = useState(360); // minutes (06:00)
  // The backend's sorting of `text`, kept until the next one arrives.
  const [resolved, setResolved] = useState<{ text: string; value: ResolvedImport } | null>(null);
  const [routeChoices, setRouteChoices] = useState<RouteChoice[]>([]);
  const [profileCount, setProfileCount] = useState(0);
  const [scanning, setScanning] = useState(false);
  const [saving, setSaving] = useState(false);
  // Read when the sheet opens, not on every render that hands in a new object.
  const openDefaults = useRef({ defaultGroup, inGroup });
  openDefaults.current = { defaultGroup, inGroup };

  // Each opening starts fresh, from the clipboard when it holds something.
  useEffect(() => {
    if (!open) return;
    setText("");
    setGroup(openDefaults.current.defaultGroup);
    setGroupEach(!openDefaults.current.inGroup);
    setScanning(false);
    readText().then((clip) => setText((cur) => withClipboard(cur, clip)));
  }, [open]);

  const dump = useMemo(
    () => parseSubscriptionDump(text, { autoUpdate, interval }),
    [text, autoUpdate, interval],
  );
  const isDump = dump !== null;
  const encryptedName = t("add.encryptedName");
  const input: AddInput = useMemo(() => {
    if (dump) return { ...EMPTY_ADD_INPUT, subs: dump };
    if (!resolved) return EMPTY_ADD_INPUT;
    return addInputFrom(resolved.value, { autoUpdate, interval }, encryptedName);
  }, [dump, resolved, autoUpdate, interval, encryptedName]);
  const { subs, routing, unsupported } = input;
  // Typing ran ahead of the last answer: nothing is added until it catches up.
  const stale = !isDump && text.trim() !== "" && resolved?.text !== text;
  // A URL that's already a subscription (or repeats in the paste) is skipped.
  const { fresh, known } = useMemo(() => {
    const seen = new Set(existingSubs.map((s) => s.url.trim()));
    const fresh = subs.filter((s) => !seen.has(s.url) && seen.add(s.url));
    return { fresh, known: subs.length - fresh.length };
  }, [subs, existingSubs]);

  // Once typing settles, the backend sorts the text and counts the profile links in it.
  useEffect(() => {
    if (!text.trim() || isDump) {
      setResolved(null);
      setProfileCount(0);
      return;
    }
    let alive = true;
    const timer = window.setTimeout(async () => {
      const { value, profileCount } = await resolveAddText(text, bridge);
      if (!alive) return;
      setResolved({ text, value });
      setProfileCount(profileCount);
    }, 250);
    return () => {
      alive = false;
      window.clearTimeout(timer);
    };
  }, [text, isDump]);

  // Each routing profile goes to the group the sheet was opened for, or the base one.
  useEffect(() => {
    const start = openDefaults.current.defaultGroup;
    const groupId = "id" in start ? start.id : BASE_GROUP_ID;
    setRouteChoices(routing.map((r) => ({ groupId, activate: r.activate })));
  }, [routing]);

  const hasSubs = fresh.length > 0;
  const hasProfiles = profileCount > 0;
  const hasRouting = routing.length > 0 && routeChoices.length === routing.length;
  const encryptedUrls = new Set(
    resolved?.value.subscriptions.filter((s) => s.encrypted).map((s) => s.url) ?? [],
  );
  const encryptedCount = fresh.filter((s) => encryptedUrls.has(s.url)).length;
  // The picker files the profiles, and the subscriptions too unless each gets its own.
  const showPicker = hasProfiles || (hasSubs && !groupEach);
  const singleSubName = fresh.length === 1 ? fresh[0].remarks : undefined;
  const nothing = stale || (!hasSubs && !hasProfiles && !hasRouting);

  const openManualSub = async () => {
    onManualSub?.(await firstSubscriptionUrl(text, { autoUpdate, interval }, bridge));
  };

  const submit = async () => {
    if (showPicker && !groupChoiceReady(group, groupEach ? "" : (singleSubName ?? ""))) {
      notify(t("groups.picker.needName"));
      return;
    }
    setSaving(true);
    let profileGroup: string | null = null;
    let added = 0;
    try {
      // Sequential so each write sees the previous one (a shared new group is made once).
      for (const sub of fresh) {
        // An exported list keeps the group it names when that group still exists.
        const kept = groups.find((g) => g.id === sub.groupId);
        const choice: GroupChoice = !groupEach ? group : kept ? { id: kept.id } : { newName: "" };
        await saveSubscription(sub, choice);
      }
      if (input.profileText.trim()) {
        const parsed = await bridge.parseShareLinks(input.profileText);
        if (parsed.length) {
          const groupId = await resolveGroup(group, "");
          await addProfiles(parsed.map((p) => ({ ...p, meta: { ...p.meta, groupId } })));
          profileGroup = groupId;
          added = parsed.length;
        }
      }
      for (const [i, link] of routing.entries()) {
        const choice = routeChoices[i];
        await importRoutingLink(link.routing, choice.groupId, choice.activate);
      }
    } catch (e) {
      if (!wasReported(e))
        notify(t("store.service.error", { error: String(e instanceof Error ? e.message : e) }));
      setSaving(false);
      return;
    }
    setSaving(false);
    onClose();
    onDone({ subs: fresh.length, profiles: added, profileGroup, routes: routing.length });
    for (const sub of fresh) if (sub.enabled) await updateSub(sub.id);
  };

  const setRouteChoice = (i: number, patch: Partial<RouteChoice>) =>
    setRouteChoices((all) => all.map((c, j) => (j === i ? { ...c, ...patch } : c)));

  const summary = [
    hasSubs ? t("add.foundSubs", { count: fresh.length }) : null,
    hasProfiles ? t("add.foundProfiles", { count: profileCount }) : null,
    hasRouting ? t("add.foundRouting", { count: routing.length }) : null,
    known ? t("add.alreadyAdded", { count: known }) : null,
    unsupported.length ? t("add.foundUnsupported", { count: unsupported.length }) : null,
  ].filter((x): x is string => !!x);

  return (
    <>
      <Sheet open={open} title={t("add.title")} onClose={onClose}>
        <Field
          label={t("add.inputLabel")}
          value={text}
          onChange={setText}
          area
          mono={false}
          placeholder={t("add.inputPh")}
          hint={
            text.trim()
              ? summary.length
                ? summary.join(" · ")
                : t("add.nothingFound")
              : t("add.inputHint")
          }
        />

        {encryptedCount > 0 && (
          <Note
            icon="lock"
            color="var(--primary)"
            title={t("add.encrypted.title", { count: encryptedCount })}
          >
            {t("add.encrypted.body")}
          </Note>
        )}
        {unsupported.map((u, i) => (
          <Note
            // biome-ignore lint/suspicious/noArrayIndexKey: the same link may be pasted twice.
            key={i}
            icon="block"
            color={
              u.kind === "urlDecrypt" || u.kind === "invalid"
                ? "var(--warn)"
                : "var(--on-surface-variant)"
            }
            title={t(UNSUPPORTED_TEXT[u.kind])}
          >
            <span className="mono truncate" dir="ltr" style={{ display: "block", fontSize: 11.5 }}>
              {u.text}
            </span>
          </Note>
        ))}

        {hasSubs && (
          <>
            <RowToggle
              icon="create_new_folder"
              title={t("add.groupEach", { count: fresh.length })}
              sub={
                fresh.length === 1
                  ? t("groups.picker.newNamed", { name: fresh[0].remarks })
                  : t("subs.import.groupEachSub")
              }
              on={groupEach}
              onChange={setGroupEach}
            />
            <RowToggle
              icon="autorenew"
              title={t("subs.autoUpdate")}
              sub={t("subs.autoUpdateSub")}
              on={autoUpdate}
              onChange={setAutoUpdate}
            />
            {autoUpdate && (
              <SettingGroup>
                <IntervalField
                  label={t("subs.interval")}
                  minutes={interval}
                  onChange={setIntervalMinutes}
                />
              </SettingGroup>
            )}
          </>
        )}

        {showPicker && (
          <GroupPicker
            label={hasSubs && groupEach ? t("add.profilesGroup") : t("subs.edit.targetGroup")}
            groups={groups}
            value={group}
            onChange={setGroup}
            suggestedName={groupEach ? undefined : singleSubName}
            style={{ marginTop: 10 }}
          />
        )}

        {hasRouting &&
          routing.map((link, i) => (
            <RoutingImportCard
              // biome-ignore lint/suspicious/noArrayIndexKey: the same profile may be pasted twice.
              key={i}
              groupId={routeChoices[i].groupId}
              routing={link.routing}
              activate={routeChoices[i].activate}
              onActivate={(activate) => setRouteChoice(i, { activate })}
            >
              <Select
                label={t("add.routingGroup")}
                value={routeChoices[i].groupId}
                options={groups.map((g) => ({ value: g.id, label: g.name }))}
                onChange={(groupId) => setRouteChoice(i, { groupId })}
              />
            </RoutingImportCard>
          ))}

        <div style={{ display: "flex", gap: 10, marginTop: 14, flexWrap: "wrap" }}>
          <Btn variant="outline" icon="qr_code_scanner" onClick={() => setScanning(true)}>
            {t("profiles.import.scanQr")}
          </Btn>
          <div style={{ flex: 1 }} />
          <Btn variant="text" onClick={onClose}>
            {t("profiles.import.cancel")}
          </Btn>
          <Btn
            variant="filled"
            icon="check"
            disabled={nothing || saving}
            onClick={() => void submit()}
          >
            {t("add.submit")}
          </Btn>
        </div>

        {(onManualProfile || onManualSub) && (
          <div style={{ display: "flex", flexDirection: "column", marginTop: 14 }}>
            {onManualProfile && (
              <SheetAction
                icon="edit_note"
                label={t("profiles.add.manual")}
                sub={t("profiles.add.manualSub")}
                onClick={onManualProfile}
              />
            )}
            {onManualSub && (
              <SheetAction
                icon="tune"
                label={t("add.subWithOptions")}
                sub={t("add.subWithOptionsSub")}
                onClick={() => void openManualSub()}
              />
            )}
          </div>
        )}
      </Sheet>

      {scanning && (
        <Suspense fallback={null}>
          <QrScannerSheet
            open
            title={t("qr.scan.title")}
            onClose={() => setScanning(false)}
            onResult={(scanned) => {
              setText((cur) => appendScanned(cur, scanned));
              setScanning(false);
              return true;
            }}
          />
        </Suspense>
      )}
    </>
  );
}

/** A card under the input: what an encrypted link means, or why a link is skipped. */
function Note({
  icon,
  color,
  title,
  children,
}: {
  icon: string;
  color: string;
  title: string;
  children: ReactNode;
}) {
  return (
    <div
      role="note"
      style={{
        display: "flex",
        gap: 10,
        alignItems: "flex-start",
        marginTop: 10,
        padding: "10px 12px",
        background: "var(--sc-high)",
        borderRadius: 12,
        fontSize: 13,
        lineHeight: 1.45,
      }}
    >
      <Icon name={icon} style={{ fontSize: 20, color, flexShrink: 0 }} />
      <div style={{ minWidth: 0, flex: 1 }}>
        <div style={{ fontWeight: 500 }}>{title}</div>
        <div style={{ color: "var(--on-surface-variant)", marginTop: 2 }}>{children}</div>
      </div>
    </div>
  );
}
