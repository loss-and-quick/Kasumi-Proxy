// ============================================================
// features/add/AddSheet.tsx
// One place to add things: paste or scan whatever you have — subscription
// URLs, share links, an exported subscription list — and it's sorted out here.
// ============================================================
import { lazy, Suspense, useEffect, useMemo, useRef, useState } from "react";
import {
  Btn,
  Field,
  GroupPicker,
  IntervalField,
  RowToggle,
  SettingGroup,
  Sheet,
  SheetAction,
} from "../../components";
import { useT } from "../../i18n";
import { classifyAddInput } from "../../lib/add-input";
import { bridge } from "../../lib/bridge-provider";
import { type GroupChoice, groupChoiceReady } from "../../lib/groups";
import { wasReported } from "../../store/errors";
import { useAppStore } from "../../store/useAppStore";
import { readText } from "../profiles/clipboard";

const QrScannerSheet = lazy(() =>
  import("../../components/QrScannerSheet").then((module) => ({ default: module.QrScannerSheet })),
);

/** What was added, so the screen can show it. */
export type AddResult = { subs: number; profiles: number; profileGroup: string | null };

export function AddSheet({
  open,
  onClose,
  defaultGroup,
  inGroup = false,
  scanOnOpen = false,
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
  /** Open the camera straight away (the "Scan QR" entry). */
  scanOnOpen?: boolean;
  onManualProfile?: () => void;
  onManualSub?: () => void;
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

  const [text, setText] = useState("");
  const [groupEach, setGroupEach] = useState(true);
  const [group, setGroup] = useState<GroupChoice>(defaultGroup);
  const [autoUpdate, setAutoUpdate] = useState(false);
  const [interval, setIntervalMinutes] = useState(360); // minutes (06:00)
  const [profileCount, setProfileCount] = useState(0);
  const [scanning, setScanning] = useState(false);
  const [saving, setSaving] = useState(false);
  const textRef = useRef(text);
  textRef.current = text;
  // Read when the sheet opens, not on every render that hands in a new object.
  const openDefaults = useRef({ defaultGroup, inGroup, scanOnOpen });
  openDefaults.current = { defaultGroup, inGroup, scanOnOpen };

  // Each opening starts fresh, from the clipboard when it holds something.
  useEffect(() => {
    if (!open) return;
    setText("");
    setGroup(openDefaults.current.defaultGroup);
    setGroupEach(!openDefaults.current.inGroup);
    setScanning(openDefaults.current.scanOnOpen);
    readText().then((clip) => {
      const v = clip?.trim();
      if (v && !textRef.current.trim()) setText(v);
    });
  }, [open]);

  const { subs, profileText } = useMemo(
    () => classifyAddInput(text, { autoUpdate, interval }),
    [text, autoUpdate, interval],
  );
  // A URL that's already a subscription (or repeats in the paste) is skipped.
  const { fresh, known } = useMemo(() => {
    const seen = new Set(existingSubs.map((s) => s.url.trim()));
    const fresh = subs.filter((s) => !seen.has(s.url) && seen.add(s.url));
    return { fresh, known: subs.length - fresh.length };
  }, [subs, existingSubs]);

  // Count the profile links the backend recognises, once typing settles.
  useEffect(() => {
    if (!profileText.trim()) {
      setProfileCount(0);
      return;
    }
    let alive = true;
    const timer = window.setTimeout(() => {
      bridge
        .parseShareLinks(profileText)
        .then((parsed) => alive && setProfileCount(parsed.length))
        .catch(() => alive && setProfileCount(0));
    }, 250);
    return () => {
      alive = false;
      window.clearTimeout(timer);
    };
  }, [profileText]);

  const hasSubs = fresh.length > 0;
  const hasProfiles = profileCount > 0;
  // The picker files the profiles, and the subscriptions too unless each gets its own.
  const showPicker = hasProfiles || (hasSubs && !groupEach);
  const singleSubName = fresh.length === 1 ? fresh[0].remarks : undefined;
  const nothing = !hasSubs && !hasProfiles;

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
      if (profileText.trim()) {
        const parsed = await bridge.parseShareLinks(profileText);
        if (parsed.length) {
          const groupId = await resolveGroup(group, "");
          await addProfiles(parsed.map((p) => ({ ...p, meta: { ...p.meta, groupId } })));
          profileGroup = groupId;
          added = parsed.length;
        }
      }
    } catch (e) {
      if (!wasReported(e))
        notify(t("store.service.error", { error: String(e instanceof Error ? e.message : e) }));
      setSaving(false);
      return;
    }
    setSaving(false);
    onClose();
    onDone({ subs: fresh.length, profiles: added, profileGroup });
    for (const sub of fresh) if (sub.enabled) await updateSub(sub.id);
  };

  const summary = [
    hasSubs ? t("add.foundSubs", { count: fresh.length }) : null,
    hasProfiles ? t("add.foundProfiles", { count: profileCount }) : null,
    known ? t("add.alreadyAdded", { count: known }) : null,
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
                onClick={onManualSub}
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
              setText((cur) => (cur.trim() ? `${cur.trim()}\n${scanned}` : scanned));
              setScanning(false);
              return true;
            }}
          />
        </Suspense>
      )}
    </>
  );
}
