// Permissions: how much the chosen center may do on this machine. Its mode
// and network above; then the sections (folders, forbidden, allowed and sudo
// commands) on the left and the chosen one's list on the right. A folder's
// Read, Write and Run switch in its row; adding and editing are a form row
// in the list, and a removal asks in its row.
import { useState } from "react";
import { api } from "../api";
import { usePoll } from "../frame";
import { escapeControls, when } from "../format";
import { Btn, Icon, ListCard, Loading, LRow, More, PageHead, Pill, RemoveAsk, Seg, Switch, TextInput, failed, toast } from "../ui";
import { useNode } from "./App";
import { CenterTabs } from "./CenterTabs";
import type { CenterEntry, Json } from "./types";

type Folder = { path: string; read: boolean; write: boolean; execute: boolean; rights?: string };
type Perm = { rules: { allow?: string[]; deny?: string[]; sudo?: string[]; stale?: Record<string, string> }; folders: { folders?: Folder[] }; sudo: { sudo?: string } };
type Sec = "folders" | "deny" | "allow" | "sudo";

const MODES = [
  { value: "allowlist", label: "Allowlist", line: "Only what an allow rule names." },
  { value: "folder", label: "Folder", line: "What each folder below allows, as nerve-run." },
  { value: "user", label: "User", line: "All you can do, as you, protected files aside." },
];

/** The mode (for a time, and in allowlist mode as whom), and the network. */
function ModeStrip({ c, o }: { c: CenterEntry; o: Json }) {
  const { status } = useNode();
  const [mode, setMode] = useState(c.mode);
  const [hours, setHours] = useState("");
  const [owner, setOwner] = useState(!!c.as_owner);
  const changed = mode !== c.mode || hours !== "" || owner !== !!c.as_owner;
  return (
    <div className="card pad stack tight mb">
      <div className="row">
        <b>Mode</b>
        <Seg label="Mode" value={mode} onChange={setMode} options={MODES.map((m) => ({ value: m.value, label: m.label }))} />
        <span className="meta grow">
          {MODES.find((m) => m.value === mode)?.line} Deny rules count in every mode.
          {c.until ? ` Until ${when(c.until)}.` : ""}
        </span>
        <Switch
          checked={!!c.no_network}
          onChange={async (off) => {
            await api("POST", "/api/network", { center: c.name, off });
            await status.reload();
          }}
        >
          No network for its commands
        </Switch>
      </div>
      <div className="row">
        <span className="faint">For</span>
        <TextInput value={hours} onChange={setHours} type="number" min="1" placeholder="always" aria-label="For hours" className="num" />
        <span className="faint">hours</span>
        {mode === "allowlist" ? (
          <label className="check">
            <input type="checkbox" checked={owner} onChange={(e) => setOwner(e.target.checked)} />
            <span>Run as you (the owner)</span>
          </label>
        ) : null}
        <span className="grow" />
        <Btn
          kind={changed ? "primary" : ""}
          icon="check"
          act={async () => {
            // As the owner goes with allowlist mode only; its box is hidden
            // in the others, and the node refuses it there.
            await api("POST", "/api/mode", { center: c.name, mode, hours: Number(hours) || undefined, as_owner: mode === "allowlist" && owner });
            setHours("");
            await status.reload();
          }}
        >
          Set the mode
        </Btn>
      </div>
      <NetworkNotes c={c} o={o} />
    </div>
  );
}

/** What the network switch means here: whether this machine can keep the
 * commands off the network, and what does not run while it is on. */
function NetworkNotes({ c, o }: { c: CenterEntry; o: Json }) {
  if (!c.no_network) return null;
  return (
    <>
      {o.network_rules === false ? (
        <span className="meta">
          While this is on, none of these commands runs: this machine cannot block their network.
          <More summary="Why">
            <p className="meta">The node's seccomp filter cannot be used here.</p>
          </More>
        </span>
      ) : null}
      {/* The node says the commands run as the owner now (`network_off`),
          which nothing keeps off the network. */}
      {c.network_off === "as_owner" ? (
        o.installed ? (
          <span className="meta">
            While this is on, none of these commands runs: in this mode they run as you.
            <More summary="Why">
              <p className="meta">Nothing keeps commands that run as you off the network. Folder mode, or allowlist mode as nerve-run, runs them.</p>
            </More>
          </span>
        ) : (
          <span className="meta">
            While this is on, none of these commands runs: here they run as you, and nothing keeps them off the network.
            <More summary="Why">
              <p className="meta">
                A node run by hand runs commands as you; only folder mode keeps them off the network, as a user that is not root and on Linux 7.1 or later. The installed node runs folder mode's commands as nerve-run.
              </p>
            </More>
          </span>
        )
      ) : null}
      <span className="meta">No command on the sudo list runs while this is on.</span>
    </>
  );
}

/** Read, Write and Run, each a switch: write reads too, so Write turns Read
 * on and Read off turns Write off. */
function Rights({ f, set, label }: { f: Folder; set: (f: Folder) => Promise<unknown> | void; label: string }) {
  const [busy, setBusy] = useState(false);
  const flip = async (k: "read" | "write" | "execute") => {
    const next = { ...f, [k]: !f[k] };
    if (k === "write" && next.write) next.read = true;
    if (k === "read" && !next.read) next.write = false;
    setBusy(true);
    try {
      await set(next);
    } catch (e) {
      failed(e);
    } finally {
      setBusy(false);
    }
  };
  return (
    <span className="seg sm" role="group" aria-label={label}>
      {(
        [
          ["read", "Read"],
          ["write", "Write"],
          ["execute", "Run"],
        ] as const
      ).map(([k, l]) => (
        <button key={k} type="button" aria-pressed={f[k]} className={f[k] ? "on" : ""} disabled={busy} onClick={() => flip(k)}>
          {l}
        </button>
      ))}
    </span>
  );
}

const PLACEHOLDER: Record<Sec, string> = {
  folders: "/home/you/project",
  deny: "git push --force",
  allow: "git status, git *, or fs.read:~/notes/*",
  sudo: "apt update",
};
const ADD: Record<Sec, string> = {
  folders: "Add a folder…",
  deny: "Add a forbidden command…",
  allow: "Add an allowed command…",
  sudo: "Add a sudo command…",
};
const ICON: Record<Sec, string> = { folders: "folder", deny: "ban", allow: "check", sudo: "key" };

/** The form row of a folder (a new one, or one whose rights change). */
function FolderForm({ start, fixed, save, cancel }: { start: Folder; fixed?: boolean; save: (f: Folder) => Promise<unknown>; cancel: () => void }) {
  const [f, setF] = useState(start);
  return (
    <div className="prow form">
      <div className="pl">
        <Icon name="folder" />
        <TextInput value={f.path} onChange={(path) => setF({ ...f, path })} mono readOnly={fixed} placeholder={PLACEHOLDER.folders} aria-label="Folder" autoFocus={!fixed} />
      </div>
      <div className="pl2">
        <Rights f={f} set={(x) => setF(x)} label="Rights of the new folder" />
        <span className="sp" />
        <Btn kind="ghost" onClick={cancel}>
          Cancel
        </Btn>
        <Btn kind="primary" icon="check" act={() => save(f)}>
          Save
        </Btn>
      </div>
    </div>
  );
}

/** The form row of a rule: the command, and for a new one Wildcard (every
 * command of its program). An edited rule starts as listed, and Save waits
 * for a change, as in the app. */
function RuleForm({ sec, start, edit, save, cancel }: { sec: Sec; start: string; edit?: boolean; save: (rule: string, wildcard: boolean) => Promise<unknown>; cancel: () => void }) {
  const [rule, setRule] = useState(start);
  const [wild, setWild] = useState(false);
  const same = !rule.trim() || (edit && rule.trim() === start);
  return (
    <div className="prow form">
      <div className="pl">
        <Icon name={ICON[sec]} />
        <TextInput value={rule} onChange={setRule} mono placeholder={PLACEHOLDER[sec]} aria-label={edit ? "The rule" : "A new rule"} autoFocus />
      </div>
      <div className="pl2">
        {edit ? null : (
          <Switch checked={wild} onChange={setWild}>
            Wildcard: every command of this program
          </Switch>
        )}
        <span className="sp" />
        <Btn kind="ghost" onClick={cancel}>
          Cancel
        </Btn>
        <Btn kind="primary" icon="check" disabled={!!same} act={() => save(rule, wild)}>
          Save
        </Btn>
      </div>
    </div>
  );
}

function PermOf({ c }: { c: CenterEntry }) {
  const { status } = useNode();
  const perm = usePoll(() => api<Perm>("GET", `/api/perm?center=${encodeURIComponent(c.name)}`), [c.name], 0);
  const [sec, setSec] = useState<Sec>("folders");
  // The row being edited: "new", a folder's path or a rule.
  const [edit, setEdit] = useState<string | null>(null);
  const p = perm.data;
  const after = async () => {
    setEdit(null);
    await Promise.all([perm.reload(), status.reload()]);
  };
  if (!p) return <Loading />;
  const folders = p.folders.folders || [];
  const rules = p.rules;
  const sudoOn = p.sudo.sudo === "on";
  const count: Record<Sec, number> = { folders: folders.length, deny: (rules.deny || []).length, allow: (rules.allow || []).length, sudo: (rules.sudo || []).length };
  const choose = (s: Sec) => {
    setSec(s);
    setEdit(null);
  };
  const addFolder = async (f: Folder) => {
    if (!f.read && !f.write && !f.execute) {
      toast("A folder needs at least one right.", "error");
      return;
    }
    await api("POST", "/api/folders/add", { center: c.name, path: f.path, read: f.read, write: f.write, execute: f.execute });
    await after();
  };
  const list = sec === "folders" ? null : (sec as "deny" | "allow" | "sudo");
  const addRule = (l: string) => async (rule: string, wildcard: boolean) => {
    await api("POST", "/api/rules/add", { center: c.name, list: l, rule, wildcard });
  };
  let rows;
  if (sec === "folders") {
    rows = folders.map((f) =>
      edit === f.path ? (
        <FolderForm key={f.path} start={f} fixed save={addFolder} cancel={() => setEdit(null)} />
      ) : (
        <div key={f.path} className="prow">
          <Icon name="folder" />
          <span className="mono cut pth" title={f.path}>
            {f.path}
          </span>
          <Rights f={f} set={addFolder} label={`Rights in ${f.path}`} />
          <Btn kind="ghost" icon="edit" label="Edit" title="Edit" onClick={() => setEdit(f.path)} />
          <RemoveAsk
            bare
            question={`Take ${f.path} away?`}
            onConfirm={async () => {
              await api("POST", "/api/folders/remove", { center: c.name, path: f.path });
              await after();
            }}
          />
        </div>
      ),
    );
  } else {
    const l = list!;
    rows = (rules[l] || []).map((raw) => {
      // The entry as `rule` prints it, its line breaks written `\n`: a
      // one-line field cannot hold a real one, and `rule edit` takes the
      // entry and the new text in this form.
      const r = escapeControls(raw);
      return edit === raw ? (
        <RuleForm
          key={raw}
          sec={sec}
          start={r}
          edit
          cancel={() => setEdit(null)}
          save={async (rule) => {
            // One change in its place (`rule edit`), from the entry as
            // listed: typed through `rule add` again, a stored rule would
            // be escaped a second time and name another command.
            await api("POST", "/api/rules/edit", { center: c.name, list: l, rule: r, new: rule });
            await after();
          }}
        />
      ) : (
        <div key={raw} className="prow">
          <Icon name={ICON[sec]} />
          <span className="mono cut pth" title={r}>
            {r}
          </span>
          {rules.stale && rules.stale[raw] ? <Pill tone="warn">{rules.stale[raw]}</Pill> : null}
          <Btn kind="ghost" icon="edit" label="Edit" title="Edit" onClick={() => setEdit(raw)} />
          <RemoveAsk
            bare
            question="Remove this rule?"
            onConfirm={async () => {
              await api("POST", "/api/rules/remove", { center: c.name, list: l, rule: raw });
              await after();
            }}
          />
        </div>
      );
    });
  }
  const note =
    sec === "allow" ? (
      <div className="prow note meta">Count only in allowlist mode.</div>
    ) : sec === "sudo" ? (
      <div className="prow note meta">
        {sudoOn ? "Sudo is on: the commands on this list run with sudo." : "Off: nothing runs with sudo. Its list waits below. Turning sudo on is done at the CLI: sudo nerve-node sudo on."}
        {sudoOn ? (
          <Btn
            kind="danger"
            icon="ban"
            act={async () => {
              await api("POST", "/api/sudo/off");
              await after();
            }}
          >
            Turn off
          </Btn>
        ) : null}
      </div>
    ) : sec === "folders" ? (
      <div className="prow note meta">What the center may do in each folder in folder mode. A whole path, starting at /.</div>
    ) : null;
  return (
    <div className="psplit">
      <div className="pnav">
        <ListCard className="navpane">
          {(
            [
              ["folders", "Folders", ""],
              ["deny", "Forbidden commands", ""],
              ["allow", "Allowed commands", "Count only in allowlist mode."],
              ["sudo", "Sudo", sudoOn ? "Sudo is on." : "Nothing runs with sudo."],
            ] as [Sec, string, string][]
          ).map(([id, label, sub]) => (
            <LRow key={id} className={sub ? "two" : ""} current={sec === id} onPick={() => choose(id)}>
              <Icon name={ICON[id]} />
              <div className="grow">
                {label}
                {sub ? <div className="faint">{sub}</div> : null}
              </div>
              {id === "sudo" ? <Pill tone={sudoOn ? "ok" : ""} dot>{sudoOn ? "On" : "Off"}</Pill> : <span className="count">{count[id]}</span>}
            </LRow>
          ))}
        </ListCard>
      </div>
      <div className="pseg">
        <Seg
          label="Section"
          size="lg"
          value={sec}
          onChange={choose}
          options={[
            { value: "folders", label: "Folders", count: count.folders },
            { value: "deny", label: "Forbidden commands", count: count.deny },
            { value: "allow", label: "Allowed commands", count: count.allow },
            { value: "sudo", label: "Sudo", count: sudoOn ? "On" : "Off" },
          ]}
        />
      </div>
      <div className="stack tight">
        {sec === "folders" ? null : (
          <p className="meta">
            Commands allowed, forbidden or run with sudo; a built-in guard catches mistakes, not someone who hides the name.
          </p>
        )}
        <div className="card clip">
          {note}
          {rows}
          {edit === "new" ? (
            sec === "folders" ? (
              <FolderForm start={{ path: "", read: true, write: false, execute: false }} save={addFolder} cancel={() => setEdit(null)} />
            ) : (
              <RuleForm
                sec={sec}
                start=""
                cancel={() => setEdit(null)}
                save={async (rule, wildcard) => {
                  await addRule(list!)(rule, wildcard);
                  await after();
                }}
              />
            )
          ) : (
            <button type="button" className="prow add" onClick={() => setEdit("new")}>
              <Icon name="plus" />
              {ADD[sec]}
            </button>
          )}
        </div>
        {sec === "folders" ? null : (
          <More>
            <p className="meta">The guard's rules keep a center's commands off Nerve itself. They match by name only: the account the commands run as is the real protection.</p>
          </More>
        )}
      </div>
    </div>
  );
}

export function PermissionsPage() {
  const { o, center, status } = useNode();
  const c = o.centers.find((x) => x.name === center);
  const [asked, setAsked] = useState(0);
  return (
    <>
      <PageHead icon="shield" title="Permissions" sub="How much each center may do on this machine.">
        <Btn
          kind="ghost"
          size=""
          icon="refresh"
          act={async () => {
            await status.reload();
            setAsked((n) => n + 1);
          }}
        >
          Refresh
        </Btn>
      </PageHead>
      {!c ? (
        <div className="card">
          <p className="lnote top">Pair a center first.</p>
        </div>
      ) : (
        <>
          <CenterTabs />
          <ModeStrip key={`${c.name}:${c.mode}:${c.as_owner}`} c={c} o={o} />
          <PermOf key={`${c.name}:${asked}`} c={c} />
        </>
      )}
    </>
  );
}

