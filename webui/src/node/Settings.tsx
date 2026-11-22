// Settings: its sections as a list (this machine, root's (on Windows an
// administrator's) settings, any
// setting by its name, the web UI and its tokens), the picked one on the
// right. Every change is one `config set` of the node's CLI.
import { useState, type ReactNode } from "react";
import { api } from "../api";
import { usePoll } from "../frame";
import { plural, when } from "../format";
import { Btn, Empty, Field, Icon, LRow, ListCard, Loading, PageHead, Pill, RemoveAsk, Seg, Split, TextInput } from "../ui";
import { useNode } from "./App";
import { onWindows, type Json } from "./types";

const LEVELS = ["error", "warn", "info", "debug"];

function Section({ icon, title, sub, children }: { icon: string; title: string; sub?: string; children: ReactNode }) {
  return (
    <section className="card clip">
      <div className="sechead">
        <span className="tile sm">
          <Icon name={icon} />
        </span>
        <div>
          <h2>{title}</h2>
          {sub ? <p>{sub}</p> : null}
        </div>
      </div>
      <div className="secbody">{children}</div>
    </section>
  );
}

function General({ v, set }: { v: Json; set: (k: string, val: string) => Promise<void> }) {
  const [name, setName] = useState<string>(v.name || "");
  const [level, setLevel] = useState<string>(v.log_level);
  return (
    <Section icon="settings" title="This machine" sub="How centers show it, and how much the node writes to its log.">
      <div className="form-row">
        <Field label="Name of this machine">
          <TextInput value={name} onChange={setName} />
        </Field>
        <Btn kind="primary" icon="check" act={() => set("node.name", JSON.stringify(name))}>
          Save
        </Btn>
      </div>
      <div className="form-row">
        <div className="field">
          <span className="label">Log level</span>
          <Seg label="Log level" value={level} onChange={setLevel} options={LEVELS.map((l) => ({ value: l, label: l[0].toUpperCase() + l.slice(1) }))} />
        </div>
        <Btn icon="check" act={() => set("log.level", JSON.stringify(level))}>
          Set the log level
        </Btn>
      </div>
      <p className="meta">Keys are kept in {v.secret_storage === "keyring" ? "the system keyring" : "files"}.</p>
    </Section>
  );
}

/** What an unset machine setting is: the shell has a default. */
function unsetText(key: string, windows: boolean): string {
  if (key === "machine.shell") return windows ? "PowerShell (the default)" : "/bin/sh (the default)";
  return "not set";
}

function RootOnly({ v, windows }: { v: Json; windows: boolean }) {
  // Windows has no sudo program to name, and the node never runs as root
  // there: only the shell is an administrator's to change.
  const keys = (v.root_only as string[]).filter((k) => !windows || k === "machine.shell");
  return (
    <Section
      icon="lock"
      title={windows ? "Administrator's settings" : "Root's settings"}
      sub={windows ? "Changed only by an administrator, in the Nerve app." : "Changed only as root: sudo nerve-node config set …"}
    >
      <div className="kv">
        {keys.map((k) => {
          const val = v.machine[k.split(".")[1]];
          return (
            <span key={k} className="contents">
              <code className="mono k">{k}</code>
              <span>{val === undefined || val === null ? unsetText(k, windows) : String(val)}</span>
              <span />
            </span>
          );
        })}
      </div>
    </Section>
  );
}

function Advanced({ v, set, unset, windows }: { v: Json; set: (k: string, val: string) => Promise<void>; unset: (k: string) => Promise<void>; windows: boolean }) {
  const [key, setKey] = useState("");
  const [value, setValue] = useState("");
  return (
    <Section icon="sliders" title="Any setting" sub={windows ? "A setting of node.toml by its dotted name." : "A setting of node.toml by its dotted name, as nerve-node config set takes it."}>
      <div className="form-row">
        <Field label="Setting">
          <TextInput value={key} onChange={setKey} mono placeholder="limits.max_running" />
        </Field>
        <Field label="Value, as TOML">
          <TextInput value={value} onChange={setValue} mono placeholder="4" />
        </Field>
      </div>
      <div className="acts-row">
        <Btn kind="primary" icon="check" act={() => set(key, value)}>
          Set
        </Btn>
        <Btn kind="ghost" icon="x" act={() => unset(key)}>
          Unset
        </Btn>
      </div>
      <p className="meta">{windows ? "Backup, restore, update and uninstall are done in the Nerve app." : "Backup, restore, update and uninstall are done at the CLI."}</p>
      <pre className="code mono">{v.toml}</pre>
    </Section>
  );
}

/** When a web UI token was made: a local date, as the other pages show
 * times (the node keeps it as an ISO time). */
function made(at: string): string {
  const ms = Date.parse(at);
  return Number.isNaN(ms) ? at : when(ms);
}

function WebUi({ windows }: { windows: boolean }) {
  const ui = usePoll(() => api("GET", "/api/ui"), []);
  const s = ui.data;
  return (
    <Section
      icon="globe"
      title="Web UI"
      sub={windows ? "Turning it on or off, its address and new tokens are changed in the Nerve app: Settings, Network, Web UI." : "Turning it on or off, its address and new tokens are changed at the CLI: nerve-node ui."}
    >
      {!s ? (
        <Loading />
      ) : (
        <>
          <div className="row">
            <b className="mono">{s.ui.listen || "off"}</b>
            <Pill tone="ok" dot>
              {s.ui.status}
            </Pill>
            <span className="meta">{plural(s.ui.sessions, "session")} signed in</span>
          </div>
          {s.tokens.length ? (
            <div className="card rows clip">
              {s.tokens.map((t: Json) => (
                <div key={t.label} className="r">
                  <Icon name="key" />
                  <b className="grow">{t.label}</b>
                  <span className="faint">{t.made ? `Made ${made(t.made)}` : ""}</span>
                  <RemoveAsk
                    label="Revoke"
                    question={`Revoke ${t.label}? It no longer logs in, and the sessions it opened end, this one too if it did.`}
                    onConfirm={async () => {
                      await api("POST", "/api/ui/revoke", { label: t.label });
                      await ui.reload();
                    }}
                  />
                </div>
              ))}
            </div>
          ) : (
            <Empty icon="key">{windows ? "No token. The Nerve app makes one." : "No token. nerve-node ui token add <label> makes one."}</Empty>
          )}
          <p className="meta">{windows ? "A new token is made in the Nerve app." : "A new token is made at the CLI."}</p>
        </>
      )}
    </Section>
  );
}

const sections = (windows: boolean): [string, string, string][] => [
  ["general", "This machine", "settings"],
  ["root", windows ? "Administrator's settings" : "Root's settings", "lock"],
  ["advanced", "Any setting", "sliders"],
  ["ui", "Web UI", "globe"],
];

export function SettingsPage() {
  const settings = usePoll(() => api("GET", "/api/settings"), [], 0);
  const windows = onWindows(useNode().o);
  const [sec, setSec] = useState("general");
  const [open, setOpen] = useState(false);
  const v = settings.data;
  const set = async (key: string, value: string) => {
    await api("POST", "/api/settings/set", { key, value });
    await settings.reload();
  };
  const unset = async (key: string) => {
    await api("POST", "/api/settings/unset", { key });
    await settings.reload();
  };
  let detail: ReactNode = <Loading />;
  if (sec === "ui") detail = <WebUi windows={windows} />;
  else if (v) {
    detail =
      sec === "root" ? (
        <RootOnly v={v} windows={windows} />
      ) : sec === "advanced" ? (
        <Advanced v={v} set={set} unset={unset} windows={windows} />
      ) : (
        <General key={`${v.name}:${v.log_level}`} v={v} set={set} />
      );
  }
  return (
    <>
      <PageHead icon="settings" title="Settings" sub="The node's settings." />
      <Split
        open={open}
        onBack={() => setOpen(false)}
        list={
          <ListCard className="navpane">
            {sections(windows).map(([id, label, icon]) => (
              <LRow
                key={id}
                current={sec === id}
                onPick={() => {
                  setSec(id);
                  setOpen(true);
                }}
              >
                <Icon name={icon} />
                <span className="grow">{label}</span>
                <Icon name="chev-right" />
              </LRow>
            ))}
          </ListCard>
        }
        detail={detail}
      />
    </>
  );
}
