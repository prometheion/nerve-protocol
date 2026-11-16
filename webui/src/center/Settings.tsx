// Settings: its sections as a list (the center, its key, each machine's own
// settings), the picked one on the right.
import { useEffect, useState, type ReactNode } from "react";
import { api } from "../api";
import { usePoll } from "../frame";
import { plural, when } from "../format";
import { Banner, Btn, Dot, Field, Icon, LRow, ListCard, Loading, More, PageHead, Pill, SecretInput, Seg, Split, TextArea, TextInput, ask, copy, toast } from "../ui";
import { useCenter } from "./App";
import type { Json, Node } from "./types";

// The levels the center can keep its log at.
const LEVELS = [
  { value: "error", label: "Error" },
  { value: "warn", label: "Warn" },
  { value: "info", label: "Info" },
  { value: "debug", label: "Debug" },
];

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

function CenterSection({ c, reload }: { c: Json; reload: () => Promise<unknown> }) {
  const [name, setName] = useState<string>(c.name);
  const [days, setDays] = useState(String(c.retention_days));
  const [minutes, setMinutes] = useState(String(c.pair_code_minutes));
  const [level, setLevel] = useState<string>(c.log_level);
  return (
    <Section icon="settings" title="Center" sub="Its name, and how long it keeps what it keeps.">
      <Field label="Name">
        <TextInput value={name} onChange={setName} maxLength={64} />
      </Field>
      <div className="form-row">
        <Field label="Keep statistics for (days)" className="narrow">
          <TextInput value={days} onChange={setDays} type="number" min="1" max="366" className="num" />
        </Field>
        <Field label="Pairing code valid for (minutes, at most 1440)" className="narrow">
          <TextInput value={minutes} onChange={setMinutes} type="number" min="1" max="1440" className="num" />
        </Field>
      </div>
      <div className="field">
        <span className="label">Log level</span>
        <Seg label="Log level" value={level} onChange={setLevel} options={LEVELS} />
        <span className="hint">Info is the default. Debug adds detail for tracking down a problem and makes the log file grow faster.</span>
      </div>
      {c.log_level_pinned ? (
        <p className="meta">The --log option (NERVE_CENTER_LOG) sets the level at every start and wins over this setting. This run keeps the level {c.log_level_now}.</p>
      ) : null}
      <div className="ffoot">
        <Btn
          kind="primary"
          size=""
          act={async () => {
            await api("POST", "/api/center", { name, retention_days: Number(days), pair_code_minutes: Number(minutes), log_level: level });
            toast("Saved.");
            await reload();
          }}
        >
          Save
        </Btn>
      </div>
    </Section>
  );
}

/** The center's TLS key (docs/dev/identity-and-pairing.md). The new pin is
 * shown once, when the rotation is made, as a pairing shows its code. */
function KeySection({ k, reload }: { k: Json; reload: () => Promise<unknown> }) {
  const [pin, setPin] = useState<string | null>(null);
  return (
    <Section icon="lock" title="Center key" sub="Machines check the center by this key's pin; a new key keeps the old one 7 more days.">
      {pin ? (
        <Banner tone="ok" icon="key">
          <div className="row">
            <span className="grow">
              New pin, shown once: <code className="mono wrap">{pin}</code>
            </span>
            <Btn kind="ghost" icon="copy" onClick={() => copy(pin)}>
              Copy
            </Btn>
            <Btn kind="ghost" icon="x" label="Hide" title="Hide" onClick={() => setPin(null)} />
          </div>
        </Banner>
      ) : null}
      <p className="meta">
        Pin served now: <code className="mono wrap">{k.pin}</code>
      </p>
      {k.grace_until_ms ? <p className="meta">A rotation is in its grace: the old key is served until {when(k.grace_until_ms)}.</p> : null}
      <More>
        <p className="meta">Rotating it makes a new key; the old one is served for 7 more days, so the machines learn the new one when they link.</p>
      </More>
      <div className="acts-row">
        {k.grace_until_ms ? (
          <Btn
            kind="danger"
            icon="key"
            act={async () => {
              const yes = await ask({ title: "Serve the new key now?", message: "Machines that were not told of the rotation cannot link any more and have to be paired again.", confirm: "Serve it now", danger: true });
              if (!yes) return;
              await api("POST", "/api/center/key/finish");
              toast("The center serves its new key now.");
              await reload();
            }}
          >
            Serve the new key now
          </Btn>
        ) : (
          <Btn
            icon="key"
            act={async () => {
              const yes = await ask({ title: "Rotate the center's key?", message: "Machines that link in the next 7 days follow it. A machine away longer, or one older than this center, has to be paired again.", confirm: "Rotate" });
              if (!yes) return;
              const r = await api("POST", "/api/center/key/rotate");
              setPin(r.pin);
              toast(`The key was rotated; ${plural(r.told, "machine")} linked now ${r.told === 1 ? "was" : "were"} told.`);
              await reload();
            }}
          >
            Rotate key
          </Btn>
        )}
      </div>
    </Section>
  );
}

// The sudo password is sealed here, in the browser, for a one-shot offer the
// machine signed (docs/dev/spec/protocol.md §7.4.1): X25519, HKDF-SHA256,
// AES-256-GCM. The center relays the sealed box and cannot open it.
const b64 = (buf: ArrayBuffer | Uint8Array) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

export async function sealSudo(offer: { key: string; offer: string }, password: string) {
  const enc = new TextEncoder();
  const subtle = crypto.subtle;
  const mine = (await subtle.generateKey({ name: "X25519" }, false, ["deriveBits"])) as CryptoKeyPair;
  const theirs = await subtle.importKey("raw", unb64(offer.key), { name: "X25519" }, false, []);
  const shared = await subtle.deriveBits({ name: "X25519", public: theirs } as Json, mine.privateKey, 256);
  const hkdf = await subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  const key = await subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: enc.encode("nerve-sudo-v1"), info: enc.encode(offer.offer) },
    hkdf,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plain = enc.encode(JSON.stringify({ password, offer: offer.offer, ts: Date.now() }));
  const ct = await subtle.encrypt({ name: "AES-GCM", iv, additionalData: enc.encode(offer.offer) }, key, plain);
  const pub = await subtle.exportKey("raw", mine.publicKey);
  return { offer: offer.offer, key: b64(pub), iv: b64(iv), ct: b64(ct) };
}

/** The machine's sudo switch: on only with a password its `sudo -v`
 * accepts. A Windows machine takes no password from here: sudo takes the
 * owner's Windows password there, which only the app on the machine asks
 * for. */
export function SudoSwitch({ n, state, set }: { n: Node; state: string | null; set: (s: string) => void }) {
  const [pw, setPw] = useState("");
  const off = (
    <Btn
      act={async () => {
        const r = await api("POST", "/api/nodes/sudo", { id: n.id, on: false });
        set(r.sudo);
        toast(`Sudo is off for ${n.name}.`);
      }}
    >
      Turn sudo off
    </Btn>
  );
  const label = <span className="meta">Sudo: {state === null ? "…" : state === "on" ? "on" : "off"}</span>;
  if (n.platform === "windows") {
    return (
      <div className="acts-row">
        {label}
        <span className="meta">Turn it on in the Nerve app on that machine, Permissions, Sudo.</span>
        {off}
      </div>
    );
  }
  return (
    <div className="form-row">
      {label}
      <Field label="Sudo password">
        <SecretInput value={pw} onChange={setPw} placeholder="sudo password" aria-label={`Sudo password of ${n.name}`} />
      </Field>
      <Btn
        act={async () => {
          const password = pw;
          setPw("");
          if (!password) {
            toast("Enter the machine's sudo password first.", "error");
            return;
          }
          const offer = await api("POST", "/api/nodes/sudo/offer", { id: n.id });
          const sealed = await sealSudo(offer, password);
          const r = await api("POST", "/api/nodes/sudo", { id: n.id, on: true, sealed });
          set(r.sudo);
          toast(`Sudo is on for ${n.name}: sudo commands on the sudo allow list run. Only the machine's owner adds to that list, on the machine.`);
        }}
      >
        Turn sudo on
      </Btn>
      {off}
    </div>
  );
}

/** A machine's own settings, as JSON, fetched when it is picked. */
function MachineSettings({ n }: { n: Node }) {
  const [text, setText] = useState("");
  const [version, setVersion] = useState<number | null>(null);
  const [msg, setMsg] = useState("");
  const [sudo, setSudo] = useState<string | null>(null);
  const load = async () => {
    const s = await api("GET", `/api/nodes/settings?id=${encodeURIComponent(n.id)}`);
    setText(JSON.stringify(s.document, null, 2));
    setVersion(s.version);
    setMsg(`Version ${s.version}.`);
    setSudo(s.sudo);
  };
  const ready = n.settings_write && n.online;
  useEffect(() => {
    if (ready) load().catch((e) => setMsg(e.message));
  }, [n.id, ready]);
  if (!n.settings_write) {
    return (
      <p className="meta">
        {n.platform === "windows"
          ? "This machine keeps its settings to itself (settings grant off). Change them in the Nerve app on the machine."
          : "This machine keeps its settings to itself (settings grant off). Change them with nerve-node on the machine."}
      </p>
    );
  }
  if (!n.online) return <p className="meta">Offline; its settings can be changed when it is back.</p>;
  return (
    <div className="stack tight">
      <SudoSwitch n={n} state={sudo} set={setSudo} />
      <TextArea className="tall" value={text} onChange={setText} aria-label={`Settings of ${n.name}`} />
      <p className="meta" role="status">
        {msg}
      </p>
      <div className="acts-row">
        <Btn icon="refresh" act={load}>
          Reload
        </Btn>
        <Btn
          kind="primary"
          act={async () => {
            let doc;
            try {
              doc = JSON.parse(text);
            } catch (e) {
              setMsg(`Not valid JSON: ${(e as Error).message}`);
              return;
            }
            try {
              const r = await api("POST", "/api/nodes/settings", { id: n.id, document: doc, if_version: version });
              setVersion(r.version);
              setMsg(`Saved, version ${r.version}.`);
              toast(`Saved the settings of ${n.name}.`);
            } catch (e) {
              setMsg(`The machine refused: ${(e as Error).message}`);
            }
          }}
        >
          Save
        </Btn>
      </div>
    </div>
  );
}

function MachinesSection({ nodes }: { nodes: Node[] }) {
  const [id, setId] = useState<string | null>(null);
  const n = nodes.find((x) => x.id === id) || nodes[0];
  return (
    <Section icon="server" title="Machines" sub="Settings kept on each machine itself, as JSON: an advanced view.">
      {n ? (
        <>
          <div className="ctabs">
            <span className="faint">Machine</span>
            <Seg label="Machine" value={n.id} onChange={setId} options={nodes.map((x) => ({ value: x.id, label: x.name }))} />
          </div>
          <div className="row">
            <Dot tone={n.online ? "ok" : ""} />
            <b>{n.name}</b>
            <Pill tone={n.online ? "ok" : ""}>{n.online ? "online" : "offline"}</Pill>
          </div>
          <MachineSettings key={n.id} n={n} />
        </>
      ) : (
        <p className="meta">No machines yet.</p>
      )}
    </Section>
  );
}

const SECTIONS: [string, string, string][] = [
  ["center", "Center", "settings"],
  ["key", "Center key", "lock"],
  ["machines", "Machines", "server"],
];

export function SettingsPage() {
  const { ov } = useCenter();
  const center = usePoll(() => api("GET", "/api/center"), [], 0);
  const [sec, setSec] = useState("center");
  const [open, setOpen] = useState(false);
  const c = center.data;
  let detail: ReactNode = <Loading />;
  if (c) {
    detail =
      sec === "key" ? <KeySection k={c.key} reload={center.reload} /> : sec === "machines" ? <MachinesSection nodes={ov.nodes} /> : <CenterSection key={JSON.stringify(c)} c={c} reload={center.reload} />;
  }
  return (
    <>
      <PageHead icon="settings" title="Settings" sub="The center, its key, and each machine's own settings." />
      <Split
        open={open}
        onBack={() => setOpen(false)}
        list={
          <ListCard className="navpane">
            {SECTIONS.map(([id, label, icon]) => (
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
