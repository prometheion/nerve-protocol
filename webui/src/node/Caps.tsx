// Capabilities: what the chosen center may use on this machine. Each
// capability and each of its actions has its On, Off or Hidden switch for
// that center in its row (none chosen: the mode decides): the built-in
// ones, your own, the programs' and those the center added, as `nerve-node
// cap` lists them, a left-out one with its reason (#213, L2-3: only the
// built-in ones had switches); then the capabilities of your own and the
// programs you allow, each added or changed in the details pane.
import { useState } from "react";
import { ApiError, api } from "../api";
import { usePoll } from "../frame";
import { CapFields, blankCapForm, type CapFormValue } from "../shared/capform";
import { AddRow, Banner, Btn, DSec, Detail, Dot, Field, FormCard, LGroup, LRow, ListCard, Loading, PageHead, Pill, RemoveAsk, Seg, Split, TextInput, toast, type Tone } from "../ui";
import { useNode } from "./App";
import { CenterTabs } from "./CenterTabs";

type Row = { name: string; effect?: string; source: string; summary?: string; kind?: string; centers?: Record<string, string>; now?: Record<string, string>; left_out?: string; broken?: string };
type Listing = {
  center?: string;
  known?: Record<string, string[]>;
  caps?: Record<string, string>;
  config?: { name: string; summary?: string; effect?: string; form: CapFormValue }[];
  programs?: { name: string; exe?: string; attached?: boolean | null; running?: boolean }[];
  capabilities?: Row[];
};

const SWITCH = ["on", "off", "hidden"].map((v) => ({ value: v, label: v[0].toUpperCase() + v.slice(1) }));

/** The capabilities a center's switches cover, from the rows `cap` lists,
 * each with its rows in order: not `settings`, which its grant governs, and
 * not what another center added, which only that one is offered. */
export function switchGroups(rows: Row[], center: string): { cap: string; source: string; rows: Row[] }[] {
  const groups: { cap: string; source: string; rows: Row[] }[] = [];
  for (const r of rows) {
    const set = r.centers ? r.centers[center] : undefined;
    if (set === "granted" || set === "not granted") continue;
    if (r.source.startsWith("center ") && r.source !== `center ${center}`) continue;
    const cap = r.name.split(".")[0];
    const g = groups.find((x) => x.cap === cap && x.source === r.source);
    if (g) g.rows.push(r);
    else groups.push({ cap, source: r.source, rows: [r] });
  }
  return groups;
}

/** Why `cap` left a row out, if it did. */
const leftOut = (r?: Row) => (r ? r.left_out || r.broken : undefined);

const effectTone = (e?: string): Tone => (e === "sense" || e === "actuate" ? "warn" : e === "execute" ? "accent" : "");

function CapSwitch({ center, cap, value, reload }: { center: string; cap: string; value: string | null; reload: () => Promise<unknown> }) {
  return (
    <Seg
      label={`${cap} for ${center}`}
      size="sm"
      value={value}
      onChange={async (setting) => {
        await api("POST", "/api/caps/set", { center, cap, setting });
        await reload();
      }}
      options={SWITCH}
    />
  );
}

function OwnForm({ start, adding, done, cancel }: { start: CapFormValue; adding: boolean; done: (name: string) => void; cancel: () => void }) {
  const [v, setV] = useState(start);
  const [refusal, setRefusal] = useState("");
  return (
    <FormCard
      icon="terminal"
      title={adding ? "Add a capability" : `Change ${v.name}`}
      sub="A fixed command that runs as nerve-run, in the folders."
      save={adding ? "Add" : "Save"}
      onCancel={cancel}
      refusal={refusal ? <Banner tone="danger">{refusal}</Banner> : null}
      onSave={async () => {
        setRefusal("");
        try {
          await api("POST", "/api/caps/save", { adding, form: v });
        } catch (e) {
          // The node checks the form as the desktop's dialog does and says
          // which field is wrong.
          if (e instanceof ApiError && !e.auth) {
            setRefusal(e.message);
            return;
          }
          throw e;
        }
        toast(adding ? `Added ${v.name}.` : `Saved ${v.name}.`);
        done(v.name);
      }}
    >
      <CapFields v={v} set={setV} adding={adding} />
    </FormCard>
  );
}

function ProgramForm({ done, cancel }: { done: (name: string) => void; cancel: () => void }) {
  const [name, setName] = useState("");
  const [exe, setExe] = useState("");
  return (
    <FormCard
      icon="window"
      title="Allow a program"
      sub="A program you allow adds capabilities while it runs, as a provider."
      save="Allow"
      onCancel={cancel}
      onSave={async () => {
        await api("POST", "/api/programs/allow", { name, exe });
        done(name);
      }}
    >
      <Field label="Name">
        <TextInput value={name} onChange={setName} placeholder="lights" />
      </Field>
      <Field label="Program">
        <TextInput value={exe} onChange={setExe} mono placeholder="/usr/local/bin/lights-provider" />
      </Field>
    </FormCard>
  );
}

function CapsOf({ center }: { center: string | null }) {
  const caps = usePoll(() => api<Listing>("GET", center ? `/api/caps?center=${encodeURIComponent(center)}` : "/api/caps"), [center], 0);
  const [sel, setSel] = useState<string | null>(null);
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState<{ kind: "own" | "program"; adding: boolean; v: CapFormValue } | null>(null);
  const v = caps.data;
  if (!v) return caps.error ? <Banner tone="danger">{caps.error.message}</Banner> : <Loading />;
  // The switches are a center's: none without one.
  const setting = v.caps || {};
  const rows = v.capabilities || [];
  const groups = center ? switchGroups(rows, center) : [];
  const own = v.config || [];
  const programs = v.programs || [];
  const rowOf = (name: string) => rows.find((r) => r.name === name);
  const pick = (x: string) => {
    setSel(x);
    setForm(null);
    setOpen(true);
  };
  const usable = (r?: Row) => (r && r.now && center ? r.now[center] === "on" : undefined);
  const first = groups.length ? `c:${groups[0].cap}` : own.length ? `o:${own[0].name}` : null;
  const current = form ? (form.adding ? `new-${form.kind}` : `o:${form.v.name}`) : sel ?? first;
  let detail;
  if (form) {
    detail =
      form.kind === "own" ? (
        <OwnForm
          key={form.adding ? "new" : form.v.name}
          start={form.v}
          adding={form.adding}
          cancel={() => setForm(null)}
          done={async (name) => {
            setForm(null);
            await caps.reload();
            setSel(`o:${name}`);
          }}
        />
      ) : (
        <ProgramForm
          cancel={() => setForm(null)}
          done={async (name) => {
            setForm(null);
            await caps.reload();
            setSel(`p:${name}`);
          }}
        />
      );
  } else if (current && current.startsWith("o:")) {
    const d = own.find((x) => `o:${x.name}` === current);
    detail = d ? (
      <Detail
        key={current}
        compact
        mono
        title={d.name}
        pills={d.form.effect ? <Pill tone={effectTone(d.form.effect)}>{d.form.effect}</Pill> : null}
        actions={
          <>
            <Btn icon="edit" onClick={() => setForm({ kind: "own", adding: false, v: { ...d.form } })}>
              Edit
            </Btn>
            <RemoveAsk
              question={`Remove ${d.name}?`}
              onConfirm={async () => {
                await api("POST", "/api/caps/remove", { name: d.name });
                setSel(null);
                await caps.reload();
              }}
            />
          </>
        }
      >
        <p className="lead">Runs a fixed command as nerve-run, in the folders. {d.summary || ""}</p>
        <DSec>
          <code className="code mono">{d.form.command}</code>
        </DSec>
      </Detail>
    ) : null;
  } else if (current && current.startsWith("p:")) {
    const p = programs.find((x) => `p:${x.name}` === current);
    const programRows = (name: string) => rows.filter((r) => r.source === `program ${name}`);
    detail = p ? (
      <Detail
        key={current}
        compact
        mono
        title={p.name}
        actions={
          <RemoveAsk
            question={`Stop allowing ${p.name}?`}
            confirm="Remove"
            onConfirm={async () => {
              await api("POST", "/api/programs/remove", { name: p.name });
              setSel(null);
              await caps.reload();
            }}
          />
        }
      >
        <p className="lead">A program you allow adds capabilities while it runs, as a provider.</p>
        <DSec>
          <code className="code mono">{p.exe || ""}</code>
        </DSec>
        <DSec title="What it offers">
          {programRows(p.name).length ? (
            <div className="kv">
              {programRows(p.name).map((r) => (
                <span key={r.name} className="contents">
                  <span className="k mono">{r.name}</span>
                  <span>{leftOut(r) ? `left out: ${leftOut(r)}` : [r.effect, r.kind].filter(Boolean).join(" ")}</span>
                  <span />
                </span>
              ))}
            </div>
          ) : (
            <p className="meta">{p.attached ? "Nothing." : "It shows once the program runs and attaches."}</p>
          )}
        </DSec>
      </Detail>
    ) : null;
  } else if (current) {
    // A capability ("c:fs") or one of its actions ("a:fs.read").
    const name = current.slice(2);
    const r = rowOf(name);
    const on = usable(r);
    const g = groups.find((x) => x.cap === name);
    const why = leftOut(r);
    detail = (
      <Detail
        compact
        mono
        title={name}
        pills={
          <>
            {r && r.effect ? <Pill tone={effectTone(r.effect)}>{r.effect}</Pill> : null}
            {r ? <span className="faint">{r.source}</span> : g ? <span className="faint">{g.source} · {g.rows.length} actions</span> : null}
          </>
        }
        actions={on === undefined ? null : <Pill tone={on ? "ok" : ""} dot>{on ? "Usable now" : "Not now"}</Pill>}
      >
        {r && r.summary ? <p className="lead">{r.summary}</p> : null}
        {why ? (
          <Banner tone="warn">Left out: {why}</Banner>
        ) : (
          <DSec title={`For ${center}`}>
            <CapSwitch center={center!} cap={name} value={setting[name] || null} reload={caps.reload} />
            <span className="faint">{setting[name] ? `Set: ${setting[name]}.` : "None chosen: its mode decides."}</span>
          </DSec>
        )}
        {r && r.centers && Object.keys(r.centers).length > 1 ? (
          <DSec title="Other centers">
            <div className="kv">
              {Object.entries(r.centers)
                .filter(([c]) => c !== center)
                .map(([c, s]) => (
                  <span key={c} className="contents">
                    <span className="k">{c}</span>
                    <span>{s === "default" ? "by its mode" : s}</span>
                    <span />
                  </span>
                ))}
            </div>
          </DSec>
        ) : null}
      </Detail>
    );
  }
  return (
    <Split
      variant="caps"
      open={open}
      onBack={() => setOpen(false)}
      list={
        <ListCard className="capl">
          {center ? <p className="lnote top">The switches are for {center}. None chosen: its mode decides.</p> : <p className="lnote top">The switches come with a paired center.</p>}
          {center && !groups.length ? <p className="lnote">Nothing to switch.</p> : null}
          {groups.map(({ cap, source, rows: actions }) => (
            <div key={`${source}:${cap}`}>
              <LRow className="cap" current={current === `c:${cap}`} onPick={() => pick(`c:${cap}`)}>
                <span className="cn">
                  <b className="mono">{cap}</b>
                  <Pill>{source}</Pill>
                </span>
                <span className="cd">{actions.map((r) => r.name.slice(cap.length + 1)).join(", ")}</span>
                <CapSwitch center={center!} cap={cap} value={setting[cap] || null} reload={caps.reload} />
              </LRow>
              {actions.map((r) => {
                const on = usable(r);
                const why = leftOut(r);
                return (
                  <LRow key={r.name} className="cap sub" current={current === `a:${r.name}`} onPick={() => pick(`a:${r.name}`)}>
                    <span className="cn">
                      <span className="mono cut">{r.name}</span>
                      {r.effect ? <Pill tone={effectTone(r.effect)}>{r.kind ? `${r.effect} ${r.kind}` : r.effect}</Pill> : null}
                    </span>
                    <span className="cd" title={why || r.summary}>
                      {why ? `left out: ${why}` : r.summary || ""}
                    </span>
                    {on === undefined || why ? null : <Dot tone={on ? "ok" : ""} />}
                    {why ? null : <CapSwitch center={center!} cap={r.name} value={setting[r.name] || null} reload={caps.reload} />}
                  </LRow>
                );
              })}
            </div>
          ))}
          <LGroup title="Your capabilities" count={own.length} />
          {own.map((d) => (
            <LRow key={d.name} className="cap" current={current === `o:${d.name}`} onPick={() => pick(`o:${d.name}`)}>
              <span className="cn">
                <span className="mono cut">{d.name}</span>
                {d.form.effect ? <Pill tone={effectTone(d.form.effect)}>{d.form.effect}</Pill> : null}
              </span>
              <span className="cd">{d.summary || d.form.command}</span>
            </LRow>
          ))}
          <AddRow
            label="Add a capability…"
            current={current === "new-own"}
            onPick={() => {
              setForm({ kind: "own", adding: true, v: blankCapForm() });
              setOpen(true);
            }}
          />
          <LGroup title="Programs" count={programs.length} />
          {programs.map((p) => (
            <LRow key={p.name} className="cap" current={current === `p:${p.name}`} onPick={() => pick(`p:${p.name}`)}>
              <span className="cn">
                <span className="mono cut">{p.name}</span>
                {p.attached == null ? null : <Pill tone={p.attached ? "ok" : ""}>{p.attached ? "attached" : "not attached"}</Pill>}
              </span>
              <span className="cd mono">{p.exe || ""}</span>
            </LRow>
          ))}
          <AddRow
            label="Allow a program…"
            current={current === "new-program"}
            onPick={() => {
              setForm({ kind: "program", adding: true, v: blankCapForm() });
              setOpen(true);
            }}
          />
        </ListCard>
      }
      detail={detail}
    />
  );
}

export function CapsPage() {
  const { center, status } = useNode();
  const [asked, setAsked] = useState(0);
  return (
    <>
      <PageHead icon="plug" title="Capabilities" sub={center ? `What ${center} may use on this machine.` : "What the centers may use on this machine."}>
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
      <CenterTabs />
      <CapsOf key={`${center}:${asked}`} center={center} />
    </>
  );
}

