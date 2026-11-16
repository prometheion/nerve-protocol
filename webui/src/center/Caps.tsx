// Capabilities: what a machine offers the agent and where each unit comes
// from, what the center left out and why, and the capabilities this center
// added there itself (docs/dev/web-uis.md). A machine that gave this center
// the settings grant takes changes: add, edit, remove. One without it is
// shown read only.
import { useEffect, useRef, useState } from "react";
import { ApiError, api } from "../api";
import { usePoll } from "../frame";
import { CapFields, blankCapForm, type CapErrors, type CapFormValue } from "../shared/capform";
import { AddRow, Banner, Btn, DSec, Detail, Empty, FormCard, LGroup, LRow, ListCard, Loading, More, PageHead, Picker, Pill, RemoveAsk, Seg, Split, toast, type Tone } from "../ui";
import { useCenter } from "./App";
import type { Json, Node } from "./types";

type Unit = { name: string; effect: string; kind: string; off?: boolean; source: string; summary?: string };
type Added = { name: string; effect: string; summary?: string; form: CapFormValue; left_out?: string | null };
type Caps = {
  id: string;
  online: boolean;
  settings_write: boolean;
  node: Node;
  units: Unit[];
  broken: { name: string; reason: string }[];
  added: { entries?: Added[]; refused?: string; error?: string } | null;
};

/** What a unit does, in a tone: one that senses or acts on the world stands
 * out, as the owner turns it on. */
export function effectTone(effect: string): Tone {
  return effect === "sense" || effect === "actuate" ? "warn" : effect === "read" ? "" : "accent";
}

/** Why the machine does not offer one this center added, where it is not
 * left out: its policy decides it as a command, so in folder mode it needs
 * an on and in allowlist mode an allow rule, and one that senses or
 * actuates waits for the owner. */
function NotOffered({ d, e }: { d: Caps; e: Added }) {
  if (e.left_out || d.units.some((u) => u.name === e.name)) return null;
  if (e.effect === "sense" || e.effect === "actuate") {
    return (
      <p className="meta">
        Not offered now:{" "}
        {d.node && d.node.platform === "windows"
          ? `only the machine's owner turns it on, in the Nerve app on that machine: Capabilities, ${e.name}.`
          : `only the machine's owner turns it on, with nerve-node cap set ${e.name} on --center and this center's name on that machine.`}
      </p>
    );
  }
  return (
    <div>
      <p className="meta">Not offered: the machine's policy does not allow it yet.</p>
      <More summary="How">
        <p className="meta">
          Turn it on in Settings › Machines, by its full name: in folder mode with an on for it ("caps": {`{"${e.name}": "on"}`}), in allowlist mode with the allow rule {e.name}. An off the owner set stays.
        </p>
      </More>
    </div>
  );
}

const idle = (d: Caps, e: Added) => !e.left_out && !d.units.some((u) => u.name === e.name);

/** The form to add or change one, checked by the center with the machine's
 * own rules while it is typed (/api/caps/check); the machine checks it
 * again on save and may refuse it with its own reason. */
function CapForm({ d, start, adding, done, cancel }: { d: Caps; start: CapFormValue; adding: boolean; done: (name: string) => void; cancel: () => void }) {
  const [v, setV] = useState(start);
  const [errors, setErrors] = useState<CapErrors>({});
  const [refusal, setRefusal] = useState("");
  const asked = useRef(0);
  useEffect(() => {
    const n = ++asked.current;
    const t = setTimeout(() => {
      api("POST", "/api/caps/check", { form: v })
        .then((r: Json) => {
          if (n === asked.current) setErrors(r.errors || {});
        })
        .catch(() => {});
    }, 300);
    return () => clearTimeout(t);
  }, [v]);
  return (
    <FormCard
      icon="terminal"
      title={adding ? `Add a capability on ${d.node.name}` : `Change ${v.name}`}
      sub="A fixed command that runs as nerve-run, in the folders."
      save={adding ? "Add" : "Save"}
      onCancel={cancel}
      refusal={refusal ? <Banner tone="danger">The machine refused: {refusal}</Banner> : null}
      onSave={async () => {
        setRefusal("");
        try {
          await api("POST", "/api/caps/save", { id: d.node.id, form: v, adding });
        } catch (e) {
          if (e instanceof ApiError && !e.auth) {
            if (e.body.errors) setErrors(e.body.errors as CapErrors);
            else setRefusal(e.message);
            return;
          }
          throw e;
        }
        toast(adding ? `Added ${v.name}.` : `Saved ${v.name}.`);
        done(v.name);
      }}
    >
      <CapFields
        v={v}
        set={setV}
        errors={errors}
        adding={adding}
        effectHint="It counts as execute whatever it says, except sense and actuate, which only the machine's owner turns on."
      />
    </FormCard>
  );
}

function CapsOf({ node }: { node: Node }) {
  const caps = usePoll(() => api<Caps>("GET", `/api/caps?id=${encodeURIComponent(node.id)}`), [node.id], 0);
  const [sel, setSel] = useState<string | null>(null);
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState<{ adding: boolean; v: CapFormValue } | null>(null);
  const d = caps.data;
  if (!d) {
    return caps.error ? <Banner tone="danger">The machine's capabilities did not load: {caps.error.message}</Banner> : <Loading />;
  }
  const a = d.added;
  const entries = (a && a.entries) || [];
  const canAdd = d.settings_write && d.online && a && !a.error && !a.refused;
  const pick = (x: string) => {
    setSel(x);
    setForm(null);
    setOpen(true);
  };
  const unit = d.units.find((u) => `u:${u.name}` === sel);
  const added = entries.find((e) => `a:${e.name}` === sel);
  const left = d.broken.find((b) => `l:${b.name}` === sel);
  let detail;
  if (form) {
    detail = (
      <CapForm
        key={form.adding ? "new" : form.v.name}
        d={d}
        start={form.v}
        adding={form.adding}
        cancel={() => setForm(null)}
        done={async (name) => {
          setForm(null);
          await caps.reload();
          setSel(`a:${name}`);
        }}
      />
    );
  } else if (added) {
    detail = (
      <Detail
        compact
        title={added.name}
        mono
        pills={
          <>
            <Pill tone={effectTone(added.effect)}>{added.effect}</Pill>
            <span className="faint">this center</span>
            {added.left_out ? <Pill tone="danger">left out</Pill> : null}
            {idle(d, added) ? <Pill tone="warn">not offered</Pill> : null}
          </>
        }
        actions={
          d.settings_write ? (
            <>
              <Btn icon="edit" onClick={() => setForm({ adding: false, v: { ...added.form } })}>
                Edit
              </Btn>
              <RemoveAsk
                question={`Remove ${added.name}? The agent is no longer offered it on this machine.`}
                onConfirm={async () => {
                  await api("POST", "/api/caps/remove", { id: d.node.id, name: added.name });
                  toast(`Removed ${added.name}.`);
                  setSel(null);
                  await caps.reload();
                }}
              />
            </>
          ) : null
        }
      >
        {added.summary ? <p className="lead">{added.summary}</p> : null}
        <DSec>
          <code className="code mono">{added.form.command}</code>
          {added.effect === "sense" || added.effect === "actuate" ? null : <span className="faint">Counted as execute.</span>}
          {added.left_out ? <p className="meta">Left out: {added.left_out}</p> : null}
          <NotOffered d={d} e={added} />
        </DSec>
      </Detail>
    );
  } else if (left) {
    detail = (
      <Detail compact title={left.name} mono pills={<Pill tone="danger">left out</Pill>}>
        <p className="lead">{left.reason}</p>
      </Detail>
    );
  } else {
    const u = unit || d.units[0];
    detail = u ? (
      <Detail
        compact
        title={u.name}
        mono
        pills={
          <>
            <Pill tone={effectTone(u.effect)}>{u.effect}</Pill>
            {u.kind !== "action" ? <Pill>{u.kind}</Pill> : null}
            {u.off ? <Pill tone="danger">off</Pill> : null}
            <span className="faint">{u.source}</span>
          </>
        }
      >
        {u.summary ? <p className="lead">{u.summary}</p> : null}
        <p className="faint">
          Offered on {d.node.name}
          {d.online ? "" : ": what it offered when it was last linked"}.
        </p>
      </Detail>
    ) : (
      <Detail compact title="Nothing offered">
        <p className="lead">This machine offers no capability to the agent now.</p>
      </Detail>
    );
  }
  const current = form ? (form.adding ? "new" : `a:${form.v.name}`) : sel ?? (d.units[0] ? `u:${d.units[0].name}` : null);
  return (
    <>
      <div className="banners">
        {!d.online ? <Banner tone="warn">This machine is offline: the list is what it offered when it was last linked.</Banner> : null}
        {!d.settings_write ? (
          <Banner tone="accent" icon="info">
            Read only: this machine has not let this center change its settings.
            <More summary="How">
              <p className="meta">
                {d.node && d.node.platform === "windows"
                  ? "Its owner lets it in the Nerve app on that machine: Centers, Settings grant."
                  : "Its owner lets it with nerve-node center settings on, on that machine."}
              </p>
            </More>
          </Banner>
        ) : null}
        {a && a.error ? <Banner tone="danger">The machine did not say: {a.error}</Banner> : null}
        {a && a.refused ? <Banner tone="warn">This machine takes no capability from a center: {a.refused}.</Banner> : null}
      </div>
      <Split
        open={open}
        onBack={() => setOpen(false)}
        list={
          <ListCard>
            <LGroup title="Offered" count={d.units.length} />
            {d.units.length ? null : <p className="lnote">This machine offers no capability to the agent now.</p>}
            {d.units.map((u) => (
              <LRow key={u.name} current={current === `u:${u.name}`} onPick={() => pick(`u:${u.name}`)}>
                <span className="mono cut grow">{u.name}</span>
                {u.off ? <Pill tone="danger">off</Pill> : null}
                <Pill tone={effectTone(u.effect)}>{u.effect}</Pill>
              </LRow>
            ))}
            {d.settings_write ? (
              <>
                <LGroup title="Added by this center" count={entries.length} />
                {!d.online || !a ? <p className="lnote">The machine is offline; its capabilities can be changed when it is back.</p> : null}
                {entries.map((e) => (
                  <LRow key={e.name} current={current === `a:${e.name}`} onPick={() => pick(`a:${e.name}`)}>
                    <span className="mono cut grow">{e.name}</span>
                    {e.left_out ? <Pill tone="danger">left out</Pill> : idle(d, e) ? <Pill tone="warn">not offered</Pill> : null}
                    <Pill tone={effectTone(e.effect)}>{e.effect}</Pill>
                  </LRow>
                ))}
                {canAdd ? (
                  <AddRow
                    label="Add a capability…"
                    current={current === "new"}
                    onPick={() => {
                      setForm({ adding: true, v: blankCapForm() });
                      setOpen(true);
                    }}
                  />
                ) : null}
              </>
            ) : null}
            {d.broken.length ? (
              <>
                <LGroup title="Left out" count={d.broken.length} />
                {d.broken.map((b) => (
                  <LRow key={b.name} current={current === `l:${b.name}`} onPick={() => pick(`l:${b.name}`)}>
                    <span className="mono cut grow">{b.name}</span>
                    <Pill tone="danger">left out</Pill>
                  </LRow>
                ))}
              </>
            ) : null}
          </ListCard>
        }
        detail={detail}
      />
    </>
  );
}

export function CapsPage() {
  const { ov, overview } = useCenter();
  const [id, setId] = useState<string | null>(null);
  // Each machine is asked once, and again on Refresh: its answer comes from
  // the machine itself.
  const [asked, setAsked] = useState(0);
  const nodes = ov.nodes;
  const node = nodes.find((n) => n.id === id) || nodes[0];
  return (
    <>
      <PageHead icon="plug" title="Capabilities" sub="What each machine offers the agent, and what this center added there.">
        <Btn
          kind="ghost"
          size=""
          icon="refresh"
          act={async () => {
            await overview.reload();
            setAsked((n) => n + 1);
          }}
        >
          Refresh
        </Btn>
      </PageHead>
      {!node ? (
        <div className="card">
          <Empty icon="server">No machines yet.</Empty>
        </div>
      ) : (
        <>
          <div className="ctabs">
            <span className="faint">Machine</span>
            {nodes.length <= 5 ? (
              <Seg label="Machine" value={node.id} onChange={(v) => setId(v)} options={nodes.map((n) => ({ value: n.id, label: n.name }))} />
            ) : (
              <Picker label="Machine" hideLabel items={nodes.map((n) => ({ value: n.id, text: n.name }))} value={node.id} onPick={setId} search="Search machines" none="No machine matches." />
            )}
          </div>
          <CapsOf key={`${node.id}:${asked}`} node={node} />
        </>
      )}
    </>
  );
}
