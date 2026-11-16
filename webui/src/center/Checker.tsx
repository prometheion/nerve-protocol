// The Action checker (issue #17): its three switches above, then one group
// at a time, chosen by the switch above the list: the blocklist, the rules
// that skip the model, the decision model, and each machine's own settings.
// A rule is added in the details pane. A save posts the whole settings with
// the version they were read at; until it has settled, every control of the
// page is off (one save at a time), and the page then shows what the center
// kept, so a refused change leaves nothing behind.
import { useEffect, useRef, useState, type ReactNode } from "react";
import { api } from "../api";
import { gb } from "../format";
import {
  AddRow,
  Banner,
  Btn,
  DSec,
  Detail,
  Empty,
  Field,
  FormCard,
  Icon,
  LRow,
  ListCard,
  Loading,
  More,
  PageHead,
  Picker,
  Pill,
  RemoveAsk,
  SecretInput,
  Seg,
  Split,
  Switch,
  TextArea,
  TextInput,
  ask,
  failed,
  toast,
} from "../ui";
import { useCenter } from "./App";
import type { Json } from "./types";

type View = "block" | "skip" | "model" | "mach";
type Focus = { view: View; id: string };

// What another page asks this one to show when it opens (the Audit page's
// link to a blocklist entry of a machine).
let pending: Focus | null = null;
export function focusChecker(f: Focus) {
  pending = f;
}

/** The longest owner's note on a machine, in UTF-8 bytes, as the center
 * takes it (checker::config::NOTE_MAX). */
export const NOTE_MAX = 400;
export const noteBytes = (s: string) => new TextEncoder().encode(s.trim()).length;

const SCOPES = [
  { value: "effects", text: "Execute, write and actuate calls (the default)" },
  { value: "with-reads", text: "Those and reads too" },
  { value: "tainted-only", text: "Only calls of a tainted session" },
];
const SOURCES = [
  { value: "local", text: "A llama-server the center runs" },
  { value: "endpoint", text: "A System One endpoint" },
];
const INSTALLING = ["downloading", "unpacking", "verifying"];

type Block = { id?: string; rule: string; on: boolean; builtin: boolean; note: string; node_id: string | null; off_for?: string[] };
type Allow = { rule: string; node_id: string | null };
type Cfg = Json;
type State = { cfg: Cfg; meta: Json };

const blockKey = (e: Block) => (e.id ? `id=${e.id}` : `${e.rule}|${e.node_id || ""}|${e.note || ""}`);
const allowKey = (a: Allow) => `${a.rule}|${a.node_id || ""}`;

/** Under a rule field: the arguments the action typed so far takes, which a
 * rule may pin after its colon, from what the machines publish. */
function fieldsHint(meta: Json, rule: string): string {
  const scope = rule.trim().split(":")[0];
  const fields: string[] | undefined = (meta.fields || {})[scope];
  return fields && fields.length ? `${scope} takes ${fields.join(", ")}. Pin them after a colon, joined by commas: ${scope}:${fields[0].split(" ")[0]}=…` : "";
}

const MORE_BLOCK =
  "Exact commands or wildcards in the machine's own rule syntax (exec.run:…, fs.write:…); a re: regex form where a glob is not enough. An fs.read: or fs.write: path also holds the paths any other capability reads or writes. Any other action is named whole (lamp.set, or lamp for all its actions), or with conditions on its arguments (lamp.set:room=office,brightness>50); a call that gives such an argument another type, or leaves it out, is refused too. The blocklist wins over the skip rules and the model. An entry for every machine can be switched off for single machines under Per machine.";
const MORE_SKIP =
  "A command rule covers a line only when every command in it meets the rule, with no flag or operand the rule does not name (but after a bare *), no wrapper with words of its own (env A=B, sudo -u), and nothing run inside another command ($( ), sh -c, env -S); a re: rule covers a line of one command; exec.run:exact:… covers one line exactly. It does not allow a call: the machine's own rules still decide.";

export function CheckerPage() {
  const { ov } = useCenter();
  const [st, setSt] = useState<State | null>(null);
  const [saving, setSaving] = useState(false);
  const start = useRef(pending);
  const [view, setView] = useState<View>(start.current?.view || "block");
  const [sel, setSel] = useState<string | null>(start.current?.id || null);
  const [open, setOpen] = useState(!!start.current);
  const load = async () => {
    const r = await api("GET", "/api/checker");
    const cfg = r.config;
    cfg.nodes = cfg.nodes || {};
    setSt({ cfg, meta: r });
  };
  useEffect(() => {
    pending = null;
    load().catch(failed);
  }, []);
  // The local model's install and state move along on their own: the page
  // asks for them every two seconds, and reads the whole settings again when
  // an install finished or a removal ended (they change the model's settings).
  useEffect(() => {
    const t = setInterval(async () => {
      if (document.hidden) return;
      try {
        const r = await api("GET", "/api/checker");
        setSt((cur) => {
          if (!cur) return cur;
          const was = cur.meta;
          const changed =
            was.installed !== r.installed || (was.install && was.install.phase) !== (r.install && r.install.phase) || JSON.stringify(was.installed_models) !== JSON.stringify(r.installed_models);
          if (changed) {
            const cfg = r.config;
            cfg.nodes = cfg.nodes || {};
            return { cfg, meta: r };
          }
          return { cfg: cur.cfg, meta: r };
        });
      } catch {
        /* the overview's poll says when the center cannot be reached */
      }
    }, 2000);
    return () => clearInterval(t);
  }, []);
  if (!st) {
    return (
      <>
        <PageHead icon="octagon" title="Action checker" />
        <Loading />
      </>
    );
  }
  const { cfg, meta } = st;
  /** Saves `change` applied to a copy of the settings shown, then shows what
   * the center kept: also when it refused, so nothing refused stays. */
  const save = async (change: (c: Cfg) => void) => {
    const next = structuredClone(cfg);
    change(next);
    setSaving(true);
    try {
      await api("POST", "/api/checker", { config: next });
    } catch (e) {
      await load().catch(() => {});
      throw e;
    } finally {
      setSaving(false);
    }
    await load();
  };
  const names = Object.fromEntries(ov.nodes.map((n) => [n.id, n.name]));
  const machineName = (id: string) => names[id] || id;
  const machines = checkerMachines(cfg, ov.nodes);
  const pick = (id: string) => {
    setSel(id);
    setOpen(true);
  };
  const choose = (v: View) => {
    setView(v);
    setSel(null);
  };
  const blocks: Block[] = cfg.blocklist;
  const allows: Allow[] = cfg.allow_rules;
  const ctx: Ctx = { cfg, meta, save, machineName, nodes: ov.nodes, pick, load };
  let list: ReactNode;
  let detail: ReactNode;
  if (view === "block") {
    const e = blocks.find((x) => `b:${blockKey(x)}` === sel) || (sel === "new-block" ? null : blocks[0]);
    list = (
      <>
        {blocks.map((x) => (
          <LRow key={blockKey(x)} current={e === x} onPick={() => pick(`b:${blockKey(x)}`)}>
            <span className={x.on ? "tone-danger" : "faint"}>
              <Icon name="ban" />
            </span>
            <span className={"mono cut grow " + (x.on ? "" : "faint")}>{x.rule}</span>
            <span className="side-text">{!x.on ? "off" : x.node_id ? machineName(x.node_id) : (x.off_for || []).length ? `off for ${x.off_for!.length}` : ""}</span>
          </LRow>
        ))}
        {blocks.length ? null : <p className="lnote top">The blocklist is empty.</p>}
        <AddRow label="Add a rule…" current={sel === "new-block"} onPick={() => pick("new-block")} />
      </>
    );
    detail = sel === "new-block" ? <RuleForm block ctx={ctx} done={(k) => setSel(k)} cancel={() => setSel(null)} /> : e ? <BlockDetail key={blockKey(e)} e={e} ctx={ctx} /> : null;
  } else if (view === "skip") {
    const a = allows.find((x) => `k:${allowKey(x)}` === sel) || (sel === "new-skip" ? null : allows[0]);
    list = (
      <>
        {allows.map((x) => (
          <LRow key={allowKey(x)} current={a === x} onPick={() => pick(`k:${allowKey(x)}`)}>
            <span className="tone-ok">
              <Icon name="check" />
            </span>
            <span className="mono cut grow">{x.rule}</span>
            <span className="side-text">{x.node_id ? machineName(x.node_id) : ""}</span>
          </LRow>
        ))}
        {allows.length ? null : <p className="lnote top">No call skips the model.</p>}
        <AddRow label="Add a rule…" current={sel === "new-skip"} onPick={() => pick("new-skip")} />
      </>
    );
    detail = sel === "new-skip" ? <RuleForm ctx={ctx} done={(k) => setSel(k)} cancel={() => setSel(null)} /> : a ? <SkipDetail key={allowKey(a)} a={a} ctx={ctx} /> : null;
  } else if (view === "model") {
    const ready = meta.local && meta.local.phase === "ready";
    list = (
      <LRow current onPick={() => pick("model")}>
        <Icon name="cpu" />
        <span className="grow">Decision model</span>
        <span className="side-text">{!cfg.model_on ? "off" : cfg.model.source === "endpoint" ? "endpoint" : ready ? "ready" : meta.installed ? "not running" : "not installed"}</span>
      </LRow>
    );
    detail = <ModelDetail key={cfg.version} ctx={ctx} />;
  } else {
    const m = machines.find((x) => `m:${x.id}` === sel) || machines[0];
    list = machines.length ? (
      machines.map((x) => {
        const own = cfg.nodes[x.id] || {};
        const said = [own.blocklist && own.blocklist !== "inherit" ? `blocklist ${own.blocklist}` : "", own.model && own.model !== "inherit" ? `model ${own.model}` : "", x.paired ? "" : "not paired"].filter(Boolean).join(", ");
        return (
          <LRow key={x.id} current={m === x} onPick={() => pick(`m:${x.id}`)}>
            <Icon name="server" />
            <span className="grow cut">{x.name}</span>
            <span className="side-text">{said}</span>
          </LRow>
        );
      })
    ) : (
      <Empty icon="server">No machine is paired.</Empty>
    );
    detail = m ? <MachineDetail key={m.id} m={m} ctx={ctx} /> : null;
  }
  return (
    <>
      <PageHead icon="octagon" title="Action checker" sub="Checks each call before a machine gets it; it can only refuse.">
        {view === "block" ? (
          <Btn
            kind="ghost"
            size=""
            icon="refresh"
            disabled={saving}
            act={async () => {
              const yes = await ask({
                title: "Reset the blocklist?",
                message: "Replace the blocklist with the defaults? Your own entries and what you switched off, also for single machines, are lost.",
                confirm: "Reset",
                danger: true,
              });
              if (yes) await save((c) => (c.blocklist = meta.default_blocklist.map((e: Block) => ({ ...e }))));
            }}
          >
            Reset to defaults
          </Btn>
        ) : null}
        <Btn kind="ghost" size="" icon="refresh" act={load}>
          Refresh
        </Btn>
      </PageHead>
      <fieldset className="plain" disabled={saving} aria-busy={saving || undefined}>
        <div className="card strip">
          <Switch checked={!!cfg.blocklist_on} onChange={(v) => save((c) => (c.blocklist_on = v))}>
            Blocklist
          </Switch>
          <Switch
            checked={!!cfg.model_on}
            onChange={async (v) => {
              if (v && !(await modelOnAsks(ctx))) return;
              await save((c) => (c.model_on = v));
            }}
          >
            Decision model
          </Switch>
          <Switch checked={!!cfg.taint_on} onChange={(v) => save((c) => (c.taint_on = v))}>
            Taint marking
          </Switch>
          <span className="meta note">It can only refuse. A change counts from the next call.</span>
        </div>
        <CheckerBanners cfg={cfg} meta={meta} />
        <Split
          variant="wide"
          open={open}
          onBack={() => setOpen(false)}
          list={
            <ListCard>
              <div className="lseg">
                <Seg
                  label="Group"
                  full
                  value={view}
                  onChange={choose}
                  options={[
                    { value: "block", label: "Blocklist", count: blocks.length },
                    { value: "skip", label: "Skip the model", count: allows.length },
                    { value: "model", label: "Decision model" },
                    { value: "mach", label: "Per machine", count: machines.length },
                  ]}
                />
              </div>
              {list}
            </ListCard>
          }
          detail={detail}
        />
      </fieldset>
    </>
  );
}

type Ctx = {
  cfg: Cfg;
  meta: Json;
  save: (change: (c: Cfg) => void) => Promise<void>;
  machineName: (id: string) => string;
  nodes: { id: string; name: string }[];
  pick: (id: string) => void;
  load: () => Promise<void>;
};

function CheckerBanners({ cfg, meta }: { cfg: Cfg; meta: Json }) {
  const stale = Object.entries(meta.stale || {});
  return (
    <div className="banners">
      {/* On but not running: every checked call is refused (fail closed), or
          with fail closed off goes to the machine unjudged. */}
      {meta.model_wanted && !(meta.local && meta.local.phase === "ready") && cfg.model.source === "local" ? (
        cfg.model.fail_closed ? (
          <Banner tone="danger">The decision model is on but does not run: every call it checks is refused. The Log page says why.</Banner>
        ) : (
          <Banner tone="danger">The decision model is on but does not run, and fail closed is off: its calls pass unjudged.</Banner>
        )
      ) : null}
      {meta.rejected && meta.rejected.length ? <Banner tone="warn">Some rules do not parse and were left out: {meta.rejected.join("; ")}</Banner> : null}
      {meta.unpublished && meta.unpublished.length ? (
        <Banner tone="warn">Some rules name a capability no machine offers, so they match no call now (a typo, or a capability that is gone): {meta.unpublished.join("; ")}</Banner>
      ) : null}
      {/* Rules whose conditions no longer fit the arguments their action
          takes: they fail closed until the owner changes them. */}
      {stale.length ? (
        <Banner tone="warn">
          Some rules no longer fit their action. Change or remove them: {stale.map(([r, why]) => `${r} (${why})`).join("; ")}
          <More summary="Why">
            <p className="meta">
              An argument is gone or of another type, or a value is no longer taken: on the blocklist such a rule may refuse calls it was not meant for, as a skip rule it may not cover the calls it was meant for.
            </p>
          </More>
        </Banner>
      ) : null}
    </div>
  );
}

/** Turning the model on with no local model installed: it would refuse
 * every checked call, so the owner is asked to install it first. True to go
 * on with the switch. */
async function modelOnAsks(ctx: Ctx): Promise<boolean> {
  const { meta, cfg } = ctx;
  if (cfg.model.source !== "local" || meta.installed || !meta.platform_supported) return true;
  const pin = meta.models[0];
  const what = cfg.model.fail_closed ? "every checked call is refused" : "every checked call passes unjudged (fail closed is off)";
  const yes = await ask({ title: "No model is installed", message: `With the model on and none installed, ${what}. Install ${pin.name} (${gb(pin.bytes)}) on the CPU now?`, confirm: "Install and turn on" });
  if (!yes) return false;
  await api("POST", "/api/checker/install", { gpu: false, model: pin.id });
  return true;
}

function Where({ ctx, node }: { ctx: Ctx; node: string | null }) {
  return <span>{node ? `Only ${ctx.machineName(node)}` : "Every machine"}</span>;
}

function BlockDetail({ e, ctx }: { e: Block; ctx: Ctx }) {
  const k = blockKey(e);
  const same = (b: Block) => blockKey(b) === k;
  const off = e.off_for || [];
  return (
    <Detail
      icon="ban"
      title="Blocklist rule"
      pills={e.builtin ? <Pill>default</Pill> : null}
      actions={
        <RemoveAsk
          size=""
          question="Remove this rule?"
          onConfirm={() => ctx.save((c) => (c.blocklist = c.blocklist.filter((b: Block) => !same(b))))}
        />
      }
    >
      <p className="lead mono wrap">{e.rule}</p>
      {e.note ? <p className="meta">{e.note}</p> : null}
      <DSec>
        <div className="kv">
          <span className="k">On</span>
          <span>{e.on ? "Refuses the calls it names." : "Off: it refuses nothing."}</span>
          <Switch label="On" checked={e.on} onChange={(v) => ctx.save((c) => (c.blocklist.find(same).on = v))} />
          <span className="k">Where</span>
          <Where ctx={ctx} node={e.node_id} />
          <span />
          {off.length ? (
            <>
              <span className="k">Switched off for</span>
              <span>{off.map(ctx.machineName).join(", ")}</span>
              <span />
            </>
          ) : null}
        </div>
      </DSec>
      <DSec>
        <More summary="What a rule can name">
          <p className="meta">{MORE_BLOCK}</p>
        </More>
        <p className="meta">It catches names, not shell variables, aliases, a script written then run, or base64.</p>
        <More summary="Why">
          <p className="meta">The matcher reads the call as written. The decision model and the machine's policy are the next lines of defence.</p>
        </More>
      </DSec>
    </Detail>
  );
}

function SkipDetail({ a, ctx }: { a: Allow; ctx: Ctx }) {
  return (
    <Detail
      icon="check"
      title="Skips the model"
      actions={
        <RemoveAsk
          size=""
          question="Remove this rule?"
          onConfirm={() => ctx.save((c) => (c.allow_rules = c.allow_rules.filter((x: Allow) => allowKey(x) !== allowKey(a))))}
        />
      }
    >
      <p className="lead mono wrap">{a.rule}</p>
      <DSec>
        <div className="kv">
          <span className="k">Where</span>
          <Where ctx={ctx} node={a.node_id} />
          <span />
        </div>
      </DSec>
      <DSec>
        <p className="meta">A matching call skips the decision model, never the blocklist.</p>
        <More summary="What a skip rule covers">
          <p className="meta">{MORE_SKIP}</p>
        </More>
      </DSec>
    </Detail>
  );
}

/** A new rule of the blocklist (`block`) or one that skips the model, in
 * the details pane: the rule, for the blocklist what it guards against,
 * and where it counts. */
function RuleForm({ block, ctx, done, cancel }: { block?: boolean; ctx: Ctx; done: (key: string) => void; cancel: () => void }) {
  const [rule, setRule] = useState("");
  const [note, setNote] = useState("");
  const [where, setWhere] = useState<"all" | "one">("all");
  const [node, setNode] = useState<string>(ctx.nodes[0]?.id || "");
  const nodeId = where === "one" && node ? node : null;
  return (
    <FormCard
      icon={block ? "ban" : "check"}
      title={block ? "Add a blocklist rule" : "Add a rule that skips the model"}
      sub={block ? "The checker refuses the calls it names." : "Calls it covers go on without the model; the machine's rules still decide."}
      save="Add"
      onCancel={cancel}
      onSave={async () => {
        const r = rule.trim();
        if (!r) {
          toast("Enter a rule.", "error");
          return;
        }
        if (block) {
          const e: Block = { rule: r, on: true, builtin: false, note: note.trim(), node_id: nodeId };
          await ctx.save((c) => c.blocklist.push(e));
          done(`b:${blockKey(e)}`);
        } else {
          const a: Allow = { rule: r, node_id: nodeId };
          await ctx.save((c) => c.allow_rules.push(a));
          done(`k:${allowKey(a)}`);
        }
      }}
    >
      <Field label="Rule" hint={fieldsHint(ctx.meta, rule) || "capability.action:target; * stands for any text."}>
        <TextInput value={rule} onChange={setRule} mono placeholder={block ? "exec.run:rm -rf /*  or  fs.write:/etc/sudoers" : "exec.run:docker exec *"} aria-label={block ? "New blocklist rule" : "New rule that skips the model"} />
      </Field>
      {block ? (
        <Field label="What it guards against (optional)">
          <TextInput value={note} onChange={setNote} />
        </Field>
      ) : null}
      <div className="field">
        <span className="label">Where it counts</span>
        <Seg
          label="Where it counts"
          value={where}
          onChange={setWhere}
          options={[
            { value: "all", label: "All machines" },
            { value: "one", label: "One machine", disabled: !ctx.nodes.length },
          ]}
        />
      </div>
      {where === "one" ? <Picker label="Machine" items={ctx.nodes.map((n) => ({ value: n.id, text: n.name }))} value={node} onPick={setNode} search="Search machines" none="No machine matches." /> : null}
      {block ? (
        <More summary="What a rule can name">
          <p className="meta">{MORE_BLOCK}</p>
        </More>
      ) : (
        <More summary="What a skip rule covers">
          <p className="meta">{MORE_SKIP}</p>
        </More>
      )}
    </FormCard>
  );
}

// ---- Per machine: the switches, entries, exceptions and allow rules of
// one machine (owner's decision of 2026-10-18) ----

type Machine = { id: string; name: string; paired: boolean };

/** The paired machines, and any machine the settings still name although it
 * is no longer paired, so its settings can be forgotten. */
export function checkerMachines(cfg: Cfg, nodes: { id: string; name: string }[]): Machine[] {
  const named = new Set<string>(Object.keys(cfg.nodes || {}));
  for (const e of cfg.blocklist as Block[]) {
    if (e.node_id) named.add(e.node_id);
    for (const id of e.off_for || []) named.add(id);
  }
  for (const a of cfg.allow_rules as Allow[]) if (a.node_id) named.add(a.node_id);
  const gone = [...named].filter((id) => !nodes.some((n) => n.id === id));
  return [...nodes.map((n) => ({ id: n.id, name: n.name, paired: true })), ...gone.map((id) => ({ id, name: id, paired: false }))];
}

function MachineDetail({ m, ctx }: { m: Machine; ctx: Ctx }) {
  const { cfg } = ctx;
  const own = cfg.nodes[m.id] || { blocklist: "inherit", model: "inherit" };
  const blocks: Block[] = cfg.blocklist;
  const entries = blocks.filter((e) => e.node_id === m.id);
  const offs = blocks.filter((e) => !e.node_id && (e.off_for || []).includes(m.id));
  const others = blocks.filter((e) => !e.node_id && !(e.off_for || []).includes(m.id));
  const allows = (cfg.allow_rules as Allow[]).filter((a) => a.node_id === m.id);
  const [note, setNote] = useState<string>(own.note || "");
  const [rule, setRule] = useState("");
  const n = noteBytes(note);
  const setOwn = (part: string, v: string) => ctx.save((c) => (c.nodes[m.id] = { ...(c.nodes[m.id] || { blocklist: "inherit", model: "inherit" }), [part]: v }));
  const part = (key: "blocklist" | "model", label: string, centerOn: boolean) => (
    <div className="field">
      <span className="label">{label}</span>
      <Seg
        label={label}
        value={own[key] || "inherit"}
        onChange={(v) => setOwn(key, v)}
        options={[
          { value: "inherit", label: `As the center (${centerOn ? "on" : "off"})` },
          { value: "on", label: "On" },
          { value: "off", label: "Off" },
        ]}
      />
    </div>
  );
  return (
    <Detail
      icon="server"
      title={m.name}
      pills={m.paired ? null : <Pill tone="danger">not paired</Pill>}
      actions={
        m.paired ? null : (
          <RemoveAsk
            size=""
            label="Forget its settings"
            question={`Forget what the checker holds for ${m.name}?`}
            onConfirm={() =>
              ctx.save((c) => {
                // A machine no longer paired: drop everything the settings
                // hold for it.
                delete c.nodes[m.id];
                c.blocklist = c.blocklist.filter((e: Block) => e.node_id !== m.id).map((e: Block) => ({ ...e, off_for: (e.off_for || []).filter((id) => id !== m.id) }));
                c.allow_rules = c.allow_rules.filter((a: Allow) => a.node_id !== m.id);
              })
            }
          />
        )
      }
    >
      <p className="lead">Each machine follows the center's switches unless you change them here.</p>
      <DSec>
        <div className="form-row">
          {part("blocklist", "Blocklist", !!cfg.blocklist_on)}
          {part("model", "Decision model", !!cfg.model_on)}
        </div>
        <p className="meta">The model on here uses the center's one model and its settings. Taint is for every machine.</p>
        <More>
          <p className="meta">
            A machine can have block entries of its own, and switch single entries for every machine off for itself. A block anywhere wins: the center's blocklist, this machine's entries, or the machine's own deny list; a skip rule only skips the model.
          </p>
        </More>
      </DSec>
      <DSec title="Your note on this machine">
        <p className="meta">A few words for the agent about this machine (one line, 400 bytes).</p>
        <More>
          <p className="meta">Such as what the machine is for. list() shows them to every harness of this center as your words, next to the machine.</p>
        </More>
        {/* The center counts the note in UTF-8 bytes, and `maxlength` counts
            characters: an umlaut or a dash takes more than one byte, so the
            field counts bytes itself and keeps a note that is too long
            rather than sending it. */}
        <Field label="Note" hint={n > NOTE_MAX ? `${n - NOTE_MAX} bytes too long` : `${NOTE_MAX - n} bytes left`}>
          <TextInput value={note} onChange={setNote} maxLength={NOTE_MAX} placeholder="test VM; its databases hold throwaway data" aria-label={`Note on ${m.name}`} />
        </Field>
        <div className="acts-row">
          <Btn
            kind="primary"
            act={async () => {
              if (n > NOTE_MAX) {
                toast(`The note is ${n} bytes long; at most ${NOTE_MAX} fit.`, "error");
                return;
              }
              await ctx.save((c) => (c.nodes[m.id] = { ...(c.nodes[m.id] || { blocklist: "inherit", model: "inherit" }), note: note.trim() }));
            }}
          >
            Save note
          </Btn>
        </div>
      </DSec>
      <DSec title="Block entries for this machine only">
        {entries.length ? (
          <div className="card rows clip">
            {entries.map((e) => (
              <div key={blockKey(e)} className="r">
                <Switch label={`${e.rule} on`} checked={e.on} onChange={(v) => ctx.save((c) => (c.blocklist.find((b: Block) => blockKey(b) === blockKey(e)).on = v))} />
                <code className="mono grow wrap">{e.rule}</code>
                <RemoveAsk bare question="Remove?" onConfirm={() => ctx.save((c) => (c.blocklist = c.blocklist.filter((b: Block) => blockKey(b) !== blockKey(e))))} />
              </div>
            ))}
          </div>
        ) : (
          <p className="meta">None.</p>
        )}
        <Field label="Add a rule for this machine" hint={fieldsHint(ctx.meta, rule)}>
          <TextInput value={rule} onChange={setRule} mono placeholder="exec.run:terraform destroy*" aria-label={`New blocklist rule for ${m.name}`} />
        </Field>
        <div className="acts-row">
          <Btn
            kind="primary"
            icon="plus"
            act={async () => {
              const r = rule.trim();
              if (!r) {
                toast("Enter a rule.", "error");
                return;
              }
              await ctx.save((c) => c.blocklist.push({ rule: r, on: true, builtin: false, note: "", node_id: m.id }));
              setRule("");
            }}
          >
            Add
          </Btn>
        </div>
      </DSec>
      <DSec title="Entries for every machine, switched off here">
        {offs.length ? (
          <div className="card rows clip">
            {offs.map((e) => (
              <div key={blockKey(e)} className="r">
                <div className="grow">
                  <code className="mono wrap">{e.rule}</code>
                  {e.note ? <div className="faint">{e.note}</div> : null}
                </div>
                <Btn
                  act={() =>
                    ctx.save((c) => {
                      const x = c.blocklist.find((b: Block) => blockKey(b) === blockKey(e));
                      x.off_for = (x.off_for || []).filter((id: string) => id !== m.id);
                    })
                  }
                >
                  Switch on again
                </Btn>
              </div>
            ))}
          </div>
        ) : (
          <p className="meta">None.</p>
        )}
        <Picker
          label="Switch off for this machine"
          items={[{ value: "", text: "Pick an entry for every machine" }, ...others.map((e) => ({ value: blockKey(e), text: e.note ? `${e.note}: ${e.rule}` : e.rule }))]}
          value=""
          search="Search entries"
          none="No entry matches."
          onPick={(v) => {
            if (!v) return;
            ctx
              .save((c) => {
                const x = c.blocklist.find((b: Block) => blockKey(b) === v);
                x.off_for = [...(x.off_for || []), m.id];
              })
              .catch(failed);
          }}
        />
      </DSec>
      <DSec title="Rules that skip the model for this machine only">
        {allows.length ? (
          <div className="card rows clip">
            {allows.map((a) => (
              <div key={allowKey(a)} className="r">
                <code className="mono grow wrap">{a.rule}</code>
                <RemoveAsk bare question="Remove?" onConfirm={() => ctx.save((c) => (c.allow_rules = c.allow_rules.filter((x: Allow) => allowKey(x) !== allowKey(a))))} />
              </div>
            ))}
          </div>
        ) : (
          <p className="meta">None. Add one under Skip the model.</p>
        )}
      </DSec>
    </Detail>
  );
}

// ---- The decision model ----

function ModelDetail({ ctx }: { ctx: Ctx }) {
  const { cfg, meta } = ctx;
  const m = cfg.model;
  const [f, setF] = useState({
    source: m.source as string,
    endpoint_url: m.endpoint_url as string,
    endpoint_model: m.endpoint_model as string,
    threshold: String(m.threshold),
    timeout_ms: String(m.timeout_ms),
    scope: m.scope as string,
    fail_closed: !!m.fail_closed,
    instructions: m.instructions as string,
    criteria_true: m.criteria_true as string,
    criteria_false: m.criteria_false as string,
  });
  const [token, setToken] = useState("");
  const put = (k: keyof typeof f) => (v: string | boolean) => setF({ ...f, [k]: v });
  const failSwitch = (
    <Switch checked={f.fail_closed} onChange={(v) => put("fail_closed")(v)}>
      {f.fail_closed ? "Fail closed: refuse a call when the model is unreachable (recommended). Off: allow and log it." : "Fail closed is off: a call the model cannot judge is allowed and logged. On refuses it (recommended)."}
    </Switch>
  );
  return (
    <Detail icon="cpu" title="Decision model">
      <p className="lead">
        {m.fail_closed ? "An optional model that refuses dangerous calls; it fails closed." : "An optional model that refuses dangerous calls; fail closed is off, so a call it cannot judge runs."}
      </p>
      <DSec>
        <Picker label="Source" items={SOURCES} value={f.source} onPick={put("source")} />
        {/* Off is the one setting that lets calls through unjudged, so it is
            not folded away while it is off. */}
        {m.fail_closed ? null : failSwitch}
        {f.source === "endpoint" ? (
          <>
            <div className="form-row">
              <Field label="Endpoint URL">
                <TextInput value={f.endpoint_url} onChange={put("endpoint_url")} mono placeholder="https://host:9931" />
              </Field>
              <Field label="Model name">
                <TextInput value={f.endpoint_model} onChange={put("endpoint_model")} mono placeholder="jev-latest (optional)" />
              </Field>
            </div>
            <div className="form-row">
              <Field label="Bearer token (kept secret, never shown back)">
                <SecretInput value={token} onChange={setToken} placeholder={meta.has_token ? "a token is set — type to replace" : "optional bearer token"} />
              </Field>
              {meta.has_token ? (
                <Btn
                  kind="ghost"
                  icon="trash"
                  act={async () => {
                    await api("POST", "/api/checker/token", { token: null });
                    await ctx.load();
                  }}
                >
                  Clear token
                </Btn>
              ) : null}
            </div>
          </>
        ) : (
          <LocalModel ctx={ctx} />
        )}
        <More summary="Advanced">
          <p className="meta">A System One model answers, in one pass, whether a call is dangerous; at or above the threshold the call is refused. An unreachable model refuses the call unless you switch fail closed off.</p>
          <div className="form-row">
            <Field label="Threshold (0 to 1)" className="narrow">
              <TextInput value={f.threshold} onChange={put("threshold")} type="number" min="0" max="1" step="0.01" className="num" />
            </Field>
            <Field label="Timeout (ms)" className="narrow">
              <TextInput value={f.timeout_ms} onChange={put("timeout_ms")} type="number" min="100" className="num" />
            </Field>
          </div>
          <Picker label="Which calls the model sees" items={SCOPES} value={f.scope} onPick={put("scope")} />
          {m.fail_closed ? failSwitch : null}
          <Field label="Question (the command text is never put here; it goes only in the state sent to the model)">
            <TextArea value={f.instructions} onChange={put("instructions")} rows={4} />
          </Field>
          <div className="form-row">
            <Field label="When true (dangerous)">
              <TextInput value={f.criteria_true} onChange={put("criteria_true")} />
            </Field>
            <Field label="When false (safe)">
              <TextInput value={f.criteria_false} onChange={put("criteria_false")} />
            </Field>
          </div>
        </More>
        <div className="ffoot">
          <Btn
            kind="ghost"
            icon="refresh"
            onClick={() => {
              setF({ ...f, instructions: "", criteria_true: "", criteria_false: "" });
              toast("Cleared; Save to store the defaults.");
            }}
          >
            Reset the question
          </Btn>
          <Btn
            kind="primary"
            size=""
            act={async () => {
              if (token) {
                await api("POST", "/api/checker/token", { token });
                setToken("");
              }
              await ctx.save((c) => {
                c.model = {
                  ...c.model,
                  source: f.source,
                  endpoint_url: f.endpoint_url.trim(),
                  endpoint_model: f.endpoint_model.trim(),
                  threshold: Number(f.threshold),
                  timeout_ms: Number(f.timeout_ms),
                  scope: f.scope,
                  fail_closed: f.fail_closed,
                  instructions: f.instructions,
                  criteria_true: f.criteria_true,
                  criteria_false: f.criteria_false,
                };
              });
              toast("Saved.");
            }}
          >
            Save
          </Btn>
        </div>
      </DSec>
    </Detail>
  );
}

function Bar({ p }: { p?: { done: number; total: number } }) {
  const pct = p && p.total ? Math.min(100, Math.round((100 * p.done) / p.total)) : 0;
  return (
    <div className="pbar">
      <progress max={100} value={pct} />
      <span>{pct}%</span>
    </div>
  );
}

/** The local model: a one-click install of llama.cpp and the chosen model
 * (d1-2B by default, or Kev-4B), then the running status. */
function LocalModel({ ctx }: { ctx: Ctx }) {
  const { meta, cfg } = ctx;
  const [chosen, setChosen] = useState<string>(cfg.model.local_model);
  const items = meta.models.map((m: Json, i: number) => ({ value: m.id, text: m.name + (i === 0 ? " (the default)" : "") }));
  const pin = meta.models.find((m: Json) => m.id === chosen) || meta.models[0];
  // One plain line per model, so the choice is informed: size, licence,
  // and the measured speed and quality.
  const line = (
    <p className="meta">
      {pin.name}: {gb(pin.bytes)}, licence {pin.licence}. {pin.summary}
    </p>
  );
  const head = (
    <>
      <p className="meta">The center downloads and runs llama.cpp and the model itself, in its own state folder.</p>
      <More>
        <p className="meta">Pick the model here; the device (CPU or GPU) is separate.</p>
      </More>
      <Picker label="Model" items={items} value={chosen} onPick={setChosen} search="Search models" none="No model matches." />
      {line}
    </>
  );
  if (!meta.platform_supported) {
    return (
      <>
        {head}
        <Banner tone="warn">This machine has no prebuilt local model for it. Use a System One endpoint instead (the other source above).</Banner>
      </>
    );
  }
  const inst = meta.install || { phase: "idle" };
  const installing = INSTALLING.includes(inst.phase);
  const install = (gpu: boolean) => async () => {
    await api("POST", "/api/checker/install", { gpu, model: pin.id });
    await ctx.load();
  };
  // Also offered while an install runs, so a slow download can be stopped
  // from the page: Remove ends the install first.
  const remove = (
    <RemoveAsk
      question={installing ? `Stop the install and delete the downloaded files${meta.installed ? ", also those of the model installed now" : ""}?` : "Delete the downloaded llama.cpp and model files? You can install them again later."}
      confirm="Remove"
      onConfirm={async () => {
        await api("POST", "/api/checker/remove");
        await ctx.load();
      }}
    />
  );
  if (installing) {
    const target = meta.models.find((m: Json) => m.id === inst.model_id) || pin;
    return (
      <>
        {head}
        <div className="card pad stack tight">
          <div className="row">
            <Icon name="download" />
            <b className="grow">Installing {target.name}</b>
            <Pill tone="warn">{inst.phase}</Pill>
          </div>
          <span className="meta">llama.cpp</span>
          <Bar p={inst.llama} />
          <span className="meta">model ({gb(target.bytes)})</span>
          <Bar p={inst.model} />
          {inst.message ? <p className="meta">{inst.message}</p> : null}
          {meta.local ? <p className="meta">The installed model keeps checking calls until the new files are in place; it is stopped only for the swap at the end.</p> : null}
          <div className="acts-row">{remove}</div>
        </div>
      </>
    );
  }
  const lastFailed = inst.phase === "failed" ? <Banner tone="danger">The last install failed: {inst.message || "unknown error"}</Banner> : null;
  if (meta.installed && pin.id === cfg.model.local_model) {
    const dev = cfg.model.local_gpu ? "GPU" : "CPU";
    const other = dev === "GPU" ? "CPU" : "GPU";
    return (
      <>
        {head}
        {lastFailed}
        <div className="acts-row">
          <span className="meta">Installed, running on the {dev}.</span>
          {meta.gpu_hint || dev === "GPU" ? (
            <Btn kind="ghost" act={install(other === "GPU")}>
              Switch to {other}
            </Btn>
          ) : null}
          {remove}
        </div>
        <LocalStatus s={meta.local} wanted={meta.model_wanted} />
      </>
    );
  }
  const current = meta.installed ? meta.models.find((m: Json) => m.id === cfg.model.local_model) : null;
  const verb = current ? "Switch" : "Install";
  return (
    <>
      {head}
      {lastFailed}
      {current ? (
        <p className="meta">
          Installed now: {current.name}. Switching downloads {pin.name} ({gb(pin.bytes)}) and removes it; the threshold and timeout become {pin.name.split(" (")[0]}'s defaults ({pin.threshold}, {pin.timeout_ms / 1000} s).
        </p>
      ) : null}
      <div className="acts-row">
        <Btn kind="primary" icon="download" act={install(false)}>
          {verb} on CPU
        </Btn>
        {meta.gpu_hint ? (
          <Btn kind="primary" icon="download" act={install(true)}>
            {verb} on GPU
          </Btn>
        ) : null}
        <span className="meta">{meta.gpu_hint ? "GPU uses the Vulkan build (NVIDIA, AMD or Intel)." : "No GPU detected; CPU only."}</span>
        {current ? remove : null}
      </div>
    </>
  );
}

/** `wanted` is the center's word on whether the model is on anywhere: by
 * the center's switch or for a single machine. */
function LocalStatus({ s, wanted }: { s: Json; wanted: boolean }) {
  if (!s) {
    return (
      <p className="meta">
        {wanted ? "The model is on but its server is not running. The Log page says why." : "The model is installed but not running. Turn the model on (the switch at the top, or for a machine under Per machine)."}
      </p>
    );
  }
  const tone = s.phase === "ready" ? "ok" : s.phase === "failed" ? "danger" : "warn";
  return (
    <div className="card pad stack tight">
      <div className="row">
        <i className={"dot " + (s.phase === "ready" ? "ok" : "")} />
        <b className="grow">Local model</b>
        <Pill tone={tone}>{s.phase}</Pill>
      </div>
      {s.url ? <p className="meta mono">{s.url}</p> : null}
      {s.message ? <p className="meta">{s.message}</p> : null}
      {s.output && s.output.length ? <pre className="code mono">{s.output.join("\n")}</pre> : null}
    </div>
  );
}

