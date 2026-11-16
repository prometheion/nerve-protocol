// Audit: every decision about a call, newest first, as a list; the details
// show the picked one and the rules it can become: allow or deny on the
// machine (with its settings grant), or a rule of the action checker that
// skips the model.
import { useEffect, useMemo, useState } from "react";
import { api } from "../api";
import { usePoll } from "../frame";
import { ago, when } from "../format";
import { Btn, CopyRow, DSec, Detail, Empty, Icon, LRow, ListCard, Loading, PageHead, Picker, Pill, Seg, Split, TextInput, toast, type Tone } from "../ui";
import { useCenter } from "./App";
import { focusChecker } from "./Checker";
import { isCut, isSudo, sudoRuleLine } from "./lines";
import type { Json, Node } from "./types";

export type Decision = {
  ts: number;
  node: string;
  node_id: string;
  cap: string;
  action: string;
  target?: string;
  decision: string;
  by?: string;
  code?: string;
  args?: Record<string, unknown>;
  checker?: { layer: string; detail: string; scope?: string };
};

const DECISIONS: Record<string, { icon: string; tone: Tone }> = {
  allowed: { icon: "ok", tone: "ok" },
  denied: { icon: "ban", tone: "danger" },
  forbidden: { icon: "lock", tone: "danger" },
  // A command the node killed for its memory limit, after it was allowed.
  killed: { icon: "ban", tone: "danger" },
};

/** The arguments of an entry's call that a rule may pin (`d.args`, kept by
 * the machine): the value of the one picked, as {field, value}. */
function Pins({ d, children }: { d: Decision; children: (pin: () => { field: string; value: unknown }) => React.ReactNode }) {
  const args = d.args && typeof d.args === "object" ? Object.entries(d.args) : [];
  const [chosen, setChosen] = useState("0");
  if (!args.length) return null;
  const text = ([k, v]: [string, unknown]) => `${k}=${typeof v === "string" ? v.replace(/\\/g, "\\\\").replace(/,/g, "\\,") : String(v)}`;
  const items = args.map((a, i) => ({ value: String(i), text: text(a) }));
  const pin = () => {
    const [field, value] = args[Number(chosen) || 0];
    return { field, value };
  };
  return (
    <div className="form-row">
      <Picker label="Pin one argument" items={items} value={chosen} onPick={(v) => setChosen(v)} search="Search arguments" none="No argument matches." />
      <div className="acts-row">{children(pin)}</div>
    </div>
  );
}

/** Where the owner of machine `n` puts a sudo command on this center's sudo
 * list: its commands run as root, so the machine takes that list from its
 * owner only (#197). The nerve-node command with Copy, or on Windows the
 * Nerve app's place. */
export function SudoListHint({ n, command }: { n?: Node; command: string }) {
  if (n && n.platform === "windows") {
    return <p className="meta">Only the machine's owner puts a command on the sudo list: in the Nerve app on that machine, Permissions, Sudo.</p>;
  }
  const line = sudoRuleLine(command);
  // A command with a quote, backslash or line break has no line that every
  // shell reads the same: the owner types it, a server has no app to use.
  if (!line) {
    return (
      <div className="stack tight">
        <p className="meta">Only the machine's owner adds a sudo command, quoted for the shell, or in the Nerve app, Permissions, Sudo:</p>
        <code className="code mono">nerve-node rule add allow --action exec.run --exact 'COMMAND'</code>
      </div>
    );
  }
  return (
    <div className="stack tight">
      <p className="meta">Only the machine's owner adds a sudo command. On that machine (--center &lt;name&gt; for several pairings):</p>
      <CopyRow value={line} />
    </div>
  );
}

/** The rules an entry the machine decided can become, on the machine. */
function MachineRules({ d, n }: { d: Decision; n?: Node }) {
  const write = n && n.settings_write;
  const why = !n ? "The machine is no longer paired." : !write ? "This machine did not give this center the settings grant." : "";
  const cut = isCut(d.cap, d.action, d.target);
  const known = d.cap && d.action && !cut && (d.target || !["exec", "fs"].includes(d.cap));
  // A sudo command has its own allow list, which only the machine's owner
  // adds to: the row says where. Deny rules take it as any other.
  const sudo = isSudo(d.cap, d.action, d.target);
  const rule = (list: string, wildcard: boolean, pin?: () => unknown) => async () => {
    const r = await api("POST", "/api/audit/rule", { node_id: d.node_id, list, cap: d.cap, action: d.action, target: d.target || "", wildcard, pin: pin ? pin() : null });
    toast(`Added to the ${list} list: ${r.rule}`);
  };
  const b = (label: string, kind: "" | "danger", list: string, wildcard: boolean, icon?: string, pin?: () => unknown) => (
    <Btn key={label} kind={kind} icon={icon} act={rule(list, wildcard, pin)} disabled={!write} title={write ? undefined : why}>
      {label}
    </Btn>
  );
  if (cut) return <p className="meta">The target was cut to its start, so no rule can name it.</p>;
  if (!known) return null;
  return (
    <DSec title="A rule for next time">
      <div className="acts-row">
        {sudo ? null : b("Allow", "", "allow", false, "check")}
        {sudo ? null : b("Allow as wildcard", "", "allow", true)}
        {b("Deny", "danger", "deny", false, "ban")}
        {b("Deny as wildcard", "danger", "deny", true)}
      </div>
      {sudo ? <SudoListHint n={n} command={d.target || ""} /> : null}
      <Pins d={d}>
        {(pin) => (
          <>
            {b("Allow with this value", "", "allow", false, undefined, pin)}
            {b("Deny with this value", "danger", "deny", false, undefined, pin)}
          </>
        )}
      </Pins>
      {!write ? <p className="meta">{why}</p> : null}
    </DSec>
  );
}

/** What a refusal of the action checker can become: a rule that skips the
 * model (center-side, no grant needed), unless the blocklist refused it,
 * which is changed on the Action checker page. */
function CheckerRules({ d }: { d: Decision }) {
  const layer = d.checker ? d.checker.layer : "";
  const scope = d.checker ? d.checker.scope : "";
  const refused = d.decision === "forbidden";
  const cut = isCut(d.cap, d.action, d.target);
  const known = d.cap && d.action && !cut && (d.target || !["exec", "fs"].includes(d.cap));
  if (layer === "blocklist") {
    return (
      <p className="meta">
        On the blocklist (hard deny).{" "}
        <a href="#checker" onClick={() => focusChecker({ view: "mach", id: `m:${d.node_id}` })}>
          {scope === "global" ? "Switch this entry off for this machine" : "Change the entry"}
        </a>{" "}
        on the Action checker page.
      </p>
    );
  }
  if (!refused || !known) return null;
  const allow = (wildcard: boolean, pin?: () => unknown) => async () => {
    const r = await api("POST", "/api/checker/allow", { cap: d.cap, action: d.action, target: d.target || "", wildcard, node_id: d.node_id, pin: pin ? pin() : null });
    toast(`This now skips the model: ${r.rule}`);
  };
  return (
    <DSec title="A rule for next time">
      <div className="acts-row">
        <Btn icon="check" act={allow(false)}>
          Trust this
        </Btn>
        <Btn act={allow(true)}>Trust as wildcard</Btn>
      </div>
      <Pins d={d}>{(pin) => <Btn act={allow(false, pin)}>Trust with this value</Btn>}</Pins>
    </DSec>
  );
}

function checkerLine(d: Decision): string | null {
  if (!d.checker || !d.checker.detail) return null;
  const { layer, detail, scope } = d.checker;
  // Whether the entry, rule or switch behind it was the center's for every
  // machine or this machine's own (entries from before per-machine
  // settings have no scope). For the model it is the switch that had it on.
  const whose = !scope
    ? ""
    : layer === "model"
      ? scope === "node"
        ? " (on by this machine's own setting)"
        : " (on for every machine)"
      : scope === "node"
        ? " (this machine's own)"
        : " (for every machine)";
  const name = layer === "model" ? "Decision model" : layer === "allow rule" ? "Skip the model" : "Blocklist";
  return `${name}${whose}: ${detail}`;
}

function DecisionDetail({ d, n }: { d: Decision; n?: Node }) {
  const k = DECISIONS[d.decision] || { icon: "info", tone: "neutral" };
  const byChecker = d.by === "action checker";
  const what = d.cap === "fs" ? "The path" : d.cap === "exec" ? "The command" : "The target";
  const icon = byChecker ? (d.checker?.layer === "blocklist" ? "ban" : "bot") : k.icon;
  return (
    <Detail
      icon={icon}
      tile={k.tone || "neutral"}
      title={`${d.cap}.${d.action}`}
      mono
      pills={<Pill tone={k.tone}>{d.decision + (d.by ? ` by ${d.by}` : "") + (d.code ? ` [${d.code}]` : "")}</Pill>}
      actions={
        <span className="faint" title={when(d.ts)}>
          {d.node} · {ago(d.ts)}
        </span>
      }
    >
      {d.target ? (
        <DSec title={what}>
          <code className="target">{d.target}</code>
        </DSec>
      ) : null}
      {checkerLine(d) ? <p className="meta">{checkerLine(d)}</p> : null}
      {byChecker ? <CheckerRules d={d} /> : <MachineRules d={d} n={n} />}
    </Detail>
  );
}

const SHOWN = 200;

export function AuditPage() {
  const { ov } = useCenter();
  const audit = usePoll(() => api<{ decisions: Decision[] }>("GET", "/api/audit"), []);
  const [kind, setKind] = useState<"all" | "allowed" | "refused">("all");
  const [machine, setMachine] = useState<string | null>(null);
  const [q, setQ] = useState("");
  const [sel, setSel] = useState<{ key: string; d: Decision } | null>(null);
  const [open, setOpen] = useState(false);
  const nodes = useMemo(() => Object.fromEntries(ov.nodes.map((n) => [n.id, n])), [ov.nodes]);
  const all = useMemo(() => (audit.data ? audit.data.decisions.slice().reverse() : []), [audit.data]);
  const refused = (d: Decision) => d.decision !== "allowed";
  const pass = (d: Decision) =>
    (kind === "all" || (kind === "refused") === refused(d)) &&
    (machine === null || d.node_id === machine) &&
    (!q.trim() || `${d.cap}.${d.action} ${d.target || ""} ${d.checker?.detail || ""}`.toLowerCase().includes(q.trim().toLowerCase()));
  const list = all.filter(pass);
  const shown = list.slice(0, SHOWN);
  // A decision has no id; its time, machine, call and target name it, and a
  // count, oldest first, the same call twice in one millisecond.
  const keys = useMemo(() => {
    const seen = new Map<string, number>();
    return new Map(
      (audit.data ? audit.data.decisions : []).map((x) => {
        const k = `${x.ts}:${x.node_id}:${x.cap}.${x.action}:${x.target || ""}`;
        const n = seen.get(k) || 0;
        seen.set(k, n + 1);
        return [x, `${k}#${n}`];
      }),
    );
  }, [audit.data]);
  const key = (x: Decision) => keys.get(x) || "";
  // The details keep the decision that was picked, also once newer ones
  // push it out of the list or the answer: a rule button never acts on
  // another decision than the one that was read. Only a filter that no
  // longer lets it through (or none picked yet) shows the newest.
  const picked = shown.find((x) => key(x) === sel?.key) || (sel && pass(sel.d) ? sel.d : undefined);
  const d = picked || shown[0];
  const first = d ? key(d) : null;
  useEffect(() => {
    if (d && !picked && first) setSel({ key: first, d });
  }, [d, picked, first]);
  const machines = [{ value: null, text: "Every machine" }, ...ov.nodes.map((n) => ({ value: n.id as string | null, text: n.name }))];
  return (
    <>
      <PageHead icon="audit" title="Audit" sub="Every decision about a call, newest first.">
        <Btn kind="ghost" size="" icon="refresh" act={audit.reload}>
          Refresh
        </Btn>
      </PageHead>
      {!audit.data ? (
        <Loading />
      ) : (
        <>
          <div className="filters">
            <Seg
              label="Decisions"
              value={kind}
              onChange={(v) => setKind(v)}
              options={[
                { value: "all", label: "All", count: all.length },
                { value: "allowed", label: "Allowed", count: all.filter((x) => !refused(x)).length },
                { value: "refused", label: "Refused", count: all.filter(refused).length },
              ]}
            />
            <TextInput value={q} onChange={setQ} type="search" placeholder="Find in target and reason" aria-label="Find in target and reason" />
            <Picker label="Machine" hideLabel items={machines} value={machine} onPick={setMachine} search="Search machines" none="No machine matches." />
          </div>
          {shown.length ? (
            <Split
              variant="even"
              open={open}
              onBack={() => setOpen(false)}
              list={
                <ListCard>
                  <div className="lead-space" />
                  {shown.map((x, idx) => {
                    const k = DECISIONS[x.decision] || { icon: "info", tone: "" };
                    return (
                      <LRow
                        key={`${idx}:${key(x)}`}
                        current={d === x}
                        onPick={() => {
                          setSel({ key: key(x), d: x });
                          setOpen(true);
                        }}
                      >
                        <span className={"tone-" + k.tone}>
                          <Icon name={x.by === "action checker" ? "bot" : k.icon} />
                        </span>
                        <span className="mono">
                          {x.cap}.{x.action}
                        </span>
                        <span className="mono cut faint grow">{x.target || x.node}</span>
                        <span className="side-text" title={when(x.ts)}>
                          {ago(x.ts).replace(" ago", "")}
                        </span>
                      </LRow>
                    );
                  })}
                  {list.length > shown.length ? <p className="lnote top">Showing the latest {shown.length} of {list.length}.</p> : null}
                </ListCard>
              }
              detail={d ? <DecisionDetail key={first || sel?.key} d={d} n={nodes[d.node_id] as Json} /> : null}
            />
          ) : (
            <div className="card">
              <Empty icon="audit">{all.length ? "Nothing matches these filters." : "No decisions yet."}</Empty>
            </div>
          )}
        </>
      )}
    </>
  );
}
