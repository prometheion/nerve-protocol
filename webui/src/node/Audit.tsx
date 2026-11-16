// Audit: what the node allowed and refused, newest first, as a list; the
// details show the picked entry and the rules its buttons store, as they
// will be stored.
import { useEffect, useState } from "react";
import { api } from "../api";
import { usePoll } from "../frame";
import { ago, when } from "../format";
import { Btn, DSec, Detail, Dot, Empty, Icon, LRow, ListCard, Loading, PageHead, Pill, Seg, Split, TextInput, ask, toast } from "../ui";
import type { Json } from "./types";

type Entry = Json;

const refusedOf = (e: Entry) => e.decision === "forbidden" || e.event === "refused";
const whatOf = (e: Entry) => [e.cap, e.action].filter(Boolean).join(".") || e.event || "entry";

function EntryDetail({ e }: { e: Entry }) {
  const refused = refusedOf(e);
  // What a button stores and where, as the node makes it (not as it is
  // shown above).
  const add = (kind: "allow" | "wildcard" | "deny") => async () => {
    const r = e.rules[kind];
    const lists: Record<string, string> = { allow: "allow", deny: "deny", sudo: "sudo allow" };
    const yes = await ask({ title: `Add to the ${lists[r.list]} list?`, message: `For ${e.center}, as it will be stored: ${r.rule}`, confirm: "Add" });
    if (!yes) return;
    await api("POST", "/api/audit/rule", { center: e.center, cap: e.cap, action: e.action, target: e.target, list: kind === "deny" ? "deny" : "allow", wildcard: kind === "wildcard" });
    toast(`Added: ${r.rule}`);
  };
  const button = (kind: "allow" | "wildcard" | "deny", label: string, danger?: boolean, icon?: string) =>
    e.rules && e.rules[kind] && e.rules[kind].rule ? (
      <Btn kind={danger ? "danger" : ""} icon={icon} act={add(kind)}>
        {label}
      </Btn>
    ) : null;
  return (
    <Detail
      icon={refused ? "ban" : "ok"}
      tile={refused ? "danger" : "ok"}
      mono
      title={whatOf(e)}
      pills={<Pill tone={refused ? "danger" : "ok"}>{refused ? "Refused" : e.decision === "allowed" ? "Allowed" : e.event || e.decision || "entry"}</Pill>}
      actions={
        <span className="faint" title={e.ts ? when(e.ts) : ""}>
          {e.center ? `${e.center} · ` : ""}
          {e.ts ? ago(e.ts) : ""}
        </span>
      }
    >
      {e.target ? (
        <DSec title={e.cap === "fs" ? "The path" : e.cap === "exec" ? "The command" : "The target"}>
          <code className="target">{e.rule_preview || e.target}</code>
        </DSec>
      ) : null}
      {e.reason ? <p className="meta">{e.reason}</p> : null}
      {e.rule_preview && e.center ? (
        <DSec title="A rule for next time">
          <div className="acts-row">
            {button("allow", "Allow", false, "check")}
            {button("wildcard", "Allow as wildcard")}
            {button("deny", "Deny", true, "ban")}
          </div>
        </DSec>
      ) : null}
    </Detail>
  );
}

export function AuditPage() {
  const [denied, setDenied] = useState(false);
  const [live, setLive] = useState(true);
  const [q, setQ] = useState("");
  const [sel, setSel] = useState<string | null>(null);
  const [open, setOpen] = useState(false);
  const audit = usePoll(() => api<{ entries: Entry[] }>("GET", `/api/audit${denied ? "?denied=1" : ""}`), [denied, live], live ? 2000 : 0);
  const all: Entry[] = audit.data ? audit.data.entries.slice().reverse() : [];
  const t = q.trim().toLowerCase();
  const list = all.filter((e) => !t || `${whatOf(e)} ${e.target || ""} ${e.reason || ""} ${e.center || ""}`.toLowerCase().includes(t));
  const key = (e: Entry) => `${e.ts}:${e.seq}:${whatOf(e)}`;
  const e = list.find((x) => key(x) === sel) || list[0];
  // The details keep the entry they show: a newer one only adds a row, so
  // a rule button never acts on an entry that came in while it was read.
  const shownKey = e ? key(e) : null;
  useEffect(() => {
    if (shownKey && shownKey !== sel) setSel(shownKey);
  }, [shownKey, sel]);
  return (
    <>
      <PageHead icon="audit" title="Audit" sub="What the node allowed and refused.">
        <Btn kind="ghost" size="" icon="refresh" act={audit.reload}>
          Refresh
        </Btn>
        <Btn
          kind="ghost"
          size=""
          icon="trash"
          act={async () => {
            const yes = await ask({ title: "Clear the audit?", message: "The entries so far are kept in the audit's older file.", confirm: "Clear", danger: true });
            if (!yes) return;
            await api("POST", "/api/audit/clear");
            await audit.reload();
          }}
        >
          Clear
        </Btn>
      </PageHead>
      <div className="filters">
        <Seg
          label="Entries"
          value={denied ? "refused" : "all"}
          onChange={(v) => setDenied(v === "refused")}
          options={[
            { value: "all", label: "All" },
            { value: "refused", label: "Refused only" },
          ]}
        />
        <TextInput value={q} onChange={setQ} type="search" placeholder="Find in target and reason" aria-label="Find in target and reason" />
        <button type="button" className="btn ghost" aria-pressed={live} title="Pause or resume the updates" onClick={() => setLive(!live)}>
          <Dot tone={live ? "ok" : ""} />
          {live ? "Live" : "Paused"}
        </button>
      </div>
      {!audit.data ? (
        <Loading />
      ) : list.length ? (
        <Split
          variant="even"
          open={open}
          onBack={() => setOpen(false)}
          list={
            <ListCard>
              <div className="lead-space" />
              {list.map((x, idx) => (
                <LRow
                  key={`${idx}:${key(x)}`}
                  current={x === e}
                  onPick={() => {
                    setSel(key(x));
                    setOpen(true);
                  }}
                >
                  <span className={refusedOf(x) ? "tone-danger" : "tone-ok"}>
                    <Icon name={refusedOf(x) ? "ban" : "ok"} />
                  </span>
                  <span className="mono">{whatOf(x)}</span>
                  <span className="mono cut faint grow">{x.target || x.center || ""}</span>
                  <span className="side-text" title={x.ts ? when(x.ts) : ""}>
                    {x.ts ? ago(x.ts).replace(" ago", "") : ""}
                  </span>
                </LRow>
              ))}
            </ListCard>
          }
          detail={e ? <EntryDetail key={key(e)} e={e} /> : null}
        />
      ) : (
        <div className="card">
          <Empty icon="audit">{all.length ? "Nothing matches." : "Nothing yet."}</Empty>
        </div>
      )}
    </>
  );
}
