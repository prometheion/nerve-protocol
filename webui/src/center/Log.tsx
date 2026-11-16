// Log: what the center did and saw, newest first, filtered by level,
// machine and text; the details show the picked entry whole.
import { useEffect, useState } from "react";
import { api, download } from "../api";
import { usePoll } from "../frame";
import { clock, when } from "../format";
import { Btn, Dot, Empty, LRow, ListCard, Loading, PageHead, Picker, Pill, Split, TextInput, copy, type Tone } from "../ui";

type Entry = { seq: number; ts: number; level: string; node?: string | null; node_id?: string | null; msg: string };
type Log = { entries: Entry[]; nodes: { id: string; name: string; paired: boolean }[]; level: string; file: boolean };

// The levels the page filters by, most to least verbose: a level shows
// itself and what is more severe. The log keeps the level set in Settings;
// this only narrows what is shown.
const LEVELS = [
  { value: "debug", text: "Everything" },
  { value: "info", text: "Info and above" },
  { value: "warn", text: "Warnings and errors" },
  { value: "error", text: "Errors only" },
];
const TONE: Record<string, Tone> = { error: "danger", warn: "warn", info: "accent", debug: "" };
const WORD: Record<string, string> = { error: "Error", warn: "Warning", info: "Info", debug: "Debug" };

export function LogPage() {
  const [level, setLevel] = useState("debug");
  // A machine's id, "-" for what is about no machine, null for all.
  const [node, setNode] = useState<string | null>(null);
  const [typed, setTyped] = useState("");
  const [q, setQ] = useState("");
  const [live, setLive] = useState(true);
  const [sel, setSel] = useState<number | null>(null);
  const [open, setOpen] = useState(false);
  useEffect(() => {
    const t = setTimeout(() => setQ(typed), 250);
    return () => clearTimeout(t);
  }, [typed]);
  const path = () => {
    const p = new URLSearchParams();
    if (level !== "debug") p.set("level", level);
    if (node) p.set("node", node);
    if (q.trim()) p.set("q", q.trim());
    const s = p.toString();
    return "/api/log" + (s ? "?" + s : "");
  };
  const log = usePoll(() => api<Log>("GET", path()), [level, node, q, live], live ? 2000 : 0, true);
  const l = log.data;
  const machines = l ? l.nodes.slice().sort((a, b) => a.name.localeCompare(b.name)) : [];
  const nodeItems = [
    { value: null, text: "All machines" },
    { value: "-", text: "The center itself" },
    ...machines.map((n) => ({ value: n.id as string | null, text: n.paired ? n.name : `${n.name} (removed)` })),
  ];
  const e = l ? l.entries.find((x) => x.seq === sel) || l.entries[0] : undefined;
  const count = (lv: string) => (l ? l.entries.filter((x) => x.level === lv).length : 0);
  const filtered = level !== "debug" || node !== null || q.trim() !== "";
  const sub = l
    ? [
        `${l.entries.length} ${l.entries.length === 1 ? "entry" : "entries"} shown`,
        count("error") ? `${count("error")} errors` : "",
        count("warn") ? `${count("warn")} ${count("warn") === 1 ? "warning" : "warnings"}` : "",
        `level ${l.level} (Settings)`,
      ]
        .filter(Boolean)
        .join(" · ")
    : undefined;
  return (
    <>
      <PageHead icon="log" title="Log" sub={sub}>
        <Btn kind="ghost" size="" icon="refresh" act={log.reload}>
          Refresh
        </Btn>
      </PageHead>
      <div className="filters">
        <Picker label="Level" hideLabel items={LEVELS} value={level} onPick={setLevel} search="Search levels" none="No level matches." />
        <Picker label="Machine" hideLabel items={nodeItems} value={node} onPick={setNode} search="Search machines" none="No machine matches." />
        <TextInput value={typed} onChange={setTyped} type="search" placeholder="Search the messages" aria-label="Search the messages" />
        <button type="button" className="btn ghost" aria-pressed={live} title="Pause or resume the updates" onClick={() => setLive(!live)}>
          <Dot tone={live ? "ok" : ""} />
          {live ? "Live" : "Paused"}
        </button>
        {l && l.file ? (
          <Btn kind="ghost" size="" icon="download" title="The whole log file, one JSON object per line" act={() => download("/api/log/download", "nerve-center-log.jsonl")}>
            Download the file
          </Btn>
        ) : null}
      </div>
      {!l ? (
        <Loading />
      ) : l.entries.length ? (
        <Split
          variant="even"
          open={open}
          onBack={() => setOpen(false)}
          list={
            <ListCard>
              <div className="lead-space" />
              {l.entries.map((x) => (
                <LRow
                  key={x.seq}
                  current={x === e}
                  onPick={() => {
                    setSel(x.seq);
                    setOpen(true);
                  }}
                >
                  <Dot tone={TONE[x.level] || ""} />
                  <span className="mono faint" title={when(x.ts)}>
                    {clock(x.ts)}
                  </span>
                  <span className="cut grow">
                    {x.node ? <b>{x.node} </b> : null}
                    {x.msg}
                  </span>
                </LRow>
              ))}
            </ListCard>
          }
          detail={
            e ? (
              <section className="card detail">
                <div className="dhead">
                  <Pill tone={TONE[e.level] || ""} dot>
                    {WORD[e.level] || e.level}
                  </Pill>
                  <span className="faint">{when(e.ts)}</span>
                  {e.node ? (
                    <Pill tone="line" title={e.node_id || ""}>
                      {e.node}
                    </Pill>
                  ) : null}
                  <span className="dacts">
                    <Btn kind="ghost" icon="copy" onClick={() => copy(e.msg)}>
                      Copy
                    </Btn>
                  </span>
                </div>
                <p className="lead wrap">{e.msg}</p>
              </section>
            ) : null
          }
        />
      ) : (
        <div className="card">
          <Empty icon="log">{filtered ? "Nothing matches these filters." : "The log is empty."}</Empty>
        </div>
      )}
    </>
  );
}
