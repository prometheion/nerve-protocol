// Log: the node's starts and stops, its links, and what went wrong, newest
// first; the details show the picked line whole.
import { useState } from "react";
import { api } from "../api";
import { usePoll } from "../frame";
import { ago, clock, when } from "../format";
import { Btn, Dot, Empty, LRow, ListCard, Loading, PageHead, Pill, Seg, Split, TextInput, ask, copy, type Tone } from "../ui";
import type { Json } from "./types";

const TONE: Record<string, Tone> = { error: "danger", warn: "warn", info: "accent" };
const WORD: Record<string, string> = { error: "Error", warn: "Warning", info: "Info", debug: "Debug" };

export function LogPage() {
  const [problems, setProblems] = useState(false);
  const [live, setLive] = useState(true);
  const [q, setQ] = useState("");
  const [sel, setSel] = useState<string | null>(null);
  const [open, setOpen] = useState(false);
  const log = usePoll(() => api<{ entries: Json[] }>("GET", `/api/log${problems ? "?problems=1" : ""}`), [problems, live], live ? 2000 : 0);
  const all: Json[] = log.data ? log.data.entries.slice().reverse() : [];
  const t = q.trim().toLowerCase();
  const list = all.map((e) => ({ e, i: `${e.ts}:${e.msg}` })).filter(({ e }) => !t || String(e.msg || "").toLowerCase().includes(t));
  const cur = list.find((x) => x.i === sel) || list[0];
  return (
    <>
      <PageHead icon="log" title="Log" sub="The node's starts and stops, its links, and what went wrong.">
        <Btn kind="ghost" size="" icon="refresh" act={log.reload}>
          Refresh
        </Btn>
        <Btn
          kind="ghost"
          size=""
          icon="trash"
          act={async () => {
            const yes = await ask({ title: "Clear the log?", message: "Its lines so far are deleted; one line says who cleared it.", confirm: "Clear", danger: true });
            if (!yes) return;
            await api("POST", "/api/log/clear");
            await log.reload();
          }}
        >
          Clear
        </Btn>
      </PageHead>
      <div className="filters">
        <Seg
          label="Lines"
          value={problems ? "problems" : "all"}
          onChange={(v) => setProblems(v === "problems")}
          options={[
            { value: "all", label: "All" },
            { value: "problems", label: "Problems" },
          ]}
        />
        <TextInput value={q} onChange={setQ} type="search" placeholder="Search the messages" aria-label="Search the messages" />
        <button type="button" className="btn ghost" aria-pressed={live} title="Pause or resume the updates" onClick={() => setLive(!live)}>
          <Dot tone={live ? "ok" : ""} />
          {live ? "Live" : "Paused"}
        </button>
      </div>
      {!log.data ? (
        <Loading />
      ) : list.length ? (
        <Split
          variant="even"
          open={open}
          onBack={() => setOpen(false)}
          list={
            <ListCard>
              <div className="lead-space" />
              {list.map(({ e, i }, idx) => (
                <LRow
                  key={idx}
                  current={cur && cur.i === i}
                  onPick={() => {
                    setSel(i);
                    setOpen(true);
                  }}
                >
                  <Dot tone={TONE[e.level] || ""} />
                  <span className="mono faint" title={e.ts ? when(e.ts) : ""}>
                    {e.ts ? clock(e.ts) : ""}
                  </span>
                  <span className="cut grow">{e.msg || ""}</span>
                </LRow>
              ))}
              <p className="lnote top">The newest 500 lines. Older ones stay in the log file.</p>
            </ListCard>
          }
          detail={
            cur ? (
              <section className="card detail">
                <div className="dhead">
                  <Pill tone={TONE[cur.e.level] || ""} dot>
                    {WORD[cur.e.level] || cur.e.level || "Line"}
                  </Pill>
                  <span className="faint">{cur.e.ts ? `${when(cur.e.ts)} (${ago(cur.e.ts)})` : ""}</span>
                  <span className="dacts">
                    <Btn kind="ghost" icon="copy" onClick={() => copy(cur.e.msg || "")}>
                      Copy
                    </Btn>
                  </span>
                </div>
                <p className="lead wrap">{cur.e.msg || ""}</p>
              </section>
            ) : null
          }
        />
      ) : (
        <div className="card">
          <Empty icon="log">{all.length ? "Nothing matches." : "Nothing yet."}</Empty>
        </div>
      )}
    </>
  );
}
