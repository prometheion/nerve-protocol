// Help, as the desktop app has it: a task map that says where each task is
// done, the reference of the node's commands by topic or from A to Z, to
// filter, each one opening on what it does, how it is written and its
// arguments, and the keyboard shortcuts. The commands come as the node's own
// CLI definition lists them (/api/help); nothing here names a command.
import { useState, type ReactNode } from "react";
import { guide } from "../api";
import { Icon, More, Pill, Seg, TextInput } from "../ui";

export type Arg = { name: string; line: string; more?: string; optional?: boolean };
export type Verb = { name: string; usage: string; line: string; more?: string; args: Arg[] };
export type Card = { name: string; line?: string; more?: string; doc?: string; holds: string[]; verbs: Verb[]; shared_args?: Arg[] };
export type NodeHelp = { sections: { name: string; line: string; cards: Card[] }[]; options?: Arg[] };

export const KEYS: [string, string][] = [
  ["Tab, Shift+Tab", "The next or the last control"],
  ["Enter, Space", "Press a button, pick a row, open or close a part"],
  ["Esc", "Close an overlay, a list or the menu"],
  ["↓ ↑", "Open a list and move through it"],
  ["Page Down, Page Up", "Six entries further in a list"],
  ["← →", "Choose in a row of choices"],
];

export function Keys() {
  return (
    <div className="keys">
      {KEYS.map(([k, d]) => (
        <span key={k} className="contents">
          <span>
            {k.split(", ").map((x, i) => (
              <span key={x}>
                {i ? " " : ""}
                <kbd>{x}</kbd>
              </span>
            ))}
          </span>
          <span>{d}</span>
        </span>
      ))}
    </div>
  );
}

/** A group of tasks, each with the place it is done, linked. */
export type Task = [string, string, string];

export function TaskMap({ groups }: { groups: [string, Task[]][] }) {
  return (
    <div>
      {groups.map(([g, rows], i) => (
        <details key={g} className="fold" open={i === 0}>
          <summary>
            <span>{g}</span>
            <span className="count">{rows.length}</span>
            <Icon name="chev" size="sm" />
          </summary>
          <div className="fb">
            {rows.map(([task, where, page]) => (
              <div key={task} className="task">
                <span>{task}</span>
                <a href={`#${page}`}>
                  <Icon name="arrow-right" size="sm" />
                  {where}
                </a>
              </div>
            ))}
          </div>
        </details>
      ))}
    </div>
  );
}

function Args({ list }: { list: Arg[] }) {
  return (
    <div className="args">
      {list.map((a) => (
        <span key={a.name + a.line} className="contents">
          <code className="mono">{a.name}</code>
          <span>
            {(a.optional ? "Optional. " : "") + a.line}
            {a.more ? (
              <More>
                <p>{a.more}</p>
              </More>
            ) : null}
          </span>
        </span>
      ))}
    </div>
  );
}

/** The lines start after `nerve-node`, which the page says once. */
const words = (usage: string) => usage.replace(/^nerve-node /, "").replace(" [OPTIONS]", "");

function CommandRow({ c, topic, byName, hit }: { c: Card; topic: string; byName: boolean; hit: boolean }) {
  const alone = c.verbs.length === 1 && c.verbs[0].name === c.name ? c.verbs[0] : null;
  const line = c.line || (alone ? alone.line : c.verbs.map((v) => v.name).join(", "));
  const own = (v: Verb) => v.args.concat(c.shared_args || []);
  const bare = alone && words(alone.usage) === c.name && !own(alone).length && !alone.more;
  return (
    <details className="cmd" open={hit || undefined} id={"cmd-" + c.name.replace(/[^\w]+/g, "-")}>
      <summary>
        <code className="mono">{c.name}</code>
        <span>{line}</span>
        {byName ? <Pill>{topic}</Pill> : <span />}
        <Icon name="chev" size="sm" />
      </summary>
      <div className="body">
        {c.more ? <p>{c.more}</p> : null}
        {bare
          ? null
          : c.verbs.map((v) => (
              <div key={v.name} className="verb">
                <code className="code mono">{words(v.usage)}</code>
                <p>{v.line}</p>
                {v.more ? (
                  <More>
                    <p>{v.more}</p>
                  </More>
                ) : null}
                {own(v).length ? (
                  <More summary={`Options (${own(v).length})`}>
                    <Args list={own(v)} />
                  </More>
                ) : null}
              </div>
            ))}
        {c.doc ? (
          <p className="meta">
            More in the user guide:{" "}
            <a href={`${guide()}/${c.doc}`} target="_blank" rel="noopener noreferrer">
              {c.doc}
            </a>
          </p>
        ) : null}
      </div>
    </details>
  );
}

/** The command reference of nerve-node, by topic or A to Z, to filter. */
export function CommandReference({ h, lead }: { h: NodeHelp; lead: ReactNode }) {
  const [q, setQ] = useState("");
  const [byName, setByName] = useState(false);
  const rows = h.sections.flatMap((s) =>
    s.cards.map((c) => ({
      c,
      topic: s.name,
      text: [c.name, c.line, c.more, ...c.verbs.flatMap((v) => [v.name, v.line, v.more, ...v.args.concat(c.shared_args || []).map((a) => `${a.name} ${a.line} ${a.more}`)])]
        .join("\n")
        .toLowerCase(),
    })),
  );
  const t = q.trim().toLowerCase();
  const hit = (r: { text: string }) => !t || r.text.includes(t);
  const shown = rows.filter(hit);
  return (
    <div className="stack tight">
      <p className="meta">{lead}</p>
      <div className="refbar">
        <TextInput value={q} onChange={setQ} type="search" placeholder="Filter: pair, folder, sudo…" aria-label="Filter the commands" />
        <Seg
          label="Order"
          value={byName ? "az" : "topic"}
          onChange={(v) => setByName(v === "az")}
          options={[
            { value: "topic", label: "By topic" },
            { value: "az", label: "A to Z" },
          ]}
        />
      </div>
      {shown.length ? null : <p className="meta">No command matches.</p>}
      {byName
        ? shown
            .slice()
            .sort((a, b) => a.c.name.localeCompare(b.c.name))
            .map((r) => <CommandRow key={r.c.name} c={r.c} topic={r.topic} byName hit={!!t} />)
        : h.sections.map((s) => {
            const mine = shown.filter((r) => r.topic === s.name);
            if (!mine.length) return null;
            return (
              <details key={s.name} className="fold" open>
                <summary>
                  <span>{s.name}</span>
                  <span className="count">{mine.length}</span>
                  <Icon name="chev" size="sm" />
                </summary>
                <div className="fb">
                  {s.line ? <p className="faint">{s.line}</p> : null}
                  {mine.map((r) => (
                    <CommandRow key={r.c.name} c={r.c} topic={r.topic} byName={false} hit={!!t} />
                  ))}
                </div>
              </details>
            );
          })}
      {h.options && h.options.length ? (
        <More summary={`Shared options (${h.options.length})`}>
          <Args list={h.options} />
        </More>
      ) : null}
    </div>
  );
}
