// Help: its sections as a list (the tasks and where each is done, the
// center's own commands, the node's commands, the keys), the picked one on
// the right, and the user guide at the top.
import { useState, type ReactNode } from "react";
import { api, guide } from "../api";
import { usePoll } from "../frame";
import { CommandReference, Keys, TaskMap, type NodeHelp, type Task } from "../shared/help";
import { Icon, LRow, LinkBtn, ListCard, Loading, More, PageHead, Split } from "../ui";
import { useCenter } from "./App";
import { centerOnWindows, windowsHelpNote } from "./lines";

type CenterHelp = { commands: { name: string; line: string; more?: string }[]; options: { name: string; line: string; more?: string; advanced?: boolean }[] };

const TASKS: [string, Task[]][] = [
  [
    "Machines and harnesses",
    [
      ["Pair a machine", "Nodes › Pair a machine", "nodes"],
      ["Connect a harness", "Harnesses › Connect a harness", "harnesses"],
      ["End a harness's session", "Harnesses › Sessions", "harnesses"],
      ["Turn a machine off for the agent", "Nodes › Disable", "nodes"],
    ],
  ],
  [
    "What the agent may do",
    [
      ["Refuse a kind of call", "Action checker › Blocklist", "checker"],
      ["Let calls skip the model", "Action checker › Skip the model", "checker"],
      ["See what a machine offers", "Capabilities", "capabilities"],
      ["Add a capability to a machine", "Capabilities › Add a capability", "capabilities"],
    ],
  ],
  [
    "This center",
    [
      ["Its name, and what it keeps", "Settings › Center", "settings"],
      ["Rotate the center key", "Settings › Center key", "settings"],
      ["A machine's own settings", "Settings › Machines", "settings"],
    ],
  ],
  ["When something is wrong", [["See what happened", "Audit, Log, Statistics", "audit"]]],
];

function Lines({ list }: { list: { name: string; line: string; more?: string }[] }) {
  return (
    <div className="args">
      {list.map((x) => (
        <span key={x.name} className="contents">
          <code className="mono">{x.name}</code>
          <span>
            {x.line}
            {x.more ? (
              <More>
                <p>{x.more}</p>
              </More>
            ) : null}
          </span>
        </span>
      ))}
    </div>
  );
}

/** The center's own commands, one line each with the rest folded; its
 * options after them, those under Advanced folded apart. */
function CenterCommands({ c, windows }: { c: CenterHelp; windows: boolean }) {
  const main = c.options.filter((o) => !o.advanced);
  const adv = c.options.filter((o) => o.advanced);
  return (
    <div className="stack tight">
      <p className="meta">
        {windows ? "Run them on the center's machine; in an administrator's terminal for the installed center." : "Run them on the center's machine; with sudo for the installed center."}
      </p>
      <Lines list={c.commands} />
      <More summary={`Options (${main.length})`}>
        <Lines list={main} />
      </More>
      <More summary={`Advanced (${adv.length})`}>
        <Lines list={adv} />
      </More>
    </div>
  );
}

const SECTIONS: [string, string, string][] = [
  ["tasks", "Tasks", "check"],
  ["center", "nerve-center commands", "terminal"],
  ["node", "nerve-node commands", "terminal"],
  ["keys", "Keyboard shortcuts", "keyboard"],
];

export function HelpPage() {
  const { ov } = useCenter();
  // The command list does not change while the center runs: asked once.
  const help = usePoll(() => api<{ node: NodeHelp; center: CenterHelp }>("GET", "/api/help"), [], 0);
  const [sec, setSec] = useState("tasks");
  const [open, setOpen] = useState(false);
  const windows = windowsHelpNote(ov);
  const h = help.data;
  const title = SECTIONS.find((s) => s[0] === sec)!;
  let body: ReactNode = <Loading />;
  if (sec === "tasks") {
    body = (
      <>
        <TaskMap groups={TASKS} />
        <p className="meta">
          New here? <a href="#overview">Get started</a> on the Overview.
        </p>
      </>
    );
  } else if (sec === "keys") {
    body = <Keys />;
  } else if (h && sec === "center") {
    body = <CenterCommands c={h.center} windows={centerOnWindows(ov)} />;
  } else if (h && sec === "node") {
    body = (
      <>
        <CommandReference h={h.node} lead="Commands of nerve-node. Run them on the machine itself." />
        {windows ? (
          <p className="meta">
            {windows}{" "}
            <a href={`${guide()}/windows.md`} target="_blank" rel="noopener noreferrer">
              Nerve on Windows
            </a>
          </p>
        ) : null}
      </>
    );
  }
  return (
    <>
      <PageHead icon="help" title="Help">
        <LinkBtn href={guide()}>User guide</LinkBtn>
      </PageHead>
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
        detail={
          <section className="card clip">
            <div className="sechead">
              <span className="tile sm">
                <Icon name={title[2]} />
              </span>
              <h2>{title[1]}</h2>
            </div>
            <div className="secbody">{body}</div>
          </section>
        }
      />
    </>
  );
}
