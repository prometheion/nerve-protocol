// Help: its sections as a list (the tasks and where each is done, the
// command reference, the keys), the picked one on the right, and the user
// guide at the top.
import { useState, type ReactNode } from "react";
import { api, guide } from "../api";
import { usePoll } from "../frame";
import { CommandReference, Keys, TaskMap, type NodeHelp, type Task } from "../shared/help";
import { Icon, LRow, LinkBtn, ListCard, Loading, PageHead, Split } from "../ui";

const TASKS: [string, Task[]][] = [
  [
    "Centers",
    [
      ["Pair a center", "Centers › Pair a center", "centers"],
      ["Rotate a center's key", "Centers › New key…", "centers"],
      ["Let a center change its rights", "Centers › Settings grant", "centers"],
    ],
  ],
  [
    "What a center may do",
    [
      ["Choose what it may do", "Permissions › Mode", "permissions"],
      ["Give it a folder", "Permissions › Folders", "permissions"],
      ["Allow or forbid one command", "Permissions › Allowed, Forbidden commands", "permissions"],
      ["Keep commands off the network", "Permissions › No network", "permissions"],
      ["Switch a capability on or off", "Capabilities", "capabilities"],
      ["Add a program's capabilities", "Capabilities › Programs", "capabilities"],
    ],
  ],
  [
    "This machine",
    [
      ["Its name and log", "Settings › This machine", "settings"],
      ["Use a proxy or a relay", "Relay", "relay"],
      ["Any setting by its name", "Settings › Any setting", "settings"],
      ["The web UI's tokens", "Settings › Web UI", "settings"],
    ],
  ],
  [
    "When something is wrong",
    [
      ["See what happened", "Audit, Log", "audit"],
      ["Stop everything at once", "Overview › Panic", "overview"],
    ],
  ],
];

const SECTIONS: [string, string, string][] = [
  ["tasks", "Tasks", "check"],
  ["ref", "Command reference", "terminal"],
  ["keys", "Keyboard shortcuts", "keyboard"],
];

export function HelpPage() {
  // The command list does not change while the node runs: asked once.
  const help = usePoll(() => api<{ node: NodeHelp }>("GET", "/api/help"), [], 0);
  const [sec, setSec] = useState("tasks");
  const [open, setOpen] = useState(false);
  const title = SECTIONS.find((s) => s[0] === sec)!;
  let body: ReactNode = <Loading />;
  if (sec === "tasks") body = <TaskMap groups={TASKS} />;
  else if (sec === "keys") body = <Keys />;
  else if (help.data) body = <CommandReference h={help.data.node} lead="Every action here runs one of these nerve-node commands, with the same checks and audit records." />;
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
