// The center's Overview: its state, Get started while a new center has
// steps left, the machines as a list with the picked one's details, and on
// a large window the sessions beside them.
import { useState } from "react";
import { api } from "../api";
import { usePoll } from "../frame";
import { when } from "../format";
import { Banner, Btn, CopyRow, Empty, Icon, ListCard, PageHead, Split, Tile } from "../ui";
import { useCenter } from "./App";
import { SessionRows } from "./Harnesses";
import { FOLDER_STEP, centerOnWindows } from "./lines";
import { NodeDetail, NodeRows, PairedBanner } from "./Nodes";
import type { Overview } from "./types";

/** Get started: three steps for a new center, each with its button; it goes
 * once all three are done. */
export function GetStarted({ o, pair }: { o: Overview; pair: () => void }) {
  const paired = o.nodes.length > 0;
  const folder = o.nodes.some((n) => (n.folders || 0) > 0 || n.folders === null);
  const harness = o.sessions.length > 0;
  if (paired && folder && harness) return null;
  // Where every machine runs Windows, the folder is given in the Nerve app;
  // where one may (a Windows center, or a Windows machine among them), the
  // step says so beside the Linux command (#213, W1-F13).
  const windows = o.nodes.length > 0 && o.nodes.every((n) => n.platform === "windows");
  const someWindows = o.nodes.some((n) => n.platform === "windows") || (!o.nodes.length && centerOnWindows(o));
  const step = (done: boolean, text: string, action?: React.ReactNode) => (
    <div className="step">
      <Tile icon={done ? "ok" : "info"} tone={done ? "ok" : "neutral"} size="sm" />
      <span className={"grow " + (done ? "meta" : "name")}>{text}</span>
      {done ? null : action}
    </div>
  );
  return (
    <section className="card steps mb" aria-label="Get started">
      <div className="sechead">
        <div>
          <h2>Get started</h2>
          <p>Three steps; this goes once they are done.</p>
        </div>
      </div>
      {step(paired, "1. Pair a machine", <Btn kind="primary" icon="plus" onClick={pair}>Pair a machine</Btn>)}
      {windows
        ? step(folder, "2. Give it a folder: in the Nerve app on that machine, Permissions › Folders")
        : step(
            folder,
            someWindows ? "2. Give it a folder (on Windows in the Nerve app, Permissions › Folders)" : "2. Give it a folder",
            <CopyRow label={someWindows ? "Linux" : undefined} value={FOLDER_STEP} />,
          )}
      {step(harness, "3. Connect a harness", <a className="btn ghost sm" href="#harnesses">How</a>)}
    </section>
  );
}

function mcpLine(o: Overview): string {
  const m = o.mcp;
  if (m.mode === "off") return "No MCP here: harnesses attach to another center.";
  if (m.mode === "stdio") return "A harness starts it over stdio.";
  return `Harnesses at ${m.url}`;
}

export function OverviewPage() {
  const { ov, overview, pair } = useCenter();
  const checker = usePoll(() => api("GET", "/api/checker"), [], 10000);
  const [id, setId] = useState<string | null>(null);
  const [open, setOpen] = useState(false);
  const online = ov.nodes.filter((n) => n.online).length;
  const n = ov.nodes.find((x) => x.id === id) || ov.nodes[0];
  const cfg = checker.data?.config;
  return (
    <>
      <PageHead icon="overview" title="Overview">
        <Btn kind="ghost" size="" icon="refresh" act={overview.reload}>
          Refresh
        </Btn>
      </PageHead>
      <div className="ovtop">
        <div className="card status">
          <span className="big">
            <Icon name="route" />
          </span>
          <div className="grow">
            <h2>Running</h2>
            <p>
              {ov.center.name}: nodes reach it at {ov.center.url}.
            </p>
            <span className="meta row">
              <Icon name="plug" />
              {mcpLine(ov)}
            </span>
          </div>
        </div>
        <div className="card pad row">
          <Tile icon="server" tone={online ? "ok" : "neutral"} />
          <div className="grow">
            <b>Machines</b>
            <div className="meta">
              {ov.nodes.length ? `${online} of ${ov.nodes.length} online.` : "None paired yet."} A new one pairs with a code for one machine.
            </div>
          </div>
          <Btn kind="primary" size="" icon="plus" onClick={pair}>
            Pair a machine
          </Btn>
        </div>
      </div>
      <div className="banners">
        {ov.alerts.slice(-5).map((a, i) => (
          <Banner key={i} tone="warn">
            {when(a.ts)}: {a.text}
          </Banner>
        ))}
      </div>
      <PairedBanner />
      <GetStarted o={ov} pair={pair} />
      <div className="card strip">
        <span className="fact">
          <Icon name="server" />
          Nodes <b>{ov.nodes.length ? `${online} of ${ov.nodes.length} online` : "none paired"}</b>
        </span>
        <span className="fact">
          <Icon name="activity" />
          Sessions <b>{ov.sessions.length}</b>
        </span>
        {cfg ? (
          <a className="fact" href="#checker">
            <Icon name="octagon" />
            Action checker{" "}
            <b>
              Blocklist {cfg.blocklist_on ? "on" : "off"} · model {cfg.model_on ? "on" : "off"}
            </b>
          </a>
        ) : null}
      </div>
      {ov.nodes.length ? (
        <Split
          variant="side3"
          open={open}
          onBack={() => setOpen(false)}
          list={
            <ListCard>
              <NodeRows
                nodes={ov.nodes}
                id={n?.id ?? null}
                pick={(x) => {
                  setId(x);
                  setOpen(true);
                }}
              />
            </ListCard>
          }
          detail={n ? <NodeDetail key={n.id} n={n} reload={overview.reload} /> : null}
          third={
            <section className="card clip">
              <div className="sechead">
                <Icon name="activity" size="lg" />
                <div>
                  <h2>Sessions</h2>
                  <p>Harnesses that are connected to this center.</p>
                </div>
              </div>
              <SessionRows sessions={ov.sessions} />
            </section>
          }
        />
      ) : (
        <div className="card">
          <Empty icon="server">No machines yet. Pair one to get started.</Empty>
        </div>
      )}
    </>
  );
}
