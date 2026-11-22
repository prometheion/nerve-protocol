// The node's Overview: its state with Panic or Unlock, what it warns of,
// its centers as a list with the picked one's details, and on a large
// window Pair a center beside them.
import { useState } from "react";
import { api, keepSession, nav } from "../api";
import { plural } from "../format";
import { Banner, Btn, CopyRow, Empty, Icon, ListCard, More, PageHead, Split, Tile, ask, toast } from "../ui";
import { useNode } from "./App";
import { onWindows } from "./types";
import { CenterDetail, CenterRows } from "./Centers";

async function panic() {
  const yes = await ask({
    title: "Panic?",
    message: "Every link closes and nothing runs until you unlock. Every web UI session ends too: you sign in again to unlock.",
    confirm: "Panic",
    danger: true,
  });
  if (!yes) return;
  await api("POST", "/api/panic");
  // The panic ended this session as well.
  keepSession(null);
  nav.toLogin();
}

export function OverviewPage() {
  const { o, status, pair } = useNode();
  const windows = onWindows(o);
  const [sel, setSel] = useState<string | null>(null);
  const [open, setOpen] = useState(false);
  const up = o.centers.filter((c) => c.status === "connected").length;
  const c = o.centers.find((x) => x.name === sel) || o.centers[0];
  const lock = o.locked ? (
    <Btn
      kind="primary"
      size=""
      icon="unlock"
      act={async () => {
        await api("POST", "/api/unlock");
        toast("The node works again.");
        await status.reload();
      }}
    >
      Unlock
    </Btn>
  ) : (
    <Btn kind="danger" size="" icon="alert" act={panic}>
      Panic
    </Btn>
  );
  return (
    <>
      <PageHead icon="overview" title="Overview" sub={o.owner ? `This machine. Owner: ${o.owner}` : "This machine. No owner"}>
        <Btn kind="ghost" size="" icon="refresh" act={status.reload}>
          Refresh
        </Btn>
      </PageHead>
      <div className="ovtop">
        <div className={"card status " + (o.locked ? "warn" : "")}>
          <span className="big">
            <Icon name={o.locked ? "lock" : "activity"} />
          </span>
          <div className="grow">
            <h2>{o.locked ? "Locked" : "Running"}</h2>
            <p>{o.locked ? "Every link is closed and nothing runs until you unlock it." : "Each call of a center is checked against your rules."}</p>
            {o.confinement ? (
              <span className="meta row">
                <Icon name="shield" />
                Confinement: {o.confinement}
              </span>
            ) : null}
          </div>
          {lock}
        </div>
        <div className="card pad stack tight">
          <div className="row">
            <Tile icon="server" tone="ok" />
            <div className="grow">
              <b>Service</b>
              <div className="meta">
                {windows ? "Starting, stopping and restarting the node is done in the Nerve app, on its Overview." : "Starting, stopping and restarting the node is done at the CLI, without sudo."}
              </div>
            </div>
          </div>
          {windows ? null : <CopyRow value="nerve-node service restart" />}
        </div>
      </div>
      <div className="banners">
        {o.locked ? (
          <Banner tone="warn" icon="lock">
            The node is locked: every link is closed and nothing runs until you unlock it.
          </Banner>
        ) : null}
        {o.owner_full_rights ? (
          windows ? (
            <Banner tone="warn">
              The owner is an administrator: user-mode commands can take its administrator rights here.
              <More>
                <p className="meta">
                  Commands of user mode, and of allowlist mode as the owner, run as that account and can take its administrator rights (UAC is no security boundary). They can do everything on this machine, Nerve and its keys included.
                </p>
              </More>
            </Banner>
          ) : (
            <Banner tone="warn">
              Root is the owner: user-mode commands run as root, with every right here.
              <More>
                <p className="meta">Commands of user mode, and of allowlist mode as the owner, run as root and can do everything on this machine, Nerve and its keys included.</p>
              </More>
            </Banner>
          )
        ) : null}
        {o.pairings_warning ? <Banner tone="warn">{o.pairings_warning}</Banner> : null}
      </div>
      <div className="card strip">
        <span className="fact">
          <Icon name="centers" />
          Centers{" "}
          <b>
            {o.centers.length} paired · {up} connected
          </b>
        </span>
        <span className="fact">
          <Icon name="terminal" />
          Commands <b>{plural(o.running, "running", "running")}</b>
        </span>
        <span className="fact">
          <Icon name="key" />
          Sudo <b>{o.sudo === "on" ? "On" : "Off"}</b>
        </span>
      </div>
      {c ? (
        <Split
          variant="side3"
          open={open}
          onBack={() => setOpen(false)}
          list={
            <ListCard>
              <CenterRows
                centers={o.centers}
                sel={c.name}
                pick={(n) => {
                  setSel(n);
                  setOpen(true);
                }}
              />
            </ListCard>
          }
          detail={<CenterDetail key={c.name} c={c} />}
          third={<PairHint pair={pair} />}
        />
      ) : (
        <div className="card">
          <Empty icon="centers">No center is paired yet.</Empty>
          <div className="ffoot pad">
            <Btn kind="primary" size="" icon="plus" onClick={pair}>
              Pair a center
            </Btn>
          </div>
        </div>
      )}
    </>
  );
}

function PairHint({ pair }: { pair: () => void }) {
  return (
    <section className="card clip">
      <div className="sechead">
        <Icon name="link" size="lg" />
        <div>
          <h2>Pair a center</h2>
          <p>Paste a center's pairing link.</p>
        </div>
      </div>
      <div className="secbody">
        <div className="acts-row">
          <Btn kind="primary" size="" icon="plus" onClick={pair}>
            Pair a center
          </Btn>
        </div>
      </div>
    </section>
  );
}
