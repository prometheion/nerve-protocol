// Nodes: the paired machines as a list and the picked one's details, and
// Pair a machine, an overlay with the command and the link to paste.
import { useEffect, useRef, useState, type ReactNode } from "react";
import { api } from "../api";
import { ago, plural, when } from "../format";
import {
  Banner,
  Btn,
  CopyRow,
  DSec,
  Detail,
  Dot,
  Empty,
  Icon,
  LGroup,
  LRow,
  ListCard,
  Loading,
  Overlay,
  PageHead,
  Pill,
  RemoveAsk,
  Split,
  ask,
  failed,
  toast,
} from "../ui";
import { useCenter } from "./App";
import { PAIR_COMMAND, folderStep, nodeState } from "./lines";
import type { Node, PairedNode, Pairing } from "./types";

/** The machines as list rows, `id` picked. */
export function NodeRows({ nodes, id, pick }: { nodes: Node[]; id: string | null; pick: (id: string) => void }) {
  const online = nodes.filter((n) => n.online).length;
  return (
    <>
      <LGroup title="Nodes" count={`${online} of ${nodes.length} online`} />
      {nodes.map((n) => {
        const s = nodeState(n);
        return (
          <LRow key={n.id} className="two" current={n.id === id} onPick={() => pick(n.id)}>
            <Dot tone={s.tone} />
            <div className="grow">
              <b className="cut">{n.name}</b>
              <span className="faint">
                {n.platform}/{n.arch}
              </span>
            </div>
            <span className="side-text">{s.word}</span>
          </LRow>
        );
      })}
    </>
  );
}

/** A machine's details: its state, what it offers, what the center left
 * out, and Rename, Disable or Enable, Remove. */
export function NodeDetail({ n, reload }: { n: Node; reload: () => Promise<unknown> }) {
  const s = nodeState(n);
  const caps = n.capabilities || [];
  // Actions the center left out: a bad name, or a schema it cannot check
  // arguments with. The owner learns why here; the agent never sees them.
  const broken = n.broken || [];
  const rename = async () => {
    const name = await ask({
      title: `Rename ${n.name}`,
      confirm: "Rename",
      field: { label: "New name (a-z, 0-9 and -, not starting or ending with -)", value: n.name, pattern: "[a-z0-9]([a-z0-9\\-]*[a-z0-9])?" },
    });
    if (typeof name === "string" && name !== n.name) {
      await api("POST", "/api/nodes/rename", { id: n.id, name });
      await reload();
    }
  };
  return (
    <Detail
      icon="server"
      tile={n.disabled ? "warn" : n.online ? "ok" : "neutral"}
      title={n.name}
      pills={<Pill tone={s.tone} dot>{s.word}</Pill>}
      actions={
        <>
          <Btn icon="edit" size="" act={rename}>
            Rename
          </Btn>
          <Btn
            icon={n.disabled ? "ok" : "ban"}
            size=""
            act={async () => {
              await api("POST", "/api/nodes/disable", { id: n.id, disabled: !n.disabled });
              await reload();
            }}
          >
            {n.disabled ? "Enable" : "Disable"}
          </Btn>
          <RemoveAsk
            size=""
            question={`Remove ${n.name}? It has to be paired again to come back.`}
            onConfirm={async () => {
              await api("POST", "/api/nodes/remove", { id: n.id });
              await reload();
            }}
          />
        </>
      }
    >
      {n.summary ? <p className="lead">{n.summary}</p> : null}
      {n.disabled ? (
        <p className="meta">
          Hidden from the agent: it is offered none of this machine's capabilities, and calls to it are refused.
        </p>
      ) : null}
      <DSec>
        <div className="kv">
          <span className="k">Platform</span>
          <span>
            {n.platform}/{n.arch}
          </span>
          <span />
          <span className="k">Link</span>
          <span title={when(n.online ? n.since_ms : n.last_seen_ms)}>{n.online ? `Since ${ago(n.since_ms)}` : `Last seen ${ago(n.last_seen_ms)}`}</span>
          <span />
          {n.folders !== undefined ? (
            <>
              <span className="k">Folders</span>
              <span>{n.folders === null ? "every one (user mode)" : n.folders}</span>
              <span />
            </>
          ) : null}
          {n.going_away ? (
            <>
              <span className="k">Going away</span>
              <span>{n.going_away}</span>
              <span />
            </>
          ) : null}
        </div>
      </DSec>
      <DSec title="What it offers">
        {caps.length ? (
          <div className="chips">
            {caps.map((c) => (
              <Pill key={c.id} tone="line" title={`${c.summary || c.id} (${c.exposure})`}>
                {c.exposure === "off" ? <s>{c.id}</s> : c.id}
              </Pill>
            ))}
          </div>
        ) : (
          <p className="meta">Offers nothing yet.</p>
        )}
      </DSec>
      {broken.length ? (
        <DSec title="Not offered to the agent">
          {broken.map((b) => (
            <p key={b.name} className="meta">
              <code className="mono">{b.name}</code> {b.reason}
            </p>
          ))}
        </DSec>
      ) : null}
    </Detail>
  );
}

/** The card that follows a pairing: the machine is paired, and its next
 * step. */
export function PairedBanner() {
  const { paired, setPaired } = useCenter();
  if (!paired) return null;
  const step = folderStep(paired);
  return (
    <div className="banners">
      <Banner tone="ok" icon="ok">
        <div className="row">
          <b className="grow">{paired.name} is paired</b>
          <Btn kind="ghost" icon="x" label="Dismiss" title="Dismiss" onClick={() => setPaired(null)} />
        </div>
        {step.copy ? (
          <div className="stack tight">
            <span className="meta">Next: give it a folder, on that machine:</span>
            <CopyRow value={step.copy} />
          </div>
        ) : (
          <span className="meta">Next: give it a folder, {step.text}.</span>
        )}
      </Banner>
    </div>
  );
}

/** Pair a machine: a code for one machine, the command and the bare link,
 * each with Copy. The link holds the center, the code and the pin, so they
 * are not shown apart. Once the center no longer has the code open, a
 * machine used it (or it ran out of tries): the overlay closes, and the
 * center says which machine it paired. */
export function PairOverlay({ onClose, onPaired }: { onClose: () => void; onPaired: (n: PairedNode) => void }) {
  const [p, setP] = useState<Pairing | null>(null);
  const asked = useRef(false);
  const make = async () => setP(await api<Pairing>("POST", "/api/pair"));
  useEffect(() => {
    if (asked.current) return;
    asked.current = true;
    make().catch((e) => {
      failed(e);
      onClose();
    });
  }, [onClose]);
  useEffect(() => {
    if (!p) return;
    const t = setInterval(async () => {
      try {
        const s = await api<{ open: boolean; node?: PairedNode }>("POST", "/api/pair/status", { code: p.code });
        if (s.open) return;
        clearInterval(t);
        if (s.node) {
          toast(`Paired ${s.node.name}.`);
          onPaired(s.node);
        } else {
          toast("The pairing code is no longer valid.", "error");
          onClose();
        }
      } catch {
        /* the overview's poll says when the center cannot be reached */
      }
    }, 2000);
    return () => clearInterval(t);
  }, [p, onClose, onPaired]);
  return (
    <OverlayFrame
      onClose={onClose}
      foot={
        <>
          <Btn kind="ghost" size="" icon="refresh" act={make}>
            New code
          </Btn>
          <span className="sp" />
          <Btn kind="primary" size="" onClick={onClose}>
            Done
          </Btn>
        </>
      }
    >
      {!p ? (
        <Loading />
      ) : (
        <>
          <CopyRow label="Command" value={PAIR_COMMAND} />
          <CopyRow label="Link" value={p.link} />
          <p className="faint row">
            <Icon name="wait" />
            The code works for one machine until {when(p.expires_ms)}.
          </p>
          {/* On a machine with other centers the command needs the one
              it is for (#213, L2-11). */}
          <span className="meta">Then give it a folder on that machine, with --center &lt;name&gt; where it has other centers:</span>
          <CopyRow label="Folder" value={folderStep(null).copy!} />
          {p.pin ? null : <p className="faint">Plain HTTP on loopback, no certificate pin.</p>}
        </>
      )}
    </OverlayFrame>
  );
}

function OverlayFrame({ onClose, foot, children }: { onClose: () => void; foot: ReactNode; children: ReactNode }) {
  return (
    <Overlay
      title="Pair a machine"
      sub="On a Linux machine, run the command, then paste the link on the next line, or paste it in the Nerve app. On a Windows machine, open the link on the machine: the Nerve app pairs with it."
      onClose={onClose}
      foot={foot}
    >
      {children}
    </Overlay>
  );
}


export function NodesPage() {
  const { ov, overview, pair } = useCenter();
  const [id, setId] = useState<string | null>(null);
  const [open, setOpen] = useState(false);
  const nodes = ov.nodes;
  const n = nodes.find((x) => x.id === id) || nodes[0];
  return (
    <>
      <PageHead icon="server" title="Nodes" sub={plural(nodes.length, "machine")}>
        <Btn kind="ghost" size="" icon="refresh" act={overview.reload}>
          Refresh
        </Btn>
        <Btn kind="primary" size="" icon="plus" onClick={pair}>
          Pair a machine
        </Btn>
      </PageHead>
      <PairedBanner />
      {nodes.length ? (
        <Split
          open={open}
          onBack={() => setOpen(false)}
          list={
            <ListCard>
              <NodeRows
                nodes={nodes}
                id={n?.id ?? null}
                pick={(x) => {
                  setId(x);
                  setOpen(true);
                }}
              />
            </ListCard>
          }
          detail={n ? <NodeDetail key={n.id} n={n} reload={overview.reload} /> : null}
        />
      ) : (
        <div className="card">
          <Empty icon="server">No machines yet. Pair one to get started.</Empty>
        </div>
      )}
    </>
  );
}
