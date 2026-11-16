// Centers: the centers this machine is paired with as a list, the picked
// one's details (its state, mode and settings grant, pause, a new key,
// unpair), and Pair a center, an overlay that takes the link a center shows.
import { useState } from "react";
import { api } from "../api";
import { when } from "../format";
import { Banner, Btn, DSec, Detail, Dot, Empty, Field, LGroup, LRow, ListCard, More, Overlay, PageHead, Pill, RemoveAsk, Split, Switch, TextInput, ask, toast, type Tone } from "../ui";
import { useNode } from "./App";
import type { CenterEntry, Json } from "./types";

export function centerTone(c: CenterEntry): Tone {
  if (c.revoked || c.unknown) return "warn";
  if (c.paused) return "";
  return c.status === "connected" ? "ok" : c.status.startsWith("cannot") || c.status.includes("refused") ? "danger" : "";
}

export function centerWord(c: CenterEntry): string {
  return c.paused ? "paused" : c.status;
}

const MODES: Record<string, string> = {
  allowlist: "Allowlist mode",
  folder: "Folder mode",
  user: "User mode",
};

export function CenterRows({ centers, sel, pick }: { centers: CenterEntry[]; sel: string | null; pick: (n: string) => void }) {
  return (
    <>
      <LGroup title="Centers" count={centers.length} />
      {centers.map((c) => (
        <LRow key={c.name} className="two" current={c.name === sel} onPick={() => pick(c.name)}>
          <Dot tone={centerTone(c)} />
          <div className="grow">
            <b className="cut">{c.name}</b>
            <span className="faint">
              {centerWord(c)} · {MODES[c.mode] || c.mode}
            </span>
          </div>
        </LRow>
      ))}
    </>
  );
}

/** A center's details: its state and address, its mode, its settings grant,
 * and Pause or Resume, New key, Unpair. */
export function CenterDetail({ c }: { c: CenterEntry }) {
  const { status, setCenter } = useNode();
  const grant = c.settings === "write";
  const run = (path: string) => async () => {
    await api("POST", path, { center: c.name });
    await status.reload();
  };
  return (
    <Detail
      title={c.name}
      pills={
        <Pill tone={centerTone(c)} dot>
          {centerWord(c)}
        </Pill>
      }
      actions={
        <>
          <Btn size="" icon={c.paused ? "play" : "pause"} act={run(c.paused ? "/api/centers/resume" : "/api/centers/pause")}>
            {c.paused ? "Resume" : "Pause"}
          </Btn>
          <Btn
            kind="ghost"
            size=""
            icon="key"
            act={async () => {
              const yes = await ask({ title: `A new key for ${c.name}?`, message: "This machine makes a new key for the center and tells it; the old one stops working.", confirm: "Make a new key" });
              if (!yes) return;
              await api("POST", "/api/centers/rotate", { center: c.name });
              toast("This machine has a new key for the center.");
            }}
          >
            New key…
          </Btn>
          <RemoveAsk
            size=""
            label="Unpair"
            icon="unlink"
            question={`Unpair ${c.name}? The node forgets it and deletes its key; it has to be paired again to come back.`}
            onConfirm={run("/api/centers/remove")}
          />
        </>
      }
    >
      <p className="mono faint wrap">{c.url}</p>
      {c.revoked ? <Banner tone="warn">The center revoked this machine.</Banner> : null}
      <DSec>
        <div className="kv">
          <span className="k">Mode</span>
          <div>
            <b>{MODES[c.mode] || c.mode}</b>
            {c.until ? <div className="faint">Until {when(c.until)}{c.then ? `, then ${c.then}` : ""}.</div> : null}
          </div>
          <a className="btn sm" href="#permissions" onClick={() => setCenter(c.name)}>
            Change
          </a>
          <span className="k">Settings grant</span>
          <div>
            <b>{grant ? "May change settings" : "Cannot change settings"}</b>
            <div className="faint">{grant ? "It may change its own rights here, up to user mode and sudo." : "Only you change what it may do."}</div>
          </div>
          <Switch
            label="Settings grant"
            checked={grant}
            onChange={async (on) => {
              if (on) {
                const yes = await ask({ title: `Let ${c.name} change its rights?`, message: "It may then set everything this machine lets it do, up to user mode and sudo.", confirm: "Grant", danger: true });
                if (!yes) return;
              }
              await api("POST", "/api/centers/settings", { center: c.name, state: on ? "on" : "off" });
              await status.reload();
            }}
          />
        </div>
      </DSec>
      <DSec title="What it may do here">
        <div className="acts-row">
          <a className="btn ghost sm" href="#permissions" onClick={() => setCenter(c.name)}>
            Permissions
          </a>
          <a className="btn ghost sm" href="#capabilities" onClick={() => setCenter(c.name)}>
            Capabilities
          </a>
        </div>
      </DSec>
    </Detail>
  );
}

/** Pair a center: the link its web UI or app shows under Pair a machine.
 * It goes to the node as the command's input, never in a command line;
 * Check shows what the link names before it pairs. */
export function PairCenter({ onClose }: { onClose: () => void }) {
  const { status } = useNode();
  const [link, setLink] = useState("");
  const [name, setName] = useState("");
  const [preview, setPreview] = useState<Json>(null);
  return (
    <Overlay
      title="Pair a center"
      sub="Paste the link the center shows under Pair a machine."
      onClose={onClose}
      foot={
        <>
          <Btn kind="ghost" size="" onClick={onClose}>
            Cancel
          </Btn>
          <Btn kind="ghost" size="" icon="check" act={async () => setPreview(await api("POST", "/api/centers/preview", { link }))}>
            Check
          </Btn>
          <Btn
            kind="primary"
            size=""
            icon="link"
            act={async () => {
              const r = await api("POST", "/api/centers/pair", { link, name });
              toast(`Paired with ${r.url || "the center"} as ${r.name || name}.`);
              await status.reload();
              onClose();
            }}
          >
            Pair
          </Btn>
        </>
      }
    >
      <Field label="Pairing link">
        <TextInput value={link} onChange={setLink} placeholder="nerve://pair?…" mono />
      </Field>
      <Field label="Name here (optional)">
        <TextInput value={name} onChange={setName} placeholder="home" />
      </Field>
      {preview && preview.preview ? (
        <Banner tone={preview.check && preview.check.ready ? "ok" : "warn"} icon="info">
          {preview.preview.center}
          {preview.preview.tls ? "" : " (plain HTTP on loopback)"}: {preview.check ? preview.check.said || "" : ""}
        </Banner>
      ) : null}
      <More>
        <p className="meta">The link goes to the node as the command's input, never in a command line.</p>
      </More>
    </Overlay>
  );
}

export function CentersPage() {
  const { o, status, pair } = useNode();
  const [sel, setSel] = useState<string | null>(null);
  const [open, setOpen] = useState(false);
  const c = o.centers.find((x) => x.name === sel) || o.centers[0];
  return (
    <>
      <PageHead icon="centers" title="Centers" sub="Pair this machine with a center, and decide what each one may change.">
        <Btn kind="ghost" size="" icon="refresh" act={status.reload}>
          Refresh
        </Btn>
        <Btn kind="primary" size="" icon="plus" onClick={pair}>
          Pair a center
        </Btn>
      </PageHead>
      {o.pairings_warning ? (
        <div className="banners">
          <Banner tone="warn">{o.pairings_warning}</Banner>
        </div>
      ) : null}
      {c ? (
        <Split
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
        />
      ) : (
        <div className="card">
          <Empty icon="centers">No center is paired yet.</Empty>
        </div>
      )}
    </>
  );
}
