// Harnesses: Connect a harness at the top of the list, then a switch
// between the harness tokens and the sessions; the details show the picked
// one, a new token's form, or how to connect.
import { useState } from "react";
import { api } from "../api";
import { usePoll } from "../frame";
import { ago, plural, when } from "../format";
import {
  AddRow,
  Banner,
  Btn,
  CopyRow,
  DSec,
  Detail,
  Dot,
  Empty,
  Field,
  FormCard,
  Icon,
  LRow,
  ListCard,
  Loading,
  PageHead,
  Pill,
  RemoveAsk,
  Seg,
  Split,
  TextInput,
  copy,
} from "../ui";
import { useCenter } from "./App";
import { centerOnWindows } from "./lines";
import type { Mcp, Overview, Session } from "./types";

type Token = { id: string; label: string; created_ms?: number; settings?: boolean };

/** Connect a harness: how this center serves MCP, and for HTTP a token made
 * here with what to paste (the JSON first, which keeps the token out of the
 * shell's history). The token is shown once. */
export function HarnessCard({ o, token, setToken }: { o: Overview; token: string | null; setToken: (t: string | null) => void }) {
  const m: Mcp = o.mcp || { mode: "stdio" };
  const head = (sub: string) => (
    <>
      <div className="dhead">
        <Icon name="plug" size="lg" />
        <h2>Connect a harness</h2>
      </div>
      <p className="lead meta">{sub}</p>
    </>
  );
  if (m.mode === "off") {
    return <section className="card detail">{head("This center serves no MCP (--mcp off): harnesses attach to another center on its state folder.")}</section>;
  }
  if (m.mode === "stdio") {
    const entry = JSON.stringify({ mcpServers: { nerve: { command: "nerve-center" } } });
    return (
      <section className="card detail">
        {head("A harness starts this center itself: put this entry in its MCP settings.")}
        <DSec>
          <CopyRow label="JSON" value={entry} />
          <p className="meta">
            {centerOnWindows(o)
              ? "It runs as you: an agent with shell tools can read its owner token. `nerve-center install` in an administrator's terminal keeps it out."
              : "It runs as you: an agent with shell tools can read its owner token. `sudo nerve-center install` keeps it out."}
          </p>
        </DSec>
      </section>
    );
  }
  const header = `Authorization: Bearer ${token}`;
  return (
    <section className="card detail">
      {head(`Harnesses reach this center at ${m.url} with a harness token. It opens /mcp only, not this page.`)}
      <DSec>
        {!token ? (
          <div className="acts-row">
            <Btn
              kind="primary"
              size=""
              icon="key"
              act={async () => {
                const r = await api<{ token: string }>("POST", "/api/tokens/create", { label: "harness" });
                setToken(r.token);
              }}
            >
              Make a token
            </Btn>
          </div>
        ) : (
          <>
            <Banner tone="warn" icon="eye">
              Shown only now. Paste the JSON into the harness's settings; the Claude Code line puts the token in your shell's history.
            </Banner>
            <CopyRow label="JSON" value={JSON.stringify({ mcpServers: { nerve: { type: "http", url: m.url, headers: { Authorization: `Bearer ${token}` } } } })} />
            <CopyRow label="URL" value={m.url || ""} />
            <CopyRow label="Header" value={header} />
            <CopyRow label="Claude Code" value={`claude mcp add --transport http nerve ${m.url} --header "${header}"`} />
            <div className="acts-row">
              <Btn kind="ghost" icon="x" onClick={() => setToken(null)}>
                Hide the token
              </Btn>
            </div>
          </>
        )}
        {m.fingerprint ? (
          <p className="meta">
            Beyond loopback the endpoint uses TLS with this center's own certificate: let the harness trust it by its pin,{" "}
            <code className="mono">{m.fingerprint}</code>.
          </p>
        ) : null}
      </DSec>
    </section>
  );
}

/** The sessions as rows with End, for a pane beside the machines. */
export function SessionRows({ sessions }: { sessions: Session[] }) {
  if (!sessions.length) return <p className="lnote">None now.</p>;
  return (
    <div className="rows">
      {sessions.map((s) => (
        <div key={s.id} className="r">
          <Dot tone="ok" />
          <div className="grow">
            <b>{s.client || "Unknown client"}</b>
            <div className="faint">
              {ago(s.started_ms)} · {plural(s.calls, "call")}
            </div>
          </div>
          <EndSession s={s} />
        </div>
      ))}
    </div>
  );
}

function EndSession({ s }: { s: Session }) {
  const { overview } = useCenter();
  return (
    <Btn
      kind="danger"
      icon="x"
      act={async () => {
        await api("POST", "/api/sessions/end", { id: s.id });
        await overview.reload();
      }}
    >
      End
    </Btn>
  );
}

function SessionDetail({ s }: { s: Session }) {
  return (
    <Detail
      icon="activity"
      tile="ok"
      title={s.client || "Unknown client"}
      pills={
        <>
          <Pill>{s.transport}</Pill>
          {/* The action checker marks a session tainted once a call of it
              returned content (issue #17). */}
          {s.tainted ? <Pill tone="warn">tainted</Pill> : null}
        </>
      }
      actions={<EndSession s={s} />}
    >
      <DSec>
        <div className="kv">
          <span className="k">Connected</span>
          <span title={when(s.started_ms)}>{ago(s.started_ms)}</span>
          <span />
          <span className="k">Calls</span>
          <span>{s.calls}</span>
          <span />
          <span className="k">Machines</span>
          <span className="chips">{s.nodes.length ? s.nodes.map((n) => <Pill key={n} tone="line">{n}</Pill>) : "none yet"}</span>
          <span />
          <span className="k">Session</span>
          <code className="mono wrap">{s.id}</code>
          <span />
        </div>
      </DSec>
    </Detail>
  );
}

function TokenDetail({ t, reload }: { t: Token; reload: () => Promise<unknown> }) {
  if (t.settings) {
    // The token of the settings (NERVE_CENTER_HARNESS_TOKEN or
    // --harness-token): only a change of the settings and a restart remove it.
    return (
      <Detail icon="key" title={<span className="mono">{t.label}</span>}>
        <p className="lead">From the center's settings; remove it there. It opens /mcp only, not this page.</p>
      </Detail>
    );
  }
  return (
    <Detail
      icon="key"
      title={t.label || "(no label)"}
      actions={
        <RemoveAsk
          size=""
          question={`Remove ${t.label || "this token"}? A harness that uses it stops.`}
          onConfirm={async () => {
            await api("POST", "/api/tokens/delete", { id: t.id });
            await reload();
          }}
        />
      }
    >
      <p className="lead">A harness token: it opens /mcp only, not this page.</p>
      <DSec>
        <div className="kv">
          <span className="k">Made</span>
          <span title={when(t.created_ms)}>{ago(t.created_ms)}</span>
          <span />
        </div>
      </DSec>
    </Detail>
  );
}

function NewToken({ done, cancel }: { done: (id: string, token: string) => void; cancel: () => void }) {
  const [label, setLabel] = useState("");
  return (
    <FormCard
      icon="key"
      title="Make a harness token"
      sub="A token lets an AI harness call this center over HTTP; it does not log in here."
      save="Make"
      onCancel={cancel}
      onSave={async () => {
        const r = await api<{ id: string; token: string }>("POST", "/api/tokens/create", { label });
        done(r.id, r.token);
      }}
    >
      <Field label="Label">
        <TextInput value={label} onChange={setLabel} maxLength={64} placeholder="for example the harness name" />
      </Field>
    </FormCard>
  );
}

export function HarnessesPage() {
  const { ov, overview } = useCenter();
  const tokens = usePoll(() => api<Token[]>("GET", "/api/tokens"), []);
  const [view, setView] = useState<"tokens" | "sessions">("tokens");
  const [sel, setSel] = useState("connect");
  const [open, setOpen] = useState(false);
  const [shown, setShown] = useState<string | null>(null);
  // The token just made, shown once in Connect a harness or under the list.
  const [made, setMade] = useState<string | null>(null);
  const pick = (id: string) => {
    setSel(id);
    setOpen(true);
  };
  const list = tokens.data || [];
  const tok = list.find((t) => `t:${t.id || "settings"}` === sel);
  const ses = ov.sessions.find((s) => `s:${s.id}` === sel);
  let detail;
  if (sel === "new") {
    detail = (
      <NewToken
        cancel={() => setSel("connect")}
        done={async (id, token) => {
          setMade(token);
          await tokens.reload();
          setSel(`t:${id}`);
        }}
      />
    );
  } else if (tok) {
    detail = <TokenDetail t={tok} reload={tokens.reload} />;
  } else if (ses) {
    detail = <SessionDetail s={ses} />;
  } else {
    detail = <HarnessCard o={ov} token={shown} setToken={(t) => { setShown(t); tokens.reload(); }} />;
  }
  return (
    <>
      <PageHead icon="terminal" title="Harnesses">
        <Btn
          kind="ghost"
          size=""
          icon="refresh"
          act={async () => {
            await Promise.all([overview.reload(), tokens.reload()]);
          }}
        >
          Refresh
        </Btn>
      </PageHead>
      {made ? (
        <div className="banners">
          <Banner tone="ok" icon="key">
            <div className="row">
              <span className="grow">
                New token, shown once: <code className="mono wrap">{made}</code>
              </span>
              <Btn kind="ghost" icon="copy" onClick={() => copy(made)}>
                Copy
              </Btn>
              <Btn kind="ghost" icon="x" label="Hide" title="Hide" onClick={() => setMade(null)} />
            </div>
          </Banner>
        </div>
      ) : null}
      <Split
        open={open}
        onBack={() => setOpen(false)}
        list={
          <ListCard>
            <LRow current={sel === "connect"} onPick={() => pick("connect")}>
              <Icon name="plus" />
              <b className="grow">Connect a harness</b>
            </LRow>
            <div className="lseg">
              <Seg
                label="Show"
                full
                value={view}
                onChange={(v) => setView(v)}
                options={[
                  { value: "tokens", label: "Tokens", count: list.length },
                  { value: "sessions", label: "Sessions", count: ov.sessions.length },
                ]}
              />
            </div>
            {view === "tokens" ? (
              <>
                {!tokens.data ? <Loading /> : null}
                {list.map((t) => (
                  <LRow key={t.id || "settings"} current={sel === `t:${t.id || "settings"}`} onPick={() => pick(`t:${t.id || "settings"}`)}>
                    <Icon name="key" />
                    <span className={"grow cut " + (t.settings ? "mono" : "")}>{t.label || "(no label)"}</span>
                    <span className="side-text">{t.settings ? "settings" : ago(t.created_ms)}</span>
                  </LRow>
                ))}
                {tokens.data && !list.length ? <p className="lnote top">No tokens yet.</p> : null}
                <AddRow label="Make a token…" current={sel === "new"} onPick={() => pick("new")} />
              </>
            ) : ov.sessions.length ? (
              ov.sessions.map((s) => (
                <LRow key={s.id} current={sel === `s:${s.id}`} onPick={() => pick(`s:${s.id}`)}>
                  <Dot tone="ok" />
                  <span className="grow cut">{s.client || "Unknown client"}</span>
                  <span className="side-text">{plural(s.calls, "call")}</span>
                </LRow>
              ))
            ) : (
              <Empty icon="activity">No harness is connected now.</Empty>
            )}
          </ListCard>
        }
        detail={detail}
      />
    </>
  );
}
