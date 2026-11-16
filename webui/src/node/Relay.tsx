// Relay: reach the centers through another node (or a proxy), or let other
// nodes reach this node's centers through this one. The list holds this
// node's way out, this machine as a relay, and the nodes that use it; the
// details the picked one, or a new node's form.
import { useState } from "react";
import { api } from "../api";
import { usePoll } from "../frame";
import { AddRow, Banner, Btn, DSec, Detail, Field, FormCard, Icon, LGroup, LRow, ListCard, Loading, PageHead, Pill, RemoveAsk, SecretInput, Split, TextInput, copy } from "../ui";
import type { Json } from "./types";

type Relay = { relay: Json; proxy: Json };

function ShownLink({ shown, hide }: { shown: { node: string; link: string }; hide: () => void }) {
  return (
    <Banner tone="ok" icon="key">
      <div className="row">
        <span className="grow">
          The link for {shown.node}, shown once: <code className="mono wrap">{shown.link}</code>
        </span>
        <Btn kind="ghost" icon="copy" onClick={() => copy(shown.link)}>
          Copy
        </Btn>
        <Btn kind="ghost" icon="x" label="Hide" title="Hide" onClick={hide} />
      </div>
    </Banner>
  );
}

function Through({ p, reload }: { p: Json; reload: () => Promise<unknown> }) {
  const [url, setUrl] = useState("");
  const [pw, setPw] = useState("");
  return (
    <Detail icon="link" title="Through a relay" pills={p.proxy ? <Pill tone="ok">On</Pill> : null}>
      <p className="lead">{p.proxy ? `Now through ${p.proxy}.` : "This node reaches its centers directly."}</p>
      {p.problem ? <Banner tone="warn">{p.problem}</Banner> : null}
      <DSec>
        <p className="meta">For a machine that reaches no center itself: the link a relay shows under Add a node, or a proxy's URL.</p>
        <Field label="Relay or proxy">
          <TextInput value={url} onChange={setUrl} mono placeholder="https://lab-pc@relay.example:7490" />
        </Field>
        <Field label="Its token or password">
          <SecretInput value={pw} onChange={setPw} />
        </Field>
        <div className="acts-row">
          <Btn
            kind="primary"
            icon="link"
            act={async () => {
              await api("POST", "/api/proxy/set", { url, password: pw });
              setPw("");
              await reload();
            }}
          >
            Connect
          </Btn>
          {p.proxy ? (
            <Btn
              kind="danger"
              icon="x"
              act={async () => {
                await api("POST", "/api/proxy/remove");
                await reload();
              }}
            >
              Disconnect
            </Btn>
          ) : null}
        </div>
      </DSec>
    </Detail>
  );
}

function AsRelay({ r, reload }: { r: Json; reload: () => Promise<unknown> }) {
  const [address, setAddress] = useState<string>(r.listen || "");
  return (
    <Detail icon="server" title="This machine as a relay" pills={r.listen ? <Pill tone="ok">On</Pill> : <Pill>Off</Pill>}>
      <p className="lead">Nodes that reach no center themselves reach this node's centers through it.</p>
      <DSec>
        <div className="kv">
          <span className="k">Listens on</span>
          <span className="mono">{r.listen || "off"}</span>
          <span />
          {r.status ? (
            <>
              <span className="k">State</span>
              <span>{typeof r.status === "string" ? r.status : JSON.stringify(r.status)}</span>
              <span />
            </>
          ) : null}
        </div>
      </DSec>
      <DSec>
        <Field label="Listen on">
          <TextInput value={address} onChange={setAddress} mono placeholder="0.0.0.0:7490" />
        </Field>
        <div className="acts-row">
          <Btn
            kind="primary"
            icon="check"
            act={async () => {
              await api("POST", "/api/relay/set", { address });
              await reload();
            }}
          >
            {r.listen ? "Change" : "Turn on"}
          </Btn>
          {r.listen ? (
            <Btn
              kind="danger"
              icon="x"
              act={async () => {
                await api("POST", "/api/relay/off");
                await reload();
              }}
            >
              Turn off
            </Btn>
          ) : null}
        </div>
      </DSec>
    </Detail>
  );
}

export function RelayPage() {
  const relay = usePoll(() => api<Relay>("GET", "/api/relay"), [], 0);
  const [sel, setSel] = useState("through");
  const [open, setOpen] = useState(false);
  const [shown, setShown] = useState<{ node: string; link: string } | null>(null);
  const [name, setName] = useState("");
  const v = relay.data;
  const pick = (x: string) => {
    setSel(x);
    setOpen(true);
  };
  if (!v) {
    return (
      <>
        <PageHead icon="route" title="Relay" />
        {relay.error ? <Banner tone="danger">{relay.error.message}</Banner> : <Loading />}
      </>
    );
  }
  const r = v.relay;
  const p = v.proxy;
  const nodes: Json[] = r.nodes || [];
  const n = nodes.find((x) => `n:${x.name}` === sel);
  let detail;
  if (sel === "relay") detail = <AsRelay key={r.listen || ""} r={r} reload={relay.reload} />;
  else if (sel === "new") {
    detail = (
      <FormCard
        icon="server"
        title="Add a node"
        sub="A node that reaches no center itself. It gets a link to paste on its machine."
        save="Make the link"
        onCancel={() => setSel("relay")}
        onSave={async () => {
          const t = await api("POST", "/api/relay/add", { name });
          setShown(t.token);
          setName("");
          await relay.reload();
          setSel(`n:${t.token?.node || name}`);
        }}
      >
        <Field label="Its name">
          <TextInput value={name} onChange={setName} placeholder="lab-pc" />
        </Field>
      </FormCard>
    );
  } else if (n) {
    detail = (
      <Detail
        icon="server"
        mono
        title={n.name}
        actions={
          <>
            <Btn
              kind="ghost"
              size=""
              icon="refresh"
              act={async () => {
                const t = await api("POST", "/api/relay/token", { name: n.name });
                setShown(t.token);
                await relay.reload();
              }}
            >
              New link
            </Btn>
            <RemoveAsk
              size=""
              question={`Remove ${n.name}? Its link stops working.`}
              onConfirm={async () => {
                await api("POST", "/api/relay/remove", { name: n.name });
                setSel("relay");
                await relay.reload();
              }}
            />
          </>
        }
      >
        <p className="lead">May reach {n.centers && n.centers.length ? n.centers.join(", ") : "every https center of this node"}.</p>
      </Detail>
    );
  } else detail = <Through p={p} reload={relay.reload} />;
  return (
    <>
      <PageHead icon="route" title="Relay" sub="Reach centers through another node, or let other nodes reach this node's centers through this one.">
        <Btn kind="ghost" size="" icon="refresh" act={relay.reload}>
          Refresh
        </Btn>
      </PageHead>
      {shown ? (
        <div className="banners">
          <ShownLink shown={shown} hide={() => setShown(null)} />
        </div>
      ) : null}
      <Split
        open={open}
        onBack={() => setOpen(false)}
        list={
          <ListCard>
            <LGroup title="This node" />
            <LRow current={sel === "through"} onPick={() => pick("through")}>
              <Icon name="link" />
              <span className="grow">{p.proxy ? "Through a relay" : "Direct"}</span>
              <span className="side-text cut">{p.proxy ? p.proxy : "no relay"}</span>
            </LRow>
            <LGroup title="This machine as a relay" />
            <LRow current={sel === "relay"} onPick={() => pick("relay")}>
              <Icon name="server" />
              <span className="grow">Relay</span>
              {r.listen ? <Pill tone="ok">On</Pill> : <span className="side-text">off</span>}
            </LRow>
            <LGroup title="Nodes that use it" count={nodes.length} />
            {nodes.map((x) => (
              <LRow key={x.name} current={sel === `n:${x.name}`} onPick={() => pick(`n:${x.name}`)}>
                <Icon name="server" />
                <span className="mono grow cut">{x.name}</span>
                <span className="side-text">{x.centers && x.centers.length ? x.centers.join(", ") : "every https center"}</span>
              </LRow>
            ))}
            <AddRow label="Add a node…" current={sel === "new"} onPick={() => pick("new")} />
          </ListCard>
        }
        detail={detail}
      />
    </>
  );
}
