// Statistics: all machines together and each machine as a list; the
// details show the picked one's numbers, its calls and its errors.
import { useState } from "react";
import { api } from "../api";
import { usePoll } from "../frame";
import { duration, plural } from "../format";
import { Btn, DSec, Detail, Empty, Icon, LGroup, LRow, ListCard, Loading, PageHead, Split } from "../ui";
import { useCenter } from "./App";
import type { Json } from "./types";

type Day = { online_ms?: number; links?: number; drops?: number; calls?: Record<string, { count: number; errors: number; total_ms: number; max_ms: number }>; errors?: Record<string, number> };
type Stats = { retention_days: number; total: Day; nodes: Record<string, Day> };

const callsOf = (d: Day) => Object.values(d.calls || {}).reduce((n, c) => n + c.count, 0);

function DayDetail({ title, d, days }: { title: string; d: Day; days: number }) {
  const calls = Object.entries(d.calls || {}).sort((a, b) => b[1].count - a[1].count);
  const errors = Object.entries(d.errors || {}).sort((a, b) => b[1] - a[1]);
  const total = calls.reduce((n, [, c]) => n + c.count, 0);
  const failed = calls.reduce((n, [, c]) => n + c.errors, 0);
  const metrics: [string, string | number][] = [
    ["Online", duration(d.online_ms || 0)],
    ["Links", d.links || 0],
    ["Drops", d.drops || 0],
    ["Calls", total],
    ["Failed calls", failed],
  ];
  return (
    <Detail title={title} actions={<span className="faint">Kept for {plural(days, "day")}.</span>}>
      <DSec>
        <div className="metrics">
          {metrics.map(([l, v]) => (
            <div key={l} className="metric">
              <span>{l}</span>
              <b>{v.toLocaleString()}</b>
            </div>
          ))}
        </div>
      </DSec>
      <DSec title="Calls">
        {calls.length ? (
          <div className="card rows clip">
            {calls.map(([k, c]) => (
              <div key={k} className="r">
                <span className="mono grow">{k}</span>
                <span>
                  {c.count}
                  {c.errors ? `, ${c.errors} failed` : ""}
                </span>
                <span className="faint">
                  avg {c.count ? Math.round(c.total_ms / c.count) : 0} ms, max {c.max_ms} ms
                </span>
              </div>
            ))}
          </div>
        ) : (
          <p className="meta">No calls.</p>
        )}
      </DSec>
      {errors.length ? (
        <DSec title="Errors">
          <div className="card rows clip">
            {errors.map(([k, n]) => (
              <div key={k} className="r">
                <span className="grow mono">{k}</span>
                <b>{n}</b>
              </div>
            ))}
          </div>
        </DSec>
      ) : null}
    </Detail>
  );
}

export function StatsPage() {
  const { ov } = useCenter();
  const stats = usePoll(() => api<Stats>("GET", "/api/stats"), []);
  const [one, setOne] = useState<string | null>(null);
  const [open, setOpen] = useState(false);
  const s = stats.data;
  if (!s) {
    return (
      <>
        <PageHead icon="gauge" title="Statistics" />
        <Loading />
      </>
    );
  }
  // The paired machines, and those only the numbers still remember.
  const names = [...new Set([...ov.nodes.map((n) => n.name), ...Object.keys(s.nodes)])].sort((a, b) => a.localeCompare(b));
  // A machine that was removed or renamed has no numbers under that name.
  const pick = one !== null && names.includes(one) ? one : null;
  const day: Json = (pick === null ? s.total : s.nodes[pick]) || {};
  const go = (v: string | null) => {
    setOne(v);
    setOpen(true);
  };
  return (
    <>
      <PageHead icon="gauge" title="Statistics" sub={`Kept for ${plural(s.retention_days, "day")}.`}>
        <Btn kind="ghost" size="" icon="refresh" act={stats.reload}>
          Refresh
        </Btn>
      </PageHead>
      {names.length ? (
        <Split
          open={open}
          onBack={() => setOpen(false)}
          list={
            <ListCard>
              <div className="lead-space" />
              <LRow current={pick === null} onPick={() => go(null)}>
                <Icon name="overview" />
                <span className="grow">All machines</span>
                <span className="side-text">{callsOf(s.total).toLocaleString()} calls</span>
              </LRow>
              <LGroup title="Machines" count={names.length} />
              {names.map((m) => (
                <LRow key={m} current={pick === m} onPick={() => go(m)}>
                  <Icon name="server" />
                  <span className="grow cut">{m}</span>
                  <span className="side-text">{callsOf(s.nodes[m] || {}).toLocaleString()} calls</span>
                </LRow>
              ))}
            </ListCard>
          }
          detail={<DayDetail title={pick === null ? "All machines" : pick} d={day} days={s.retention_days} />}
        />
      ) : (
        <div className="card">
          <Empty icon="server">No machines yet.</Empty>
        </div>
      )}
    </>
  );
}
