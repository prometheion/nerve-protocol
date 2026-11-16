// The frame of both web UIs: the sidebar with the pages, the state and the
// theme; the page shown by the address (#overview); the polls that keep a
// page current; and the start, which asks the server whether this tab is
// signed in before it draws anything.
import { StrictMode, useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { createRoot } from "react-dom/client";
import { ApiError, signOut, startSession } from "./api";
import { chooseTheme, storedTheme, type ThemeChoice } from "./theme";
import { Asks, Banner, Btn, Icon, Toasts, toast, type Tone } from "./ui";
import "./styles/tokens.css";
import "./styles/app.css";

export type PageDef = { id: string; title: string; icon: string; bottom?: boolean };

/** The page the address names, or the first. */
export function useHashPage(pages: PageDef[]): string {
  const read = useCallback(() => {
    const h = location.hash.slice(1);
    return pages.some((p) => p.id === h) ? h : pages[0].id;
  }, [pages]);
  const [page, setPage] = useState(read);
  useEffect(() => {
    const go = () => {
      setPage(read());
      window.scrollTo(0, 0);
    };
    window.addEventListener("hashchange", go);
    return () => window.removeEventListener("hashchange", go);
  }, [read]);
  return page;
}

export type Poll<T> = {
  data: T | null;
  error: Error | null;
  reload: () => Promise<void>;
  set: (v: T | null) => void;
};

/** What `load` answers, asked when the page opens and again every `every`
 * ms while the tab is in view (0: only when asked). An answer that comes
 * after a newer question is dropped. */
export function usePoll<T>(load: () => Promise<T>, deps: unknown[], every = 2000): Poll<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const run = useRef(0);
  const fn = useRef(load);
  fn.current = load;
  const reload = useCallback(async () => {
    const n = ++run.current;
    try {
      const v = await fn.current();
      if (n !== run.current) return;
      setData(v);
      setError(null);
    } catch (e) {
      if (n !== run.current) return;
      if (e instanceof ApiError && e.auth) return;
      setError(e as Error);
    }
  }, []);
  useEffect(() => {
    setData(null);
    setError(null);
    reload();
    if (!every) return;
    const t = setInterval(() => {
      if (!document.hidden) reload();
    }, every);
    const seen = () => {
      if (!document.hidden) reload();
    };
    document.addEventListener("visibilitychange", seen);
    return () => {
      clearInterval(t);
      document.removeEventListener("visibilitychange", seen);
      run.current++;
    };
  }, deps);
  return { data, error, reload, set: setData };
}

/** Tells, once each, that the server cannot be reached and that it is back. */
export function useReach(error: Error | null, data: unknown, what: string) {
  const down = useRef(false);
  useEffect(() => {
    if (error && !down.current) {
      down.current = true;
      toast(`Cannot reach the ${what}. Trying again.`, "error");
    } else if (!error && data && down.current) {
      down.current = false;
      toast(`Connected to the ${what} again.`);
    }
  }, [error, data, what]);
}

function ThemeSwitch() {
  const [choice, setChoice] = useState<ThemeChoice>(storedTheme);
  const opts: [ThemeChoice, string, string][] = [
    ["system", "System", "monitor"],
    ["light", "Light", "sun"],
    ["dark", "Dark", "moon"],
  ];
  return (
    <div className="themes" role="radiogroup" aria-label="Theme">
      {opts.map(([v, label, icon]) => (
        <button
          key={v}
          type="button"
          role="radio"
          aria-checked={choice === v}
          onClick={() => {
            chooseTheme(v);
            setChoice(v);
          }}
        >
          <Icon name={icon} />
          {label}
        </button>
      ))}
    </div>
  );
}

/** The sidebar and the page, as the app's window: the pages at the top,
 * Settings and Help at the foot, the state, the theme and Sign out. */
export function Shell({
  role,
  pages,
  page,
  status,
  children,
}: {
  role: string;
  pages: PageDef[];
  page: string;
  status: { tone: Tone; title: string; line: string } | null;
  children: ReactNode;
}) {
  const [nav, setNav] = useState(false);
  useEffect(() => setNav(false), [page]);
  const title = pages.find((p) => p.id === page)?.title || "";
  useEffect(() => {
    document.title = `${title} · Nerve ${role}`;
  }, [title, role]);
  const link = (p: PageDef) => (
    <a key={p.id} className="nav" href={`#${p.id}`} data-page={p.id} aria-current={p.id === page ? "page" : undefined}>
      <Icon name={p.icon} />
      <span>{p.title}</span>
    </a>
  );
  return (
    <div className="shell" data-nav={nav ? "open" : ""}>
      <aside className="side" aria-label="Menu">
        <div className="logo">
          <img src="/icon.svg" alt="" width={32} height={32} />
          <div>
            <b>Nerve</b>
            <small>{role === "center" ? "Center" : "Node"} on this machine</small>
          </div>
          <Btn kind="ghost" icon="x" label="Close menu" className="side-close" onClick={() => setNav(false)} />
        </div>
        <nav aria-label="Pages">{pages.filter((p) => !p.bottom).map(link)}</nav>
        <div className="fill" />
        <nav aria-label="More pages">{pages.filter((p) => p.bottom).map(link)}</nav>
        {status ? (
          <div className={"sstat " + status.tone} role="status">
            <i className="dot" />
            <div>
              <b>{status.title}</b>
              <small>{status.line}</small>
            </div>
          </div>
        ) : null}
        <ThemeSwitch />
        <Btn kind="ghost" icon="logout" className="signout" act={signOut}>
          Sign out
        </Btn>
      </aside>
      <div className="drawer-scrim" onClick={() => setNav(false)} />
      <div className="main">
        <div className="topbar">
          <Btn kind="ghost" icon="menu" label="Open menu" onClick={() => setNav(true)} />
          <b>{title}</b>
        </div>
        <main className="page" id="page" key={page}>
          {children}
        </main>
      </div>
      <Toasts />
      <Asks />
    </div>
  );
}

/** Starts a web UI: draws it once the server says this tab is signed in;
 * goes to the login when it is not. */
export async function start(App: () => ReactNode, what: string) {
  const el = document.getElementById("root")!;
  const root = createRoot(el);
  try {
    if (!(await startSession())) return;
  } catch {
    root.render(
      <div className="login">
        <Banner tone="danger">Cannot reach the {what}. Reload to try again.</Banner>
      </div>,
    );
    return;
  }
  root.render(
    <StrictMode>
      <App />
    </StrictMode>,
  );
}
