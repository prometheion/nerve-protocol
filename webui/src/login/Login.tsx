// The login of both web UIs: the secret is posted once, and the session the
// answer holds is kept in this tab's sessionStorage; the page then sends it
// as a header with every API call. The secret never appears in a URL, and
// nothing is kept in a cookie. What the page says comes from the server, in
// <meta name="nerve-login"> (nerve_transport::webui::login_page).
import { useRef, useState, type FormEvent } from "react";
import { keepSession } from "../api";
import { Icon } from "../ui";

export type LoginInfo = {
  /** What is asked for: "Owner token", "Web UI token". */
  secret: string;
  /** "Log in to this center". */
  title: string;
  tagline: string;
  /** The command that shows the secret, and what follows it. */
  command?: string;
  after?: string;
};

export function readInfo(): LoginInfo {
  const meta = document.querySelector('meta[name="nerve-login"]') as HTMLMetaElement | null;
  try {
    const v = JSON.parse(meta?.content || "");
    if (v && typeof v.secret === "string") return v;
  } catch {
    /* a page served without its text */
  }
  return { secret: "Token", title: "Log in", tagline: "" };
}

export const go = { home: () => location.replace("/") };

export function Login({ info }: { info: LoginInfo }) {
  const input = useRef<HTMLInputElement>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [shown, setShown] = useState(false);
  const submit = async (ev: FormEvent) => {
    ev.preventDefault();
    // Read from the field itself: a password manager or a script may fill
    // it without an input event.
    const token = input.current?.value || "";
    setBusy(true);
    setError("");
    try {
      const r = await fetch("/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token }),
      });
      let v: { session?: string; error?: string } = {};
      try {
        v = await r.json();
      } catch {
        /* no JSON */
      }
      if (r.ok && v.session) {
        keepSession(v.session);
        go.home();
        return;
      }
      setError(v.error || "Cannot sign in.");
      input.current?.select();
    } catch {
      setError("Cannot reach the server. Try again.");
    }
    setBusy(false);
  };
  return (
    <main className="login">
      <form className="card login-form" method="post" action="/login" onSubmit={submit}>
        <div className="login-head">
          <img src="/icon.svg" alt="" width={44} height={44} />
          <h1>{info.title}</h1>
        </div>
        {info.tagline ? <p className="meta">{info.tagline}</p> : null}
        <span className="secret">
          <input
            ref={input}
            className="input login-input"
            type={shown ? "text" : "password"}
            name="token"
            placeholder={info.secret}
            aria-label={info.secret}
            aria-describedby="login-error"
            aria-invalid={error ? true : undefined}
            autoComplete="off"
            autoCapitalize="off"
            spellCheck={false}
            autoFocus
            required
          />
          <button
            type="button"
            className="btn ghost sm icon reveal"
            aria-label={shown ? "Hide" : "Show"}
            title={shown ? "Hide" : "Show"}
            aria-pressed={shown}
            onClick={() => {
              setShown(!shown);
              input.current?.focus();
            }}
          >
            <Icon name={shown ? "eye-off" : "eye"} />
          </button>
        </span>
        <p id="login-error" className="login-error" role="alert" hidden={!error}>
          {error}
        </p>
        <button className="btn primary login-submit" type="submit" disabled={busy}>
          <Icon name="unlock" />
          {busy ? "Checking…" : "Log in"}
        </button>
        {info.command ? (
          <p className="faint">
            No token at hand? <code className="mono">{info.command}</code>
            {info.after}
          </p>
        ) : null}
      </form>
    </main>
  );
}
