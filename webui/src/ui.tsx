// The building blocks both web UIs draw their pages with, in the app's
// layout B: buttons, switches, the rows of choices, fields, the list and
// its details, the inline question before a removal, overlays, folds and
// toasts. No UI library: each is small and follows the app's widget of the
// same name (crates/nerve/ui/widgets.slint).
import {
  createElement,
  useCallback,
  useEffect,
  useId,
  useRef,
  useState,
  type InputHTMLAttributes,
  type KeyboardEvent,
  type PointerEvent as ReactPointerEvent,
  type ReactNode,
  type TextareaHTMLAttributes,
} from "react";
import { createPortal } from "react-dom";
import { ApiError } from "./api";
import { ICONS } from "./icons";

export type Tone = "" | "accent" | "ok" | "warn" | "danger" | "neutral" | "line";

// ---------- Icons ----------

const camel = (k: string) => k.replace(/-(\w)/g, (_, c: string) => c.toUpperCase());

export function Icon({ name, size }: { name: string; size?: "sm" | "lg" }) {
  const parts = ICONS[name] || [];
  return (
    <svg className={"ico" + (size ? " " + size : "")} viewBox="0 0 24 24" aria-hidden="true">
      {parts.map(([tag, attrs], i) =>
        createElement(tag, { key: i, ...Object.fromEntries(Object.entries(attrs).map(([k, v]) => [camel(k), v])) }),
      )}
    </svg>
  );
}

// ---------- Toasts ----------

type ToastItem = { id: number; text: string; kind: "ok" | "error" };
let toastList: ToastItem[] = [];
let toastNext = 1;
const toastWatch = new Set<(t: ToastItem[]) => void>();

/** A short note in the corner, gone after a few seconds. */
export function toast(text: string, kind: "ok" | "error" = "ok") {
  const t = { id: toastNext++, text, kind };
  toastList = [...toastList, t].slice(-4);
  toastWatch.forEach((f) => f(toastList));
  setTimeout(() => {
    toastList = toastList.filter((x) => x.id !== t.id);
    toastWatch.forEach((f) => f(toastList));
  }, kind === "error" ? 7000 : 3500);
}

/** What went wrong, as a toast; a session that ended says nothing (the page
 * goes to the login). */
export function failed(e: unknown) {
  if (e instanceof ApiError && e.auth) return;
  toast(e instanceof Error ? e.message : String(e), "error");
}

export function Toasts() {
  const [list, setList] = useState(toastList);
  useEffect(() => {
    toastWatch.add(setList);
    return () => void toastWatch.delete(setList);
  }, []);
  return (
    <div className="toasts" role="status" aria-live="polite">
      {list.map((t) => (
        <div key={t.id} className={"toast " + t.kind}>
          <Icon name={t.kind === "error" ? "alert" : "check"} />
          <span>{t.text}</span>
        </div>
      ))}
    </div>
  );
}

export async function copy(text: string) {
  try {
    await navigator.clipboard.writeText(text);
    toast("Copied.");
  } catch {
    toast("Copying is blocked here. Select the text and copy it by hand.", "error");
  }
}

// ---------- Buttons ----------

type BtnProps = {
  children?: ReactNode;
  kind?: "" | "primary" | "ghost" | "danger" | "danger-solid";
  size?: "" | "sm";
  icon?: string;
  /** A plain click. */
  onClick?: () => void;
  /** An action: the button is busy while it runs, and what fails is a toast. */
  act?: () => Promise<unknown> | unknown;
  title?: string;
  label?: string;
  disabled?: boolean;
  type?: "button" | "submit";
  className?: string;
  /** Ignore the second click of a double-click (the confirm of a question
   * opens where the first click landed). */
  single?: boolean;
};

/** Runs an action the way a button does: busy, errors as a toast. */
export function useAction(): [boolean, (fn: () => Promise<unknown> | unknown) => Promise<void>] {
  const [busy, setBusy] = useState(false);
  const live = useRef(true);
  useEffect(() => {
    live.current = true;
    return () => {
      live.current = false;
    };
  }, []);
  const run = useCallback(async (fn: () => Promise<unknown> | unknown) => {
    setBusy(true);
    try {
      await fn();
    } catch (e) {
      failed(e);
    } finally {
      if (live.current) setBusy(false);
    }
  }, []);
  return [busy, run];
}

export function Btn({ children, kind = "", size = "sm", icon, onClick, act, title, label, disabled, type = "button", className, single }: BtnProps) {
  const [busy, run] = useAction();
  const cls = ["btn", kind, size, !children && icon ? "icon" : "", className || ""].filter(Boolean).join(" ");
  return (
    <button
      type={type}
      className={cls}
      title={title}
      aria-label={label}
      aria-busy={busy || undefined}
      disabled={disabled || busy}
      onClick={(e) => {
        if (single && e.detail > 1) return;
        if (act) run(act);
        else onClick?.();
      }}
    >
      {busy ? <span className="spinner" aria-hidden="true" /> : icon ? <Icon name={icon} /> : null}
      {children}
    </button>
  );
}

/** A link styled as a button, opening outside the page. */
export function LinkBtn({ href, children, icon = "external", kind = "ghost" }: { href: string; children: ReactNode; icon?: string; kind?: string }) {
  return (
    <a className={`btn ${kind}`} href={href} target="_blank" rel="noopener noreferrer">
      <Icon name={icon} />
      {children}
    </a>
  );
}

// ---------- Small pieces ----------

export function Pill({ tone = "", dot, children, title }: { tone?: Tone; dot?: boolean; children: ReactNode; title?: string }) {
  return (
    <span className={"pill " + tone} title={title}>
      {dot ? <i className="dot" /> : null}
      {children}
    </span>
  );
}

export function Dot({ tone = "" }: { tone?: Tone }) {
  return <i className={"dot " + tone} />;
}

export function Tile({ icon, tone = "", size }: { icon: string; tone?: Tone; size?: "sm" }) {
  return (
    <span className={`tile ${tone} ${size || ""}`}>
      <Icon name={icon} size={size ? undefined : "lg"} />
    </span>
  );
}

export function Banner({ tone = "", icon = "alert", children }: { tone?: Tone; icon?: string; children: ReactNode }) {
  return (
    <div className={"banner " + tone} role={tone === "danger" ? "alert" : undefined}>
      <Icon name={icon} />
      <div className="grow">{children}</div>
    </div>
  );
}

export function Loading() {
  return (
    <div className="loading" role="status">
      <span className="dots" aria-hidden="true">
        <span />
        <span />
        <span />
      </span>
      Loading…
    </div>
  );
}

export function Empty({ icon = "info", children }: { icon?: string; children: ReactNode }) {
  return (
    <div className="empty">
      <span className="tile neutral">
        <Icon name={icon} />
      </span>
      <p>{children}</p>
    </div>
  );
}

/** The rest of a short text, folded: the line before it says what counts. */
export function More({ summary = "More", children, open }: { summary?: string; children: ReactNode; open?: boolean }) {
  return (
    <details className="more" open={open}>
      <summary>
        <span>{summary}</span>
        <Icon name="chev" size="sm" />
      </summary>
      <div className="body">{children}</div>
    </details>
  );
}

/** A text to copy: its label, the text, Copy. */
export function CopyRow({ label, value }: { label?: string; value: string }) {
  return (
    <div className={"copy" + (label ? "" : " bare")}>
      {label ? <span>{label}</span> : null}
      <code className="mono">{value}</code>
      <Btn kind="ghost" icon="copy" onClick={() => copy(value)}>
        Copy
      </Btn>
    </div>
  );
}

// ---------- Choices ----------

export function Switch({
  checked,
  onChange,
  children,
  label,
  disabled,
}: {
  checked: boolean;
  onChange: (next: boolean) => Promise<unknown> | unknown;
  children?: ReactNode;
  label?: string;
  disabled?: boolean;
}) {
  const [busy, run] = useAction();
  return (
    <button
      type="button"
      role="switch"
      className="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled || busy}
      onClick={() => run(() => onChange(!checked))}
    >
      <span className="track" />
      {children ? <span>{children}</span> : null}
    </button>
  );
}

export type Option<T> = { value: T; label: ReactNode; count?: ReactNode; disabled?: boolean };

/** A row of choices of which one is on, as the app's Segmented: the arrow
 * keys move the choice, and the row is one stop of the Tab key. */
export function Seg<T extends string | number | null>({
  label,
  options,
  value,
  onChange,
  size,
  full,
  disabled,
}: {
  label: string;
  options: Option<T>[];
  value: T;
  onChange: (v: T) => Promise<unknown> | unknown;
  size?: "sm" | "lg";
  full?: boolean;
  disabled?: boolean;
}) {
  const [busy, run] = useAction();
  const box = useRef<HTMLDivElement>(null);
  const keys = (ev: KeyboardEvent) => {
    const step = ({ ArrowLeft: -1, ArrowUp: -1, ArrowRight: 1, ArrowDown: 1 } as Record<string, number>)[ev.key];
    if (!step) return;
    ev.preventDefault();
    const at = options.findIndex((o) => o.value === value);
    const next = options[at + step];
    if (next && !next.disabled) {
      run(() => onChange(next.value));
      const b = box.current?.querySelectorAll("button")[at + step] as HTMLButtonElement | undefined;
      b?.focus();
    }
  };
  return (
    <div ref={box} className={`seg ${size || ""} ${full ? "full" : ""}`} role="radiogroup" aria-label={label} onKeyDown={keys}>
      {options.map((o) => (
        <button
          key={String(o.value)}
          type="button"
          role="radio"
          aria-checked={o.value === value}
          tabIndex={o.value === value || (!options.some((x) => x.value === value) && o === options[0]) ? 0 : -1}
          disabled={disabled || busy || o.disabled}
          onClick={(ev) => {
            ev.stopPropagation();
            if (o.value !== value) run(() => onChange(o.value));
          }}
        >
          {o.label}
          {o.count !== undefined ? <span className="n">{o.count}</span> : null}
        </button>
      ))}
    </div>
  );
}

// ---------- Fields ----------

export function Field({ label, hint, error, children, className }: { label: ReactNode; hint?: ReactNode; error?: string; children: ReactNode; className?: string }) {
  return (
    <label className={"field " + (className || "")}>
      <span className="label">{label}</span>
      {children}
      {hint ? <span className="hint">{hint}</span> : null}
      {error !== undefined ? (
        <span className="error" role="status">
          {error}
        </span>
      ) : null}
    </label>
  );
}

type InputProps = Omit<InputHTMLAttributes<HTMLInputElement>, "onChange" | "value"> & {
  value: string;
  onChange: (v: string) => void;
  mono?: boolean;
};

export function TextInput({ value, onChange, mono, className, ...rest }: InputProps) {
  return (
    <input
      className={`input ${mono ? "mono" : ""} ${className || ""}`}
      type="text"
      autoComplete="off"
      spellCheck={false}
      value={value}
      onChange={(e) => onChange(e.target.value)}
      {...rest}
    />
  );
}

/** A password, token or passphrase field with a button that shows what was
 * typed and hides it again. */
export function SecretInput({ value, onChange, ...rest }: InputProps) {
  const [shown, setShown] = useState(false);
  return (
    <span className="secret">
      <input
        className="input"
        type={shown ? "text" : "password"}
        autoComplete="off"
        spellCheck={false}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        {...rest}
      />
      <Btn kind="ghost" icon={shown ? "eye-off" : "eye"} label={shown ? "Hide" : "Show"} title={shown ? "Hide" : "Show"} onClick={() => setShown(!shown)} className="reveal" />
    </span>
  );
}

export function TextArea({ value, onChange, className, ...rest }: Omit<TextareaHTMLAttributes<HTMLTextAreaElement>, "onChange" | "value"> & { value: string; onChange: (v: string) => void }) {
  return <textarea className={"input " + (className || "")} spellCheck={false} value={value} onChange={(e) => onChange(e.target.value)} {...rest} />;
}

/** The rows a field of `text` needs to show it whole, from `least` up to
 * 24: a long line counts as one row for every 60 characters, about what a
 * row of the details pane holds, and a field of several lines keeps one
 * empty row to type on. No style is written (the CSP), so the height is
 * the field's rows. */
export function rowsFor(text: string, least: number): number {
  const rows = text.split("\n").reduce((n, line) => n + Math.max(1, Math.ceil(line.length / 60)), 0);
  return Math.min(24, Math.max(least, rows + (least > 1 ? 1 : 0)));
}

/** A JSON or command field that grows with its text (owner's finding on
 * pre2: the Arguments and Result fields showed a few short lines). A
 * one-line field (a command) takes no line break: Enter is not typed. */
export function GrowArea({ value, onChange, className, oneLine, ...rest }: Omit<TextareaHTMLAttributes<HTMLTextAreaElement>, "onChange" | "value" | "rows"> & { value: string; onChange: (v: string) => void; oneLine?: boolean }) {
  return (
    <textarea
      className={"input grow-area " + (oneLine ? "one-line " : "") + (className || "")}
      spellCheck={false}
      value={value}
      rows={rowsFor(value, oneLine ? 1 : 4)}
      onChange={(e) => onChange(oneLine ? e.target.value.replace(/[\r\n]+/g, " ") : e.target.value)}
      onKeyDown={oneLine ? (e) => e.key === "Enter" && e.preventDefault() : undefined}
      {...rest}
    />
  );
}

// ---------- The page: its head, the list and the details ----------

export function PageHead({ icon, title, sub, children }: { icon: string; title: ReactNode; sub?: ReactNode; children?: ReactNode }) {
  return (
    <header className="phead">
      <Tile icon={icon} />
      <div className="grow">
        <h1 id="top-title">{title}</h1>
        {sub ? <p className="sub">{sub}</p> : null}
      </div>
      {children ? <div className="acts">{children}</div> : null}
    </header>
  );
}

/** The list's share of a Split's two panes, in percent, as the steps the
 * stylesheet has (`.split[data-w]`): a width the owner dragged to. Each pane
 * keeps its least width there (`minmax`), the list 260 px and the details
 * 400 px. */
export const PANE = { least: 20, most: 76, step: 2, list: 260, details: 400 };

/** Where the width a Split's list was dragged to is kept: per page (and
 * kind of Split), in this browser only. */
function paneKey(variant: string): string {
  const page = (typeof location === "undefined" ? "" : location.hash).replace(/^#/, "").split(/[?/]/)[0];
  return `nerve.pane.${page || "home"}.${variant || "split"}`;
}

function storedPane(key: string): number | null {
  try {
    const n = Number(localStorage.getItem(key));
    return n >= PANE.least && n <= PANE.most ? n : null;
  } catch {
    return null;
  }
}

/** The list's share at `x` (a pointer's place) between the list's left edge
 * and the details' right edge, on the stylesheet's steps: the drag stops
 * where a pane would go below its least width (owner, #213). */
export function paneShare(x: number, left: number, right: number): number {
  const span = right - left;
  if (span <= 0) return 50;
  const step = (n: number, round: (n: number) => number) => round(n / PANE.step) * PANE.step;
  const least = step(Math.max(PANE.least, (PANE.list / span) * 100), Math.ceil);
  const most = step(Math.min(PANE.most, 100 - (PANE.details / span) * 100), Math.floor);
  return Math.min(most, Math.max(least, step(((x - left) / span) * 100, Math.round)));
}

/** The gap between the list and the details: dragged (or the arrow keys)
 * it gives the list another width, which the page keeps; a double-click
 * gives the width back to the page (owner's finding on pre2: the panes
 * could not be resized). Only where the two stand side by side. */
function Gutter({ width, setWidth }: { width: number | null; setWidth: (w: number | null) => void }) {
  // The two panes' edges, as they stand now.
  const edges = (bar: Element) => {
    const split = bar.closest(".split");
    const l = split?.querySelector(":scope > .lcol")?.getBoundingClientRect();
    const d = split?.querySelector(":scope > .dcol")?.getBoundingClientRect();
    return l && d ? { l, d } : null;
  };
  const drag = (e: ReactPointerEvent<HTMLDivElement>) => {
    const at = edges(e.currentTarget);
    if (!at) return;
    const { l, d } = at;
    e.preventDefault();
    const bar = e.currentTarget;
    bar.setPointerCapture?.(e.pointerId);
    const move = (m: PointerEvent) => setWidth(paneShare(m.clientX, l.left, d.right));
    const end = () => {
      bar.removeEventListener("pointermove", move);
      bar.removeEventListener("pointerup", end);
      bar.removeEventListener("pointercancel", end);
    };
    bar.addEventListener("pointermove", move);
    bar.addEventListener("pointerup", end);
    bar.addEventListener("pointercancel", end);
  };
  // Without a width of its own the list has the page's: where the panes
  // meet now.
  const now = (bar: Element) => {
    const at = edges(bar);
    return width ?? (at ? paneShare(at.l.right, at.l.left, at.d.right) : 40);
  };
  return (
    <div
      className="gutter"
      role="separator"
      aria-orientation="vertical"
      aria-label="Width of the list"
      aria-valuemin={PANE.least}
      aria-valuemax={PANE.most}
      aria-valuenow={width ?? undefined}
      title="Drag to resize; double-click for the page's own width"
      tabIndex={0}
      onPointerDown={drag}
      onDoubleClick={() => setWidth(null)}
      onKeyDown={(e) => {
        const by = e.key === "ArrowLeft" ? -PANE.step : e.key === "ArrowRight" ? PANE.step : 0;
        if (by) {
          e.preventDefault();
          setWidth(Math.min(PANE.most, Math.max(PANE.least, now(e.currentTarget) + by)));
        }
      }}
    />
  );
}

/** The list on the left and the picked row's details on the right, side by
 * side where the page is 680 px wide or more; narrower they take turns,
 * `open` showing the details with Back. A third pane (`third`, or the
 * section column `nav`) joins from 1040 px (app.css). */
export function Split({
  list,
  detail,
  open,
  onBack,
  variant = "",
  third,
  nav,
}: {
  list: ReactNode;
  detail: ReactNode;
  open: boolean;
  onBack: () => void;
  variant?: string;
  third?: ReactNode;
  nav?: ReactNode;
}) {
  const key = paneKey(variant);
  const [width, setWidthNow] = useState<number | null>(() => storedPane(key));
  const setWidth = (w: number | null) => {
    setWidthNow(w);
    try {
      if (w === null) localStorage.removeItem(key);
      else localStorage.setItem(key, String(w));
    } catch {
      /* storage blocked: the width lasts until the page is left */
    }
  };
  return (
    <div className={`split ${variant} ${open ? "open" : ""} ${nav ? "three" : ""}`} data-w={width ?? undefined}>
      {nav ? <div className="navpane card">{nav}</div> : null}
      <div className="lcol">{list}</div>
      <div className="dcol">
        <Gutter width={width} setWidth={setWidth} />
        <Btn kind="ghost" icon="arrow-left" className="back" onClick={onBack}>
          Back to the list
        </Btn>
        {detail}
      </div>
      {third ? <div className="third">{third}</div> : null}
    </div>
  );
}

export function ListCard({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={"card list " + (className || "")}>{children}</div>;
}

export function LGroup({ title, count, className }: { title: ReactNode; count?: ReactNode; className?: string }) {
  return (
    <div className={"lgroup " + (className || "")}>
      {title}
      {count !== undefined ? <span className="count">{count}</span> : null}
    </div>
  );
}

/** One row of a list: a click or Enter picks it. A row may hold controls of
 * its own (a switch), so it is not itself a button. */
export function LRow({
  current,
  onPick,
  children,
  className,
  label,
}: {
  current?: boolean;
  onPick: () => void;
  children: ReactNode;
  className?: string;
  label?: string;
}) {
  return (
    <div
      role="button"
      tabIndex={0}
      aria-label={label}
      aria-current={current ? "true" : undefined}
      className={"lrow " + (className || "")}
      onClick={onPick}
      onKeyDown={(e) => {
        if ((e.key === "Enter" || e.key === " ") && e.target === e.currentTarget) {
          e.preventDefault();
          onPick();
        }
      }}
    >
      {children}
    </div>
  );
}

/** The row at the end of a list's group that opens its form. */
export function AddRow({ label, current, onPick, className }: { label: string; current?: boolean; onPick: () => void; className?: string }) {
  return (
    <button type="button" className={"lrow add " + (className || "")} aria-current={current ? "true" : undefined} onClick={onPick}>
      <Icon name="plus" />
      {label}
    </button>
  );
}

export function Detail({
  icon,
  tile,
  title,
  pills,
  actions,
  compact,
  children,
  mono,
}: {
  icon?: string;
  tile?: Tone;
  title: ReactNode;
  pills?: ReactNode;
  actions?: ReactNode;
  compact?: boolean;
  children?: ReactNode;
  mono?: boolean;
}) {
  return (
    <section className={"card detail " + (compact ? "compact" : "")}>
      <div className="dhead">
        {icon ? tile !== undefined ? <Tile icon={icon} tone={tile} /> : <Icon name={icon} size="lg" /> : null}
        <h2 className={mono ? "mono" : ""}>{title}</h2>
        {pills}
        {actions ? <span className="dacts">{actions}</span> : null}
      </div>
      {children}
    </section>
  );
}

export function DSec({ title, children }: { title?: string; children: ReactNode }) {
  return (
    <div className="dsec">
      {title ? <h3>{title}</h3> : null}
      {children}
    </div>
  );
}

/** A form in the details pane: its title, the fields, Cancel and Save. */
export function FormCard({
  icon,
  title,
  sub,
  children,
  onCancel,
  onSave,
  save = "Save",
  refusal,
}: {
  icon: string;
  title: string;
  sub?: ReactNode;
  children: ReactNode;
  onCancel: () => void;
  onSave: () => Promise<unknown>;
  save?: string;
  refusal?: ReactNode;
}) {
  return (
    <form
      className="card detail compact"
      onSubmit={(e) => {
        e.preventDefault();
      }}
    >
      <div className="dhead">
        <Icon name={icon} size="lg" />
        <h2>{title}</h2>
      </div>
      {sub ? <p className="lead meta">{sub}</p> : null}
      <div className="form">
        {children}
        {refusal}
        <div className="ffoot">
          <Btn kind="ghost" size="" onClick={onCancel}>
            Cancel
          </Btn>
          <Btn kind="primary" size="" icon="check" act={onSave} type="submit">
            {save}
          </Btn>
        </div>
      </div>
    </form>
  );
}

// ---------- Questions ----------

/** A removal that asks first, in place: the button turns into the question,
 * Cancel and the button that does it. */
export function RemoveAsk({
  question,
  onConfirm,
  label = "Remove",
  confirm,
  icon = "trash",
  size = "sm",
  bare,
}: {
  question: string;
  onConfirm: () => Promise<unknown>;
  label?: string;
  confirm?: string;
  icon?: string;
  size?: "" | "sm";
  bare?: boolean;
}) {
  const [asking, setAsking] = useState(false);
  if (!asking) {
    return (
      <Btn kind={bare ? "ghost" : "danger"} size={size} icon={icon} label={bare ? label : undefined} title={bare ? label : undefined} onClick={() => setAsking(true)}>
        {bare ? null : label}
      </Btn>
    );
  }
  return (
    <span className="ask" role="group" aria-label={question}>
      <span>{question}</span>
      <Btn kind="ghost" size={size} onClick={() => setAsking(false)}>
        Cancel
      </Btn>
      <Btn kind="danger-solid" size={size} icon={icon} single act={async () => {
        await onConfirm();
        setAsking(false);
      }}>
        {confirm || label}
      </Btn>
    </span>
  );
}

/** A small window over the page: Esc, the cross, Cancel or a click on the
 * scrim closes it. It is drawn in the document's body, not where it is
 * used: the page is a size container (app.css `.page`), which would hold a
 * fixed scrim to the page instead of the window (#213, review). */
export function Overlay({ title, sub, onClose, children, foot, first }: { title: string; sub?: ReactNode; onClose: () => void; children?: ReactNode; foot?: ReactNode; first?: string }) {
  const box = useRef<HTMLDivElement>(null);
  const id = useId();
  const close = useRef(onClose);
  close.current = onClose;
  useEffect(() => {
    const before = document.activeElement as HTMLElement | null;
    // The first field, else the main button, else any: each looked for in
    // turn, or the header's Close, which comes first, would always win.
    // A window that names its control (a question without a field names
    // Cancel) puts the focus there, so a stray Enter does not say yes.
    const start = (first ? [first] : ["input, textarea", "button.primary", "button"]).map((s) => box.current?.querySelector<HTMLElement>(s)).find(Boolean);
    start?.focus();
    const esc = (e: globalThis.KeyboardEvent) => {
      if (e.key === "Escape") close.current();
    };
    document.addEventListener("keydown", esc);
    return () => {
      document.removeEventListener("keydown", esc);
      before?.focus?.();
    };
  }, []);
  return createPortal(
    <div className="scrim" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="dialog" role="dialog" aria-modal="true" aria-labelledby={id} ref={box}>
        <div className="dh">
          <div className="grow">
            <h2 id={id}>{title}</h2>
            {sub ? <p>{sub}</p> : null}
          </div>
          <Btn kind="ghost" icon="x" label="Close" title="Close" onClick={onClose} className="x" />
        </div>
        {children ? <div className="db">{children}</div> : null}
        {foot ? <div className="df">{foot}</div> : null}
      </div>
    </div>,
    document.body,
  );
}

type Ask = { title: string; message?: ReactNode; confirm: string; danger?: boolean; field?: { label: string; value: string; pattern?: string } };
let askHost: ((a: Ask, done: (v: string | boolean | null) => void) => void) | null = null;

/** Asks a question in an overlay: true (or the field's text) for yes, null
 * for no. For what is not a removal: a removal asks in its row. */
export function ask(a: Ask): Promise<string | boolean | null> {
  return new Promise((resolve) => {
    if (!askHost) return resolve(null);
    askHost(a, resolve);
  });
}

export function Asks() {
  const [q, setQ] = useState<{ a: Ask; done: (v: string | boolean | null) => void } | null>(null);
  const [text, setText] = useState("");
  useEffect(() => {
    askHost = (a, done) => {
      setText(a.field?.value || "");
      setQ({ a, done });
    };
    return () => {
      askHost = null;
    };
  }, []);
  const close = useCallback(() => {
    setQ((cur) => {
      cur?.done(null);
      return null;
    });
  }, []);
  if (!q) return null;
  const { a } = q;
  const valid = !a.field || (text !== "" && (!a.field.pattern || new RegExp(`^(?:${a.field.pattern})$`).test(text)));
  const yes = () => {
    if (!valid) return;
    q.done(a.field ? text : true);
    setQ(null);
  };
  return (
    <Overlay
      title={a.title}
      sub={a.message}
      onClose={close}
      first={a.field ? undefined : ".df button"}
      foot={
        <>
          <Btn kind="ghost" size="" onClick={close}>
            Cancel
          </Btn>
          <Btn kind={a.danger ? "danger-solid" : "primary"} size="" onClick={yes} disabled={!valid}>
            {a.confirm}
          </Btn>
        </>
      }
    >
      {a.field ? (
        <Field label={a.field.label}>
          <TextInput value={text} onChange={setText} onKeyDown={(e) => e.key === "Enter" && yes()} aria-invalid={!valid || undefined} />
        </Field>
      ) : null}
    </Overlay>
  );
}

// ---------- A searchable list to pick one entry from ----------

export type PickItem<T> = { value: T; text: string };

/** A list to pick one entry from, with a search field, for when a row of
 * choices would be too long: a button shows the choice and opens a panel.
 * Down opens it, Up and Down move, Enter picks, Escape closes. */
export function Picker<T extends string | null>({
  label,
  items,
  value,
  onPick,
  search = "Search",
  none = "Nothing matches.",
  hideLabel,
}: {
  label: string;
  items: PickItem<T>[];
  value: T;
  onPick: (v: T) => void;
  search?: string;
  none?: string;
  hideLabel?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState("");
  const [active, setActive] = useState(0);
  const id = useId();
  const root = useRef<HTMLDivElement>(null);
  const button = useRef<HTMLButtonElement>(null);
  const shown = items.filter((i) => i.text.toLowerCase().includes(q.trim().toLowerCase()));
  const chosen = items.find((i) => i.value === value);
  const show = (on: boolean) => {
    setOpen(on);
    if (on) {
      setQ("");
      setActive(Math.max(0, items.findIndex((i) => i.value === value)));
    }
  };
  const pick = (i: PickItem<T>) => {
    setOpen(false);
    button.current?.focus();
    if (i.value !== value) onPick(i.value);
  };
  return (
    <div
      className="field picker"
      ref={root}
      onBlur={(e) => {
        if (open && !root.current?.contains(e.relatedTarget as Node)) setOpen(false);
      }}
    >
      <span className={hideLabel ? "sr" : "label"} id={`${id}-l`}>
        {label}
      </span>
      <button
        ref={button}
        type="button"
        className="input picker-btn"
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-labelledby={`${id}-l ${id}-b`}
        id={`${id}-b`}
        onClick={() => show(!open)}
        onKeyDown={(e) => {
          if (e.key === "ArrowDown" || e.key === "ArrowUp") {
            e.preventDefault();
            show(true);
          }
        }}
      >
        <span>{chosen ? chosen.text : ""}</span>
        <Icon name="chev" size="sm" />
      </button>
      {open ? (
        <div className="picker-panel">
          <input
            className="input"
            type="text"
            role="combobox"
            aria-expanded="true"
            aria-controls={`${id}-list`}
            aria-label={search}
            aria-activedescendant={shown[active] ? `${id}-o${active}` : undefined}
            placeholder="Search…"
            autoFocus
            autoComplete="off"
            spellCheck={false}
            value={q}
            onChange={(e) => {
              setQ(e.target.value);
              setActive(0);
            }}
            onKeyDown={(e) => {
              const step = ({ ArrowDown: 1, ArrowUp: -1, PageDown: 6, PageUp: -6 } as Record<string, number>)[e.key];
              if (step) {
                e.preventDefault();
                if (shown.length) setActive(Math.min(shown.length - 1, Math.max(0, active + step)));
              } else if (e.key === "Enter") {
                e.preventDefault();
                if (shown[active]) pick(shown[active]);
              } else if (e.key === "Escape") {
                e.preventDefault();
                e.stopPropagation();
                setOpen(false);
                button.current?.focus();
              }
            }}
          />
          <ul className="picker-list" role="listbox" id={`${id}-list`} tabIndex={-1} aria-labelledby={`${id}-l`}>
            {shown.map((i, k) => (
              <li
                key={String(i.value)}
                id={`${id}-o${k}`}
                role="option"
                aria-selected={i.value === value}
                className={k === active ? "active" : ""}
                onMouseDown={(e) => e.preventDefault()}
                onClick={() => pick(i)}
              >
                <span>{i.text}</span>
                {i.value === value ? <Icon name="check" size="sm" /> : null}
              </li>
            ))}
          </ul>
          <p className="picker-none" role="status">
            {shown.length ? "" : none}
          </p>
        </div>
      ) : null}
    </div>
  );
}
