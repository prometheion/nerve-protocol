// The form of a capability of your own, the same in both UIs: a name, what
// it does, the fixed command, its arguments and result as JSON Schemas, its
// time limit and where it runs. Each field shows what is wrong with it.
import { Field, Seg, TextArea, TextInput } from "../ui";

export type CapFormValue = {
  name: string;
  summary: string;
  effect: string;
  command: string;
  params: string;
  result: string;
  timeout: string;
  platform: string;
};

export type CapErrors = Partial<Record<keyof CapFormValue, string>>;

export const blankCapForm = (): CapFormValue => ({ name: "", summary: "", effect: "read", command: "", params: "", result: "", timeout: "", platform: "any" });

const EFFECTS = ["read", "write", "execute", "sense", "actuate"];
const PLATFORMS: [string, string][] = [
  ["any", "Any system"],
  ["linux", "Linux"],
  ["windows", "Windows"],
];

export function CapFields({
  v,
  set,
  errors,
  adding,
  effectHint,
}: {
  v: CapFormValue;
  set: (v: CapFormValue) => void;
  errors?: CapErrors;
  adding: boolean;
  effectHint?: string;
}) {
  const e = (k: keyof CapFormValue) => (errors ? errors[k] || "" : undefined);
  const put = (k: keyof CapFormValue) => (x: string) => set({ ...v, [k]: x });
  return (
    <>
      <div className="form-row">
        <Field label="Name (cap.action, like sensors.read)" error={e("name")}>
          <TextInput value={v.name} onChange={put("name")} readOnly={!adding} mono placeholder="backup.run" />
        </Field>
        <Field label="Time limit (seconds, empty for the machine's default)" error={e("timeout")}>
          <TextInput value={v.timeout} onChange={put("timeout")} inputMode="numeric" />
        </Field>
      </div>
      <div className="field">
        <span className="label">What it does</span>
        <Seg label="What it does" size="sm" value={v.effect} onChange={put("effect")} options={EFFECTS.map((x) => ({ value: x, label: x }))} />
        {effectHint ? <span className="hint">{effectHint}</span> : null}
        {errors ? <span className="error" role="status">{e("effect")}</span> : null}
      </div>
      <Field label="Summary (one line for the agent)" error={e("summary")}>
        <TextInput value={v.summary} onChange={put("summary")} placeholder="Backs up my notes." />
      </Field>
      <Field label="Command (the program first; a word {field} is the argument field)" error={e("command")}>
        <TextInput value={v.command} onChange={put("command")} mono placeholder="restic backup /home/you/notes" />
      </Field>
      <Field label="Arguments (a JSON Schema; empty for none)" error={e("params")}>
        <TextArea value={v.params} onChange={put("params")} placeholder={'{"type": "object", "properties": {}}'} />
      </Field>
      <Field label="Result (a JSON Schema the printed JSON fits; empty for the printed text)" error={e("result")}>
        <TextArea value={v.result} onChange={put("result")} placeholder="empty: the printed text" />
      </Field>
      <div className="field">
        <span className="label">Where it runs</span>
        <Seg label="Where it runs" size="sm" value={v.platform} onChange={put("platform")} options={PLATFORMS.map(([value, label]) => ({ value, label }))} />
        {errors ? <span className="error" role="status">{e("platform")}</span> : null}
      </div>
    </>
  );
}
