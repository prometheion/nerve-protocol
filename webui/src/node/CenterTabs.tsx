// The center a page shows, above it: a row of choices of the paired
// centers, or a searchable list where there are many.
import { Picker, Seg } from "../ui";
import { useNode } from "./App";

export function CenterTabs() {
  const { o, center, setCenter } = useNode();
  if (!center) return null;
  return (
    <div className="ctabs">
      <span className="faint">Center</span>
      {o.centers.length <= 5 ? (
        <Seg label="Center" value={center} onChange={setCenter} options={o.centers.map((c) => ({ value: c.name, label: c.name }))} />
      ) : (
        <Picker label="Center" hideLabel items={o.centers.map((c) => ({ value: c.name, text: c.name }))} value={center} onPick={setCenter} search="Search centers" none="No center matches." />
      )}
    </div>
  );
}
