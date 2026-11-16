// The shared building blocks of layout B.
import { useState } from "react";
import { expect, it, vi } from "vitest";
import { button, click, key, render, text, type } from "./test/dom";
import { Btn, LRow, ListCard, Overlay, Picker, RemoveAsk, Seg, Split } from "./ui";

it("asks before a removal, in place, and removes only on yes", async () => {
  const gone = vi.fn(async () => {});
  const el = await render(<RemoveAsk question="Remove dev?" onConfirm={gone} />);
  await click(button(el, "Remove"));
  expect(text(el)).toContain("Remove dev?");
  await click(button(el, "Cancel"));
  expect(gone).not.toHaveBeenCalled();
  expect(text(el)).not.toContain("Remove dev?");
  await click(button(el, "Remove"));
  const yes = el.querySelectorAll("button")[1];
  await click(yes);
  expect(gone).toHaveBeenCalledTimes(1);
});

function Picked() {
  const [open, setOpen] = useState(false);
  const [sel, setSel] = useState("a");
  return (
    <Split
      open={open}
      onBack={() => setOpen(false)}
      list={
        <ListCard>
          {["a", "b"].map((x) => (
            <LRow key={x} current={sel === x} onPick={() => (setSel(x), setOpen(true))}>
              row {x}
            </LRow>
          ))}
        </ListCard>
      }
      detail={<div className="card">details of {sel}</div>}
    />
  );
}

it("shows the picked row's details, and Back goes to the list on a small window", async () => {
  const el = await render(<Picked />);
  const split = el.querySelector(".split")!;
  expect(split.classList.contains("open")).toBe(false);
  await click(el.querySelectorAll(".lrow")[1]);
  expect(text(el)).toContain("details of b");
  expect(el.querySelectorAll(".lrow")[1].getAttribute("aria-current")).toBe("true");
  expect(split.classList.contains("open")).toBe(true);
  await click(button(el, "Back to the list"));
  expect(split.classList.contains("open")).toBe(false);
  // Enter picks a row too.
  await key(el.querySelectorAll(".lrow")[0], "Enter");
  expect(text(el)).toContain("details of a");
});

it("moves a row of choices with the arrow keys", async () => {
  const chose = vi.fn();
  const el = await render(<Seg label="Mode" options={[{ value: "a", label: "A" }, { value: "b", label: "B" }]} value="a" onChange={chose} />);
  const group = el.querySelector("[role=radiogroup]")!;
  expect(group.querySelectorAll("[aria-checked=true]")[0].textContent).toBe("A");
  await key(group, "ArrowRight");
  expect(chose).toHaveBeenCalledWith("b");
});

it("closes an overlay with Esc", async () => {
  const close = vi.fn();
  await render(<Overlay title="Pair a machine" onClose={close}>x</Overlay>);
  expect(document.querySelector("[role=dialog]")?.getAttribute("aria-modal")).toBe("true");
  await key(document.body, "Escape");
  expect(close).toHaveBeenCalled();
});

it("puts the focus in an overlay's field, not on its Close", async () => {
  await render(
    <Overlay title="Rename" onClose={() => {}} foot={<Btn kind="primary">Rename</Btn>}>
      <input aria-label="Name" />
    </Overlay>,
  );
  expect(document.activeElement?.getAttribute("aria-label")).toBe("Name");
  await render(
    <Overlay title="Sure?" onClose={() => {}} foot={<Btn kind="primary">Yes</Btn>}>
      x
    </Overlay>,
  );
  expect(document.activeElement?.textContent).toBe("Yes");
});

it("picks an entry of a long list by its search", async () => {
  const pick = vi.fn();
  const items = ["alpha", "beta", "gamma"].map((v) => ({ value: v, text: v }));
  const el = await render(<Picker label="Machine" items={items} value="alpha" onPick={pick} />);
  await click(el.querySelector(".picker-btn"));
  const search = el.querySelector("input[role=combobox]")!;
  await type(search, "gam");
  expect(el.querySelectorAll("[role=option]")).toHaveLength(1);
  await key(search, "Enter");
  expect(pick).toHaveBeenCalledWith("gamma");
  expect(el.querySelector("[role=option]")).toBeNull();
});

it("shows what an action that failed says, and is busy while it runs", async () => {
  let done!: () => void;
  const el = await render(
    <>
      <Btn act={() => new Promise<void>((r) => (done = r))}>Wait</Btn>
      <Btn act={async () => { throw new Error("the center refused"); }}>Fail</Btn>
    </>,
  );
  const { Toasts } = await import("./ui");
  const t = await render(<Toasts />);
  await click(button(el, "Wait"));
  expect(el.querySelector("button")!.getAttribute("aria-busy")).toBe("true");
  expect(el.querySelector("button")!.disabled).toBe(true);
  done();
  await click(button(el, "Fail"));
  expect(text(t)).toContain("the center refused");
});
