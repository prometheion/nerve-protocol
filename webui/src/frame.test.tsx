// The poll that keeps a page current.
import { act } from "react";
import { afterEach, expect, it, vi } from "vitest";
import { usePoll } from "./frame";
import { render, settle, text } from "./test/dom";

afterEach(() => vi.useRealTimers());

function Shown({ load }: { load: () => Promise<string> }) {
  const poll = usePoll(load, [], 2000);
  return <p>{poll.data ?? "Loading"}</p>;
}

it("shows an answer that takes longer than the interval, and asks the next one after it", async () => {
  vi.useFakeTimers({ shouldAdvanceTime: true });
  let asked = 0;
  // Every answer takes 3 s, longer than the 2 s between two questions.
  const load = () =>
    new Promise<string>((done) => {
      const n = ++asked;
      setTimeout(() => done(`answer ${n}`), 3000);
    });
  const el = await render(<Shown load={load} />);
  expect(text(el)).toBe("Loading");
  await act(async () => {
    await vi.advanceTimersByTimeAsync(2100);
  });
  // No second question while the first is open.
  expect(asked).toBe(1);
  await act(async () => {
    await vi.advanceTimersByTimeAsync(1000);
  });
  await settle();
  expect(text(el)).toBe("answer 1");
  // After the answer the next tick asks again.
  await act(async () => {
    await vi.advanceTimersByTimeAsync(2100);
  });
  expect(asked).toBe(2);
});
