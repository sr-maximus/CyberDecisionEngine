import { test } from "node:test";
import assert from "node:assert/strict";
import { EvidenceReviewQueue } from "../src/utils/evidenceReviewQueue";
import type { RunRecord } from "../src/types";

const tick = () => new Promise((resolve) => setTimeout(resolve, 10));
const result = { id: "run" } as RunRecord;
function deferred() {
  let resolve!: (run: RunRecord) => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<RunRecord>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

test("immediate selection, coalescing, and continued editing during a slow save", async () => {
  const requests: { changes: unknown; response: ReturnType<typeof deferred> }[] = [];
  const queue = new EvidenceReviewQueue(async (_, changes) => {
    const response = deferred();
    requests.push({ changes, response });
    return response.promise;
  }, 0);
  queue.enqueue("run", "one", "validated");
  queue.enqueue("run", "one", "false_positive");
  queue.enqueue("run", "two", "validated");
  assert.equal(queue.snapshot("run").one.status, "false_positive");
  assert.equal(requests.length, 0);
  assert.equal(queue.hasUnsettled("run"), true);
  await tick();
  assert.deepEqual(requests[0].changes, [{ evidence_id: "one", status: "false_positive" }, { evidence_id: "two", status: "validated" }]);
  queue.enqueue("run", "one", "pending");
  queue.enqueue("run", "three", "validated");
  assert.equal(requests.length, 1);
  requests[0].response.resolve(result);
  await tick();
  assert.equal(queue.snapshot("run").one.status, "pending");
  assert.equal(queue.snapshot("run").one.state, "saving");
  assert.equal(queue.snapshot("run").two.state, "saved");
  assert.equal(requests.length, 2);
  requests[1].response.resolve(result);
  await tick();
  assert.equal(queue.hasUnsettled("run"), false);
});

test("failed save remains unconfirmed and can be retried without blocking other rows", async () => {
  let attempts = 0;
  const queue = new EvidenceReviewQueue(async () => {
    if (++attempts === 1) throw new Error("Failed to fetch");
    return result;
  }, 0);
  queue.enqueue("run", "one", "validated");
  await tick();
  assert.equal(queue.snapshot("run").one.state, "error");
  assert.equal(queue.hasUnsettled(), true);
  queue.enqueue("run", "one", "validated");
  queue.enqueue("run", "two", "false_positive");
  await tick();
  assert.equal(attempts, 2);
  assert.equal(queue.hasUnsettled(), false);
});

test("navigation unsubscribes the view without losing pending saves or run isolation", async () => {
  const saved: string[] = [];
  const queue = new EvidenceReviewQueue(async (id) => ({ ...result, id }), 0);
  queue.onSaved((run) => saved.push(run.id));
  const unsubscribe = queue.subscribe(() => {});
  queue.enqueue("first", "one", "validated");
  unsubscribe();
  queue.enqueue("second", "one", "false_positive");
  await tick();
  assert.deepEqual(saved.sort(), ["first", "second"]);
  assert.equal(queue.snapshot("first").one.status, "validated");
  assert.equal(queue.snapshot("second").one.status, "false_positive");
  assert.equal(queue.hasUnsettled(), false);
});

test("more than 500 selections are split into bounded batches without dropping changes", async () => {
  const sizes: number[] = [];
  const queue = new EvidenceReviewQueue(async (_, changes) => { sizes.push(changes.length); return result; }, 0);
  for (let i = 0; i < 501; i++) queue.enqueue("run", `ev-${i}`, "validated");
  await tick();
  assert.deepEqual(sizes, [500, 1]);
  assert.equal(queue.hasUnsettled(), false);
});

test("bulk selection emits one optimistic update and preserves every evidence id", async () => {
  const queue = new EvidenceReviewQueue(async () => result, 0);
  let notifications = 0;
  queue.subscribe(() => notifications++);
  queue.enqueueMany("run", Array.from({ length: 350 }, (_, i) => ({ evidence_id: `ev-${i}`, status: "validated" })));
  assert.equal(notifications, 1);
  assert.equal(Object.keys(queue.snapshot("run")).length, 350);
  await tick();
  assert.equal(queue.hasUnsettled(), false);
});

test("an old failed response does not roll back a newer selection", async () => {
  const response = deferred();
  let attempts = 0;
  const queue = new EvidenceReviewQueue(async () => ++attempts === 1 ? response.promise : result, 0);
  queue.enqueue("run", "one", "validated");
  await tick();
  queue.enqueue("run", "one", "pending");
  response.reject(new Error("offline"));
  await tick();
  assert.equal(queue.snapshot("run").one.status, "pending");
  assert.equal(queue.snapshot("run").one.state, "saved");
});
