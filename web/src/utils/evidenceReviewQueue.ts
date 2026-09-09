import { reviewRunEvidenceBatch, type EvidenceReviewChange, type EvidenceReviewStatus } from "../api";
import type { RunRecord } from "../types";

type ReviewEntry = { status: EvidenceReviewStatus; state: "saving" | "saved" | "error"; revision: number };
type Snapshot = Readonly<Record<string, ReviewEntry>>;
type RunQueue = {
  snapshot: Snapshot;
  pending: Map<string, ReviewEntry>;
  inFlight: boolean;
  timer?: ReturnType<typeof setTimeout>;
};
const EMPTY: Snapshot = {};

// Run-scoped queues survive tab/view changes. Only one batch per run is sent at a time.
export class EvidenceReviewQueue {
  private runs = new Map<string, RunQueue>();
  private listeners = new Set<() => void>();
  private savedListeners = new Set<(run: RunRecord) => void>();
  private revision = 0;

  constructor(
    private save = reviewRunEvidenceBatch,
    private delay = 300
  ) {}

  subscribe = (listener: () => void) => {
    this.listeners.add(listener);
    return () => { this.listeners.delete(listener); };
  };

  onSaved = (listener: (run: RunRecord) => void) => {
    this.savedListeners.add(listener);
    return () => { this.savedListeners.delete(listener); };
  };

  snapshot = (runId: string): Snapshot => this.runs.get(runId)?.snapshot ?? EMPTY;

  hasUnsettled = (runId?: string): boolean => {
    const queues = runId ? [this.runs.get(runId)] : [...this.runs.values()];
    return queues.some((queue) => queue && Object.values(queue.snapshot).some((entry) => entry.state !== "saved"));
  };

  enqueue(runId: string, evidenceId: string, status: EvidenceReviewStatus) {
    this.enqueueMany(runId, [{ evidence_id: evidenceId, status }]);
  }

  enqueueMany(runId: string, changes: EvidenceReviewChange[]) {
    let queue = this.runs.get(runId);
    if (!queue) {
      queue = { snapshot: EMPTY, pending: new Map(), inFlight: false };
      this.runs.set(runId, queue);
    }
    const snapshot = { ...queue.snapshot };
    for (const { evidence_id: evidenceId, status } of changes) {
      const previous = snapshot[evidenceId];
      if (previous?.status === status && previous.state !== "error") continue;
      const entry: ReviewEntry = { status, state: "saving", revision: ++this.revision };
      snapshot[evidenceId] = entry;
      queue.pending.set(evidenceId, entry);
    }
    if (!queue.pending.size) return;
    queue.snapshot = snapshot;
    this.emit();
    if (!queue.inFlight && !queue.timer) {
      queue.timer = setTimeout(() => { void this.flush(runId, queue!); }, this.delay);
    }
  }

  private emit() {
    this.listeners.forEach((listener) => listener());
  }

  private async flush(runId: string, queue: RunQueue) {
    queue.timer = undefined;
    if (queue.inFlight || !queue.pending.size) return;
    const batch = [...queue.pending.entries()].slice(0, 500);
    batch.forEach(([id]) => queue.pending.delete(id));
    queue.inFlight = true;
    let updated: RunRecord | undefined;
    try {
      const changes: EvidenceReviewChange[] = batch.map(([evidence_id, entry]) => ({ evidence_id, status: entry.status }));
      updated = await this.save(runId, changes);
    } catch {
      // An interrupted response is unconfirmed, not a successful save or a rollback.
    }
    const snapshot = { ...queue.snapshot };
    for (const [id, entry] of batch) {
      if (snapshot[id]?.revision === entry.revision) {
        snapshot[id] = { ...entry, state: updated ? "saved" : "error" };
      }
    }
    queue.snapshot = snapshot;
    queue.inFlight = false;
    if (updated) this.savedListeners.forEach((listener) => listener(updated!));
    this.emit();
    if (queue.pending.size) void this.flush(runId, queue);
  }
}

export const evidenceReviews = new EvidenceReviewQueue();
