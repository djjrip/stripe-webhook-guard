/**
 * Storage adapter interface for recording and locking Stripe webhook events.
 */
export interface IdempotencyStore {
  /**
   * Attempts to acquire an execution lock for the given event ID.
   * Returns true if this is the first time the event is being processed, or false if it is a duplicate / already in progress.
   */
  acquireLock(eventId: string, ttlSeconds?: number): Promise<boolean>;

  /**
   * Marks the event as successfully processed with its execution payload.
   */
  markCompleted(eventId: string, resultSummary?: Record<string, unknown>): Promise<void>;

  /**
   * Marks the event as failed and releases the lock for retry, or records failure.
   */
  markFailed(eventId: string, error: string): Promise<void>;

  /**
   * Checks the status of an event.
   */
  getStatus(eventId: string): Promise<'PENDING' | 'COMPLETED' | 'FAILED' | null>;
}

/**
 * Built-in in-memory idempotency store with TTL eviction (ideal for local testing and lightweight services).
 */
export class MemoryIdempotencyStore implements IdempotencyStore {
  private records = new Map<string, { status: 'PENDING' | 'COMPLETED' | 'FAILED'; expiresAt: number; result?: unknown }>();

  async acquireLock(eventId: string, ttlSeconds: number = 300): Promise<boolean> {
    const now = Date.now();
    const existing = this.records.get(eventId);

    if (existing && existing.expiresAt > now) {
      // Event already recorded and unexpired
      return false;
    }

    this.records.set(eventId, {
      status: 'PENDING',
      expiresAt: now + ttlSeconds * 1000
    });

    return true;
  }

  async markCompleted(eventId: string, resultSummary?: Record<string, unknown>): Promise<void> {
    const existing = this.records.get(eventId);
    if (existing) {
      existing.status = 'COMPLETED';
      existing.result = resultSummary;
    }
  }

  async markFailed(eventId: string, error: string): Promise<void> {
    const existing = this.records.get(eventId);
    if (existing) {
      existing.status = 'FAILED';
      existing.result = { error };
    }
  }

  async getStatus(eventId: string): Promise<'PENDING' | 'COMPLETED' | 'FAILED' | null> {
    const now = Date.now();
    const existing = this.records.get(eventId);
    if (!existing || existing.expiresAt <= now) {
      return null;
    }
    return existing.status;
  }
}
