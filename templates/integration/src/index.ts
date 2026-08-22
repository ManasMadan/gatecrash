/**
 * A gatecrash integration, in the smallest form that is still honest about the hard parts.
 *
 * This one appends every admission to a file as NDJSON. That is deliberately dull — the
 * interesting content is the three problems any integration has to solve, which are
 * marked below and which have nothing to do with what you eventually do with the event:
 *
 *   1. Resuming. The box numbers every redemption. Reconnect without a sequence and you
 *      miss whatever happened while you were away.
 *   2. Duplicates. Resuming replays, so at-least-once is what you get. Anything that
 *      writes, charges or opens a barrier has to tolerate seeing an event twice.
 *   3. Refusals are not errors. A denial is the system working. Most of what a gate
 *      emits on a bad night is refusals, and an integration that treats them as faults
 *      pages somebody at 1am about a wristband from last year.
 *
 * Copy this directory, rename it, and replace `handle`.
 */

import type { ScanResult } from 'gatecrash-client'

/** Where the integration left off, so a restart does not miss or re-do the whole event. */
export interface Cursor {
  read(): Promise<number | undefined>
  write(seq: number): Promise<void>
}

export interface IntegrationOptions {
  /** Anything with the shape of the box's event stream. */
  source: EventSource

  /** Called once per admission, at least once. Must tolerate repeats — see below. */
  handle: (result: ScanResult) => Promise<void> | void

  /** Where to remember the last sequence handled. */
  cursor: Cursor

  /** Called for refusals. Optional, because "somebody was turned away" is not an error. */
  onRefusal?: (result: ScanResult) => void

  /** Called when the stream itself fails. EventSource reconnects on its own. */
  onError?: (error: unknown) => void
}

/**
 * Wires an event stream to a handler, with the de-duplication and cursor bookkeeping that
 * every integration needs and that is easy to get subtly wrong.
 *
 * ## Why de-duplication lives here and not in your handler
 *
 * The box guarantees each redemption is committed exactly once — that is the whole point
 * of it, one `INSERT ... ON CONFLICT DO NOTHING`. What it cannot guarantee is that you
 * *see* each one exactly once: you reconnect, you replay from a sequence, and the events
 * either side of the boundary arrive twice. Delivery is at-least-once and no amount of
 * care at the box's end changes that.
 *
 * So the sequence number is the idempotency key, and this function drops anything at or
 * below the highest it has already handled. That turns at-least-once delivery into
 * effectively-once handling for anything whose side effect is idempotent.
 *
 * If your side effect is *not* idempotent — a charge, a printed wristband — the sequence
 * has to reach your own storage and be checked in the same transaction as the effect. A
 * counter in memory is lost on the restart you were trying to survive.
 */
export function run(options: IntegrationOptions): () => void {
  const { source, handle, cursor, onRefusal, onError } = options

  // In memory, and only a fast path. The cursor on disk is the real answer; this exists
  // so the common case does not read a file per event.
  let highest = -1

  const listener = (message: MessageEvent<string>) => {
    void (async () => {
      let result: ScanResult
      try {
        result = JSON.parse(message.data) as ScanResult
      } catch (error) {
        // Unparseable is a bug in one event, not a reason to stop consuming the rest.
        onError?.(error)
        return
      }

      // Refusals first, and never through `handle`. A WRONG_ZONE is the venue's rules
      // working correctly; an integration that writes those to the same place as
      // admissions produces an attendance figure that is wrong in an interesting way.
      if (result.verdict !== 'ADMIT') {
        onRefusal?.(result)
        return
      }

      const seq = result.seq ?? 0
      if (seq <= highest) return

      try {
        await handle(result)
        highest = seq
        // Written after the handler, not before. Crash between the two and the event is
        // replayed, which is the failure this is built to tolerate. The other order
        // loses events instead, and a lost admission is not recoverable from anywhere.
        await cursor.write(seq)
      } catch (error) {
        // Deliberately not advancing the cursor: the event is retried on reconnect.
        onError?.(error)
      }
    })()
  }

  // The box names its events. "redemption" is a scan the engine committed; "denial" is
  // one it refused before a row existed. Both are ScanResult shaped.
  source.addEventListener('redemption', listener as EventListener)
  source.addEventListener('denial', listener as EventListener)
  source.addEventListener('error', () => {
    // Nothing to do. EventSource retries with backoff and replays Last-Event-ID, and
    // reimplementing either is how integrations get a reconnect storm of their own.
    onError?.(new Error('stream interrupted; EventSource will retry'))
  })

  return () => {
    source.removeEventListener('redemption', listener as EventListener)
    source.removeEventListener('denial', listener as EventListener)
    source.close()
  }
}

/**
 * A cursor kept in a file.
 *
 * Enough for a display or a log. Anything whose side effect costs money should keep its
 * cursor in the same store as the effect, so the two commit together — see the note on
 * de-duplication above.
 */
export function fileCursor(path: string): Cursor {
  return {
    async read() {
      const { readFile } = await import('node:fs/promises')
      try {
        const raw = await readFile(path, 'utf8')
        const seq = Number.parseInt(raw.trim(), 10)
        return Number.isFinite(seq) ? seq : undefined
      } catch {
        // No cursor yet: a first run. Returning undefined starts from the live edge
        // rather than replaying the whole event, which is almost always what is wanted
        // — pass an explicit 0 if it is not.
        return undefined
      }
    },
    async write(seq: number) {
      const { writeFile, rename } = await import('node:fs/promises')
      // Written to a temporary file and renamed, so a power cut cannot leave a
      // half-written number that parses as a much earlier sequence.
      await writeFile(`${path}.tmp`, String(seq), 'utf8')
      await rename(`${path}.tmp`, path)
    },
  }
}
