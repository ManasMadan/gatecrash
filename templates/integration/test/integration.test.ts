import { describe, expect, it, vi } from 'vitest'
import { run, type Cursor } from '../src/index'

/**
 * A stand-in for the box's stream.
 *
 * Hand-rolled rather than mocked, because what these tests are about is the sequence of
 * events across a reconnect, and that is exactly what a mock would paper over.
 *
 * Not declared as implementing EventSource: its `addEventListener` overloads are keyed on
 * the DOM event map, and satisfying them exactly costs more than the cast at each call
 * site is worth.
 */
class FakeSource {
  private listeners = new Map<string, Set<EventListener>>()
  closed = false

  addEventListener(type: string, listener: EventListener) {
    const existing = this.listeners.get(type)
    if (existing) existing.add(listener)
    else this.listeners.set(type, new Set([listener]))
  }

  removeEventListener(type: string, listener: EventListener) {
    this.listeners.get(type)?.delete(listener)
  }

  close() {
    this.closed = true
  }

  emit(type: string, data: unknown) {
    const event = { data: JSON.stringify(data) } as unknown as Event
    for (const listener of this.listeners.get(type) ?? []) {
      listener(event)
    }
  }
}

const memoryCursor = (): Cursor & { value?: number } => {
  const state: { value?: number } = {}
  return {
    // Promise.resolve rather than `async`: the Cursor contract is promise-returning, and
    // an async function with nothing to await is a lint error for a good reason.
    read: () => Promise.resolve(state.value),
    write: (seq: number) => {
      state.value = seq
      return Promise.resolve()
    },
    get value() {
      return state.value
    },
  }
}

const admission = (seq: number) => ({
  verdict: 'ADMIT',
  severity: 'ok',
  reason: 'in you go',
  scan_id: `scan-${seq}`,
  checkpoint: 'gate-north',
  device: 'phone-1',
  seq,
})

const flush = () => new Promise((resolve) => setTimeout(resolve, 0))

describe('an integration', () => {
  it('handles each admission once', async () => {
    const source = new FakeSource()
    const handle = vi.fn()
    run({ source: source as unknown as EventSource, handle, cursor: memoryCursor() })

    source.emit('redemption', admission(1))
    source.emit('redemption', admission(2))
    await flush()

    expect(handle).toHaveBeenCalledTimes(2)
  })

  it('drops the replay a reconnect causes', async () => {
    // The property that matters. Resuming from a sequence replays the events either side
    // of the boundary, so delivery is at-least-once no matter how careful the box is.
    // An integration that charges a card or prints a wristband per event has to survive
    // exactly this.
    const source = new FakeSource()
    const handle = vi.fn()
    run({ source: source as unknown as EventSource, handle, cursor: memoryCursor() })

    source.emit('redemption', admission(1))
    source.emit('redemption', admission(2))
    await flush()
    source.emit('redemption', admission(2)) // the replay
    source.emit('redemption', admission(1)) // and an older one
    await flush()

    expect(handle).toHaveBeenCalledTimes(2)
  })

  it('does not treat a refusal as an admission', async () => {
    const source = new FakeSource()
    const handle = vi.fn()
    const onRefusal = vi.fn()
    run({
      source: source as unknown as EventSource,
      handle,
      cursor: memoryCursor(),
      onRefusal,
    })

    source.emit('denial', { ...admission(1), verdict: 'ALREADY_USED', severity: 'refuse' })
    await flush()

    // A refusal is the system working. Counting it as attendance is how a turnout figure
    // ends up wrong in a way nobody notices until settlement.
    expect(handle).not.toHaveBeenCalled()
    expect(onRefusal).toHaveBeenCalledTimes(1)
  })

  it('does not advance the cursor past an event that threw', async () => {
    const source = new FakeSource()
    const cursor = memoryCursor()
    const handle = vi.fn().mockRejectedValueOnce(new Error('disk full'))
    const onError = vi.fn()
    run({ source: source as unknown as EventSource, handle, cursor, onError })

    source.emit('redemption', admission(7))
    await flush()

    // Left where it was, so the event is retried on reconnect. Advancing here would
    // lose an admission, and a lost admission cannot be recovered from anywhere.
    expect(cursor.value).toBeUndefined()
    expect(onError).toHaveBeenCalledTimes(1)
  })

  it('stops listening when told to', async () => {
    const source = new FakeSource()
    const handle = vi.fn()
    const stop = run({ source: source as unknown as EventSource, handle, cursor: memoryCursor() })

    stop()
    source.emit('redemption', admission(1))
    await flush()

    expect(handle).not.toHaveBeenCalled()
    expect(source.closed).toBe(true)
  })
})
