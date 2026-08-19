import { describe, expect, it, vi } from 'vitest'

import { ApiError } from '@/api'
import { Client } from '@/client'

/** A fetch stub that records what it was called with. */
function stubFetch(responder: (url: string, init?: RequestInit) => Response | Promise<Response>): {
  fetch: typeof globalThis.fetch
  calls: { url: string; init?: RequestInit }[]
} {
  const calls: { url: string; init?: RequestInit }[] = []
  const fetch = ((input: string | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.href
    calls.push({ url, init })
    return Promise.resolve(responder(url, init))
  }) as unknown as typeof globalThis.fetch
  return { fetch, calls }
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

describe('@gatecrash/protocol client', () => {
  it('sends the bearer token and parses the response', async () => {
    const { fetch, calls } = stubFetch(() => json({ event: 'Sundown Sessions', api: '1' }))
    const client = new Client({ baseUrl: 'https://10.11.0.1:8443', token: 'device-token', fetch })

    const meta = await client.meta()
    expect(meta.event).toBe('Sundown Sessions')
    expect(calls[0]!.url).toBe('https://10.11.0.1:8443/v1/meta')
    expect((calls[0]!.init!.headers as Record<string, string>).Authorization).toBe(
      'Bearer device-token',
    )
  })

  it('strips a trailing slash from the base URL', async () => {
    // A trailing slash produces double slashes in every path, which some proxies
    // normalise and some do not.
    const { fetch, calls } = stubFetch(() => json({}))
    const client = new Client({ baseUrl: 'https://10.11.0.1:8443///', fetch })
    await client.meta()
    expect(calls[0]!.url).toBe('https://10.11.0.1:8443/v1/meta')
  })

  it('turns the box error shape into a typed error', async () => {
    const { fetch } = stubFetch(() =>
      json({ code: 'not_assigned', message: 'Not your gate.' }, 403),
    )
    const client = new Client({ baseUrl: 'https://box', token: 't', fetch })

    await expect(client.scan({ scan_id: 'x', payload: 'y' })).rejects.toMatchObject({
      status: 403,
      code: 'not_assigned',
      message: 'Not your gate.',
    })
  })

  // The distinction matters at a gate: a 503 means the box could not decide and the
  // scanner should try again, while a 403 means it never will and retrying just
  // burns battery.
  it('marks the right errors as retryable', () => {
    const cases: [number, boolean][] = [
      [0, true],
      [429, true],
      [500, true],
      [503, true],
      [400, false],
      [401, false],
      [403, false],
      [404, false],
      [409, false],
    ]
    for (const [status, retryable] of cases) {
      expect(new ApiError(status, 'x', 'y').retryable, `status ${status}`).toBe(retryable)
    }
  })

  it('reports an unreachable box as retryable rather than as a crash', async () => {
    const fetch = (() =>
      Promise.reject(new TypeError('Failed to fetch'))) as unknown as typeof globalThis.fetch
    const client = new Client({ baseUrl: 'https://box', fetch })

    const error = await client.meta().catch((caught: unknown) => caught)
    expect(error).toBeInstanceOf(ApiError)
    expect((error as ApiError).status).toBe(0)
    expect((error as ApiError).retryable).toBe(true)
  })

  it('gives up rather than holding a socket open for a phone stack timeout', async () => {
    // A phone on a saturated venue Wi-Fi will hold a socket for thirty seconds
    // before its own stack gives up, and thirty seconds at a gate is a queue.
    vi.useFakeTimers()
    const fetch = ((_input: string, init?: RequestInit) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () =>
          reject(new DOMException('aborted', 'AbortError')),
        )
      })) as unknown as typeof globalThis.fetch

    const client = new Client({ baseUrl: 'https://box', fetch, timeoutMillis: 100 })
    const pending = client.meta().catch((caught: unknown) => caught)
    await vi.advanceTimersByTimeAsync(150)

    const error = await pending
    expect(error).toBeInstanceOf(ApiError)
    expect((error as ApiError).status).toBe(0)
    vi.useRealTimers()
  })

  it('gives the manifest sync a longer deadline than a scan', async () => {
    // The filter for fifty thousand tickets is about 175 KB and this happens once
    // at doors rather than per person, so the scan deadline would be wrong here.
    vi.useFakeTimers()
    let aborted = false
    const fetch = ((_input: string, init?: RequestInit) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => {
          aborted = true
          reject(new DOMException('aborted', 'AbortError'))
        })
      })) as unknown as typeof globalThis.fetch

    const client = new Client({ baseUrl: 'https://box', fetch, timeoutMillis: 100 })
    const pending = client.sync('gate-north').catch(() => undefined)

    await vi.advanceTimersByTimeAsync(500)
    expect(aborted, 'the sync was aborted at the scan deadline').toBe(false)

    await vi.advanceTimersByTimeAsync(20_000)
    await pending
    expect(aborted).toBe(true)
    vi.useRealTimers()
  })

  it('encodes path parameters', async () => {
    // Ticket ids are opaque and a checkpoint code comes from a manifest somebody
    // else wrote.
    const { fetch, calls } = stubFetch(() => json({}))
    const client = new Client({ baseUrl: 'https://box', fetch })
    await client.ticket('a/b c')
    expect(calls[0]!.url).toBe('https://box/v1/ticket/a%2Fb%20c')
  })

  it('builds the nearest-amenities query', async () => {
    const { fetch, calls } = stubFetch(() => json([]))
    const client = new Client({ baseUrl: 'https://box', fetch })
    await client.nearby('TICKET', {
      from: 'n-concourse',
      kinds: ['washroom', 'water'],
      accessible: true,
      stepFree: true,
      limit: 3,
    })

    const url = new URL(calls[0]!.url)
    expect(url.pathname).toBe('/v1/ticket/TICKET/nearby')
    expect(url.searchParams.getAll('kind')).toEqual(['washroom', 'water'])
    expect(url.searchParams.get('accessible')).toBe('1')
    expect(url.searchParams.get('step_free')).toBe('1')
    expect(url.searchParams.get('limit')).toBe('3')
  })

  it('handles an empty body', async () => {
    const { fetch } = stubFetch(() => new Response('', { status: 200 }))
    const client = new Client({ baseUrl: 'https://box', fetch })
    await expect(client.revokeDevice('dev-1')).resolves.toBeUndefined()
  })

  it('falls back to the status when a proxy swallowed the error body', async () => {
    const { fetch } = stubFetch(
      () => new Response('<html>502</html>', { status: 502, statusText: 'Bad Gateway' }),
    )
    const client = new Client({ baseUrl: 'https://box', fetch })

    const error = await client.meta().catch((caught: unknown) => caught)
    expect((error as ApiError).status).toBe(502)
    expect((error as ApiError).message).toContain('Bad Gateway')
  })
})
