import { ApiError } from '@/api'
import type {
  Announcement,
  ClaimResponse,
  DashboardStats,
  EnrollResponse,
  Guidance,
  Incident,
  ManifestSync,
  Meta,
  NearbyAmenity,
  ScanResult,
  TicketView,
  VenuePlan,
} from '@/api'

/**
 * A thin client for the box.
 *
 * Thin on purpose. It does fetch, a timeout and typed responses; it does not do
 * retries, queueing or caching, because only the caller knows whether a request is
 * safe to repeat — and at a gate the answer depends on the idempotency key the
 * scanner minted, which this layer cannot see.
 *
 * The timeout is the important part. A phone on a saturated venue Wi-Fi will hold
 * a socket open for thirty seconds before its own stack gives up, and thirty
 * seconds at a gate is a queue. Every call here has a deadline measured against
 * what a person will tolerate rather than what the network might eventually do.
 */

export interface ClientOptions {
  /** The box's base URL, from the enrollment QR or discovery. */
  baseUrl: string

  /** A device token or the organizer's dashboard token. */
  token?: string

  /**
   * Default timeout in milliseconds.
   *
   * Four seconds. The published scan budget is 150ms at the 99th percentile, so
   * anything approaching four seconds is a broken network rather than a slow box,
   * and the right answer is to fall back to the offline mirror rather than keep
   * waiting.
   */
  timeoutMillis?: number

  /** Injected for tests. */
  fetch?: typeof globalThis.fetch
}

const DEFAULT_TIMEOUT = 4_000

export class Client {
  private readonly baseUrl: string
  private readonly timeout: number
  private readonly doFetch: typeof globalThis.fetch
  private token: string | undefined

  constructor(options: ClientOptions) {
    // A trailing slash here produces double slashes in every path, which some
    // proxies normalise and some do not.
    this.baseUrl = options.baseUrl.replace(/\/+$/, '')
    this.token = options.token
    this.timeout = options.timeoutMillis ?? DEFAULT_TIMEOUT
    this.doFetch = options.fetch ?? globalThis.fetch.bind(globalThis)
  }

  /** Replaces the credential, after an enrollment or a token refresh. */
  setToken(token: string | undefined): void {
    this.token = token
  }

  get url(): string {
    return this.baseUrl
  }

  // Public endpoints.

  meta(): Promise<Meta> {
    return this.request('GET', '/v1/meta')
  }

  /** The box's clock, which is the authority for rotating codes. */
  time(
    ownMillis?: number,
  ): Promise<{ now: string; unix_ms: number; gc2_window: number; skew_ms?: number }> {
    const query = ownMillis === undefined ? '' : `?t=${ownMillis}`
    return this.request('GET', `/v1/time${query}`)
  }

  venue(): Promise<{ plan: VenuePlan; fingerprint: string }> {
    return this.request('GET', '/v1/venue')
  }

  announcements(since?: number): Promise<Announcement[]> {
    const query = since === undefined ? '' : `?since=${since}`
    return this.request('GET', `/v1/announcements${query}`)
  }

  // Enrollment. Unauthenticated: the single-use code in the body is the
  // credential, and it arrived on paper.

  enroll(code: string, name: string, publicKey?: string): Promise<EnrollResponse> {
    return this.request('POST', '/v1/enroll', { code, name, public_key: publicKey })
  }

  // Scanner endpoints.

  sync(checkpoint?: string): Promise<ManifestSync> {
    const query = checkpoint ? `?checkpoint=${encodeURIComponent(checkpoint)}` : ''
    // A longer deadline than a scan: the Bloom filter for fifty thousand tickets
    // is about 175 KB, and this happens once at doors rather than per person.
    return this.request('GET', `/v1/manifest${query}`, undefined, 20_000)
  }

  scan(request: {
    scan_id: string
    payload: string
    checkpoint?: string
    direction?: 'in' | 'out'
    hlc?: string
    offline_admitted?: boolean
    observed_at?: string
  }): Promise<ScanResult> {
    return this.request('POST', '/v1/scan', request)
  }

  guidance(ticketId: string, from?: string, stepFree?: boolean): Promise<{ guidance: Guidance }> {
    const params = new URLSearchParams({ ticket: ticketId })
    if (from) params.set('from', from)
    if (stepFree) params.set('step_free', '1')
    return this.request('GET', `/v1/guidance?${params.toString()}`)
  }

  raiseIncident(request: {
    kind: string
    severity?: string
    checkpoint?: string
    note?: string
    head_count?: number
    reporter?: string
    client_id?: string
  }): Promise<Incident> {
    return this.request('POST', '/v1/incidents', request)
  }

  gateIncidents(): Promise<Incident[]> {
    return this.request('GET', '/v1/incidents')
  }

  // Attendee endpoints. Authenticated by knowing a ticket id, which is the only
  // credential an attendee has.

  ticket(id: string, from?: string, stepFree?: boolean): Promise<TicketView> {
    const params = new URLSearchParams()
    if (from) params.set('from', from)
    if (stepFree) params.set('step_free', '1')
    const query = params.size > 0 ? `?${params.toString()}` : ''
    return this.request('GET', `/v1/ticket/${encodeURIComponent(id)}${query}`)
  }

  claim(id: string, device?: string): Promise<ClaimResponse> {
    return this.request('POST', `/v1/ticket/${encodeURIComponent(id)}/claim`, {
      device: device ?? '',
    })
  }

  nearby(
    id: string,
    options: {
      from: string
      kinds?: string[]
      accessible?: boolean
      stepFree?: boolean
      limit?: number
    },
  ): Promise<NearbyAmenity[]> {
    const params = new URLSearchParams({ from: options.from })
    for (const kind of options.kinds ?? []) params.append('kind', kind)
    if (options.accessible) params.set('accessible', '1')
    if (options.stepFree) params.set('step_free', '1')
    if (options.limit) params.set('limit', String(options.limit))
    return this.request('GET', `/v1/ticket/${encodeURIComponent(id)}/nearby?${params.toString()}`)
  }

  // Dashboard endpoints.

  stats(): Promise<DashboardStats> {
    return this.request('GET', '/v1/admin/stats')
  }

  incidents(query?: { live?: boolean; zone?: string; minSeverity?: string }): Promise<Incident[]> {
    const params = new URLSearchParams()
    if (query?.live) params.set('live', '1')
    if (query?.zone) params.set('zone', query.zone)
    if (query?.minSeverity) params.set('min_severity', query.minSeverity)
    const suffix = params.size > 0 ? `?${params.toString()}` : ''
    return this.request('GET', `/v1/admin/incidents${suffix}`)
  }

  transitionIncident(
    id: string,
    body: { status: string; actor: string; note?: string; assigned_to?: string },
  ): Promise<Incident> {
    return this.request('POST', `/v1/admin/incidents/${encodeURIComponent(id)}`, body)
  }

  invite(body: {
    checkpoints: string[]
    name?: string
    ttl_seconds?: number
    uses?: number
  }): Promise<{
    invite: { code: string; url: string; ca: string; event: string; expires: string }
    qr: string
  }> {
    return this.request('POST', '/v1/admin/invite', body)
  }

  revokeDevice(id: string): Promise<{ revoked: string }> {
    return this.request('POST', `/v1/admin/devices/${encodeURIComponent(id)}/revoke`)
  }

  revokeTicket(id: string): Promise<{ revoked: string }> {
    return this.request('POST', `/v1/admin/tickets/${encodeURIComponent(id)}/revoke`)
  }

  announce(body: { text: string; zone?: string; priority?: boolean }): Promise<Announcement> {
    return this.request('POST', '/v1/admin/announce', body)
  }

  seal(): Promise<{ seq: number; rows: number; root: string; head: string }> {
    return this.request('POST', '/v1/admin/seal', undefined, 30_000)
  }

  verifyChain(): Promise<{ ok: boolean; rows: number; head: string; error?: string }> {
    return this.request('GET', '/v1/admin/verify', undefined, 60_000)
  }

  /**
   * Opens an SSE stream, resuming from a sequence.
   *
   * Returns the raw EventSource so the caller owns reconnection. EventSource
   * already retries with backoff and replays `Last-Event-ID` for free, and
   * wrapping it would mean reimplementing both.
   *
   * The token rides in the query string because EventSource cannot set headers.
   * That is a real trade — a token in a URL can end up in a log — and it is why the
   * box logs paths without query strings and why device tokens are cheap to
   * revoke.
   */
  stream(path: string, from?: number): EventSource {
    const url = new URL(this.baseUrl + path)
    if (from !== undefined) url.searchParams.set('from', String(from))
    if (this.token) url.searchParams.set('token', this.token)
    return new EventSource(url.toString())
  }

  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
    timeout?: number,
  ): Promise<T> {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), timeout ?? this.timeout)

    try {
      const headers: Record<string, string> = {}
      if (this.token) headers.Authorization = `Bearer ${this.token}`
      if (body !== undefined) headers['Content-Type'] = 'application/json'

      const response = await this.doFetch(this.baseUrl + path, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: controller.signal,
      })

      const text = await response.text()
      if (!response.ok) {
        // The box always returns a code and a message; falling back to the status
        // text keeps this honest against a proxy that swallowed the body.
        let code = 'http_error'
        let message = response.statusText || `HTTP ${response.status}`
        try {
          const parsed = JSON.parse(text) as { code?: string; message?: string }
          if (parsed.code) code = parsed.code
          if (parsed.message) message = parsed.message
        } catch {
          // Not JSON. The status is still useful.
        }
        throw new ApiError(response.status, code, message)
      }
      return (text.length > 0 ? JSON.parse(text) : undefined) as T
    } catch (error) {
      if (error instanceof ApiError) throw error
      // A network failure and an abort are the same thing to the caller: the box
      // could not be reached. Status 0 marks it as retryable.
      const message = error instanceof Error ? error.message : String(error)
      throw new ApiError(0, 'unreachable', message)
    } finally {
      clearTimeout(timer)
    }
  }
}
