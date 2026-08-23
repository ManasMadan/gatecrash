import { BloomFilter, Client, parsePayload } from 'gatecrash-client'
import type {
  Assignment,
  IncidentKindOption,
  ManifestSync,
  ScanResult,
  VenuePlan,
} from 'gatecrash-client'

/**
 * The scanner's local state and its offline behaviour.
 *
 * This is where the product's hardest promise lives: a gate keeps working when the
 * box does not. The mechanism is three things held on the device —
 *
 *   1. a Bloom filter over every valid ticket id, so a garbage QR is refused with
 *      no network at all;
 *   2. a mirror of which ids have already been admitted at this gate, so reuse is
 *      spotted before the box answers;
 *   3. a durable queue of scans that have not been acknowledged, drained with
 *      backoff when the network returns.
 *
 * Everything durable goes in localStorage rather than IndexedDB. That is a
 * deliberate downgrade: IndexedDB is the right tool for tens of thousands of rows,
 * but it is asynchronous, it has a transaction model that is easy to get subtly
 * wrong, and on the Android WebView builds this has to run on it has a history of
 * silently failing under storage pressure. The queue is at most a few hundred scans
 * — a gate that has been offline long enough to exceed that has a bigger problem —
 * and a synchronous write that either works or throws is worth more here than
 * capacity nobody will use.
 */

const STORAGE_PREFIX = 'gatecrash.scanner.'

const KEY_ENROLLMENT = `${STORAGE_PREFIX}enrollment`
const KEY_QUEUE = `${STORAGE_PREFIX}queue`
const KEY_MIRROR = `${STORAGE_PREFIX}mirror`
const KEY_SETTINGS = `${STORAGE_PREFIX}settings`

/** What the enrollment ceremony left behind. */
export interface Enrollment {
  boxUrl: string
  token: string
  deviceId: string
  deviceName: string
  event: string
  mode: string
  checkpoints: string[]
  assignments: Assignment[]
  /** The gate this device is currently working, when it covers several. */
  activeCheckpoint: string
  caFingerprint?: string
}

/** A scan waiting to be acknowledged by the box. */
export interface QueuedScan {
  scanId: string
  payload: string
  checkpoint: string
  direction?: 'in' | 'out'
  observedAt: string
  /** True when the scanner let this person through on its own mirror. */
  offlineAdmitted: boolean
  attempts: number
  /** The verdict the scanner showed, so the log can be reconciled afterwards. */
  localVerdict: string
}

/** The redeemed-set mirror for one checkpoint. */
interface Mirror {
  checkpoint: string
  seq: number
  /** Base32 ticket ids already admitted here. */
  redeemed: string[]
  bloom: string
  tickets: number
  venue: VenuePlan | null
  incidentKinds: IncidentKindOption[]
  /** The box's clock at sync time, and ours, so drift can be reported. */
  boxNow: string
  syncedAt: string
}

export interface Settings {
  sound: boolean
  haptics: boolean
  volume: number
  /** Gun mode: a USB barcode reader types into a field instead of using the camera. */
  gunMode: boolean
  /** The staff member's name, attached to any incident they raise. */
  reporter: string
  /** In DEGRADED mode, whether this gate admits during a partition. */
  admitOffline: boolean
}

export const defaultSettings: Settings = {
  sound: true,
  haptics: true,
  volume: 0.9,
  gunMode: false,
  reporter: '',
  admitOffline: false,
}

/** Reads a JSON value from localStorage, returning null on anything unusable. */
function read<T>(key: string): T | null {
  try {
    const raw = localStorage.getItem(key)
    return raw === null ? null : (JSON.parse(raw) as T)
  } catch {
    // A corrupt entry is treated as absent. Throwing here would mean a scanner
    // that will not start, which is worse than one that has to re-sync.
    return null
  }
}

function write(key: string, value: unknown): void {
  try {
    localStorage.setItem(key, JSON.stringify(value))
  } catch {
    // Storage full or blocked. The scanner keeps working in memory; the durability
    // is what is lost, and the diagnostics screen shows it.
  }
}

export function loadEnrollment(): Enrollment | null {
  return read<Enrollment>(KEY_ENROLLMENT)
}

export function saveEnrollment(enrollment: Enrollment): void {
  write(KEY_ENROLLMENT, enrollment)
}

export function clearEnrollment(): void {
  // Everything, not just the token: a device being handed to a different gate must
  // not carry the previous gate's mirror, or it will warn about reuse for tickets
  // that were admitted somewhere else.
  for (const key of [KEY_ENROLLMENT, KEY_QUEUE, KEY_MIRROR]) {
    try {
      localStorage.removeItem(key)
    } catch {
      // Ignored.
    }
  }
}

export function loadSettings(): Settings {
  return { ...defaultSettings, ...(read<Partial<Settings>>(KEY_SETTINGS) ?? {}) }
}

export function saveSettings(settings: Settings): void {
  write(KEY_SETTINGS, settings)
}

/**
 * The scanner's offline mirror.
 *
 * Holds the Bloom filter, the redeemed set for this gate, and the venue plan the
 * scanner needs to name the door it is sending somebody to. Parsed once on load
 * because parsing a 175 KB filter per scan would show up in the latency budget.
 */
export class Mirrors {
  private filter: BloomFilter | null = null
  private redeemed = new Set<string>()
  private state: Mirror | null = null

  static load(): Mirrors {
    const mirrors = new Mirrors()
    const stored = read<Mirror>(KEY_MIRROR)
    if (stored) mirrors.adopt(stored)
    return mirrors
  }

  /** Replaces the mirror from a fresh sync. */
  replace(sync: ManifestSync, checkpoint: string): void {
    const state: Mirror = {
      checkpoint,
      seq: sync.seq,
      redeemed: sync.redeemed,
      bloom: sync.bloom,
      tickets: sync.tickets,
      venue: sync.venue,
      incidentKinds: sync.incident_kinds,
      boxNow: sync.now,
      syncedAt: new Date().toISOString(),
    }
    this.adopt(state)
    write(KEY_MIRROR, state)
  }

  private adopt(state: Mirror): void {
    this.state = state
    this.redeemed = new Set(state.redeemed)
    this.filter = parseFilter(state.bloom)
  }

  get synced(): boolean {
    return this.state !== null
  }

  get seq(): number {
    return this.state?.seq ?? 0
  }

  get checkpoint(): string {
    return this.state?.checkpoint ?? ''
  }

  get ticketCount(): number {
    return this.state?.tickets ?? 0
  }

  get venue(): VenuePlan | null {
    return this.state?.venue ?? null
  }

  get incidentKinds(): IncidentKindOption[] {
    return this.state?.incidentKinds ?? []
  }

  get syncedAt(): string | null {
    return this.state?.syncedAt ?? null
  }

  get filterBytes(): number {
    return this.filter?.stats().bytes ?? 0
  }

  /**
   * Records an admission the box confirmed, so the mirror stays current between
   * syncs.
   */
  observe(ticketId: string, seq: number): void {
    this.redeemed.add(ticketId.toUpperCase())
    if (this.state) {
      this.state.redeemed = [...this.redeemed]
      if (seq > this.state.seq) this.state.seq = seq
      write(KEY_MIRROR, this.state)
    }
  }

  /**
   * Decides what the scanner can say about a payload without the box.
   *
   * The three answers are the whole point. `unknown` and `used` are decided
   * locally and are definitive enough to act on; `ask` means the device does not
   * know and the box must be consulted, which is the normal case.
   */
  judge(payload: string): 'unknown' | 'used' | 'ask' | 'malformed' {
    const parsed = parsePayload(payload)
    if (parsed.format === 'unknown') return 'malformed'

    // A Bloom filter has no false negatives, so a miss is certain: this id was
    // never issued for this event. That is what makes a garbage-QR flood free.
    if (this.filter && !this.filter.testBase32(parsed.ticketId)) return 'unknown'

    // The mirror can be stale — it only knows what it has been told — so a hit is a
    // strong hint rather than proof. The box is still the authority when it can be
    // reached; this is what lets the scanner warn instantly, and what powers
    // DEGRADED mode when it cannot.
    if (this.redeemed.has(parsed.ticketId)) return 'used'

    return 'ask'
  }
}

function parseFilter(base64: string): BloomFilter | null {
  try {
    const binary = atob(base64)
    const bytes = new Uint8Array(binary.length)
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
    return BloomFilter.parse(bytes)
  } catch {
    return null
  }
}

/**
 * The durable scan queue.
 *
 * A scan enters the queue before it is sent and leaves it when the box
 * acknowledges. That ordering is what makes the guarantee hold across a browser
 * being killed mid-request: the scan is either in the queue or acknowledged, never
 * neither.
 */
export class Queue {
  private items: QueuedScan[]

  private constructor(items: QueuedScan[]) {
    this.items = items
  }

  static load(): Queue {
    return new Queue(read<QueuedScan[]>(KEY_QUEUE) ?? [])
  }

  get length(): number {
    return this.items.length
  }

  get all(): readonly QueuedScan[] {
    return this.items
  }

  /** How many queued scans let somebody in on the scanner's own decision. */
  get offlineAdmissions(): number {
    return this.items.filter((item) => item.offlineAdmitted).length
  }

  add(scan: QueuedScan): void {
    this.items.push(scan)
    // A cap, because a scanner that has been offline for hours should stop growing
    // rather than fill its storage and start failing writes. Dropping the oldest
    // is the least-bad choice: the newest scans are the ones somebody is still
    // standing in front of.
    if (this.items.length > 2_000) this.items = this.items.slice(-2_000)
    this.flush()
  }

  remove(scanId: string): void {
    this.items = this.items.filter((item) => item.scanId !== scanId)
    this.flush()
  }

  markAttempt(scanId: string): void {
    const found = this.items.find((item) => item.scanId === scanId)
    if (found) {
      found.attempts++
      this.flush()
    }
  }

  next(): QueuedScan | undefined {
    return this.items[0]
  }

  clear(): void {
    this.items = []
    this.flush()
  }

  private flush(): void {
    write(KEY_QUEUE, this.items)
  }
}

/** A scan id: a random 128-bit value in hex, which is what the API takes. */
export function newScanId(): string {
  const bytes = new Uint8Array(16)
  crypto.getRandomValues(bytes)
  return [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('')
}

/** Builds a client for an enrolled device. */
export function clientFor(enrollment: Enrollment): Client {
  return new Client({ baseUrl: enrollment.boxUrl, token: enrollment.token })
}

/**
 * A locally-decided verdict, shaped like the box's so one screen renders both.
 *
 * Marked `offline` by the caller so staff can always tell a local decision from the
 * box's — which matters, because a local ADMIT in DEGRADED mode is a claim the box
 * has not yet agreed with.
 */
export function localVerdict(
  scanId: string,
  checkpoint: string,
  device: string,
  verdict: string,
  reason: string,
  severity: 'admit' | 'deny' | 'redirect',
): ScanResult {
  return {
    verdict: verdict as ScanResult['verdict'],
    severity,
    reason,
    scan_id: scanId,
    checkpoint,
    device,
    hlc: '0.0',
  }
}
