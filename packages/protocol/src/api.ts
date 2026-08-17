/**
 * The box's HTTP API, typed.
 *
 * Hand-written types rather than generated ones. The API is small, it changes with
 * the Go structs in the same commit, and a code generator in the build would mean
 * a scanner that cannot be built without a Go toolchain — which is exactly the
 * kind of thing that stops somebody fixing a UI bug at 6pm on event day.
 *
 * The client below is deliberately thin: fetch, a timeout, and typed responses.
 * Retries and offline queueing live in the scanner, because only the scanner knows
 * which requests are safe to retry — and the answer depends on the idempotency key
 * it minted, not on anything this layer can see.
 */

export type Verdict =
  | 'ADMIT'
  | 'ALREADY_USED'
  | 'INVALID_SIG'
  | 'UNKNOWN_TICKET'
  | 'REVOKED'
  | 'WRONG_EVENT'
  | 'EXPIRED_WINDOW'
  | 'WRONG_ZONE'
  | 'WRONG_DOOR'
  | 'PREREQUISITE_MISSING'
  | 'SCANNER_NOT_AUTHORIZED'
  | 'PASS_LIMIT_REACHED'
  | 'WRONG_DIRECTION'
  | 'DOORS_CLOSED'
  | 'MALFORMED'

/**
 * How the scanner should present a verdict.
 *
 * Three values rather than one per verdict, because the number of verdicts will
 * grow and the number of things a person standing at a gate can usefully
 * distinguish will not. `redirect` is the important one: it is the amber screen for
 * somebody whose ticket is fine and who is in the wrong place, and separating it
 * from `deny` is the single highest-value UX decision in the product.
 */
export type Severity = 'admit' | 'deny' | 'redirect'

export type Direction = 'in' | 'out' | 'both'

export interface SeatRef {
  section?: string
  row?: string
  seat?: string
}

export interface Admission {
  checkpoint: string
  checkpoint_name?: string
  device: string
  occurrence?: number
  direction?: Direction
  hlc: string
  at?: string
  offline?: boolean
}

export interface Redirect {
  checkpoint: string
  name: string
  lane?: string
  zone?: string
}

/** Everything a gate needs to show for one scan. */
export interface ScanResult {
  verdict: Verdict
  severity: Severity
  /** The sentence shown to staff. Written by the box so every gate says the same thing. */
  reason: string

  scan_id: string
  ticket?: string

  checkpoint: string
  checkpoint_name?: string
  device: string

  zone?: string
  zone_name?: string

  /** The big glyphs on the verdict screen: the tier colour and the seat. */
  tier?: string
  tier_name?: string
  tier_colour?: string
  seat?: SeatRef
  seat_label?: string
  section_name?: string

  direction?: Direction
  occurrence?: number
  passes_left?: number

  hlc: string
  seq?: number
  at?: string

  /** The winning admission, when this is a refusal for reuse. */
  previous?: Admission
  /** That admission rendered relative to now, so the gate can show the evidence. */
  ago?: string

  missing?: string[]
  redirect?: Redirect[]

  /**
   * True when this is the replayed result of an earlier scan with the same id.
   * Distinguishing this from ALREADY_USED is the difference between "your Wi-Fi
   * hiccuped" and "this person is reusing a ticket".
   */
  idempotent?: boolean

  /** True when a partition let somebody in twice and the box has now noticed. */
  flagged?: boolean
}

export interface Meta {
  api: string
  version: string
  event: string
  event_id: string
  venue?: string
  timezone?: string
  support?: string
  doors?: string
  curfew?: string
  mode: 'strict' | 'degraded'
  ca_fingerprint?: string
  organizer_fingerprint?: string
  seq: number
  now: string
  gc2_window: number
  rotating: boolean
}

export interface Assignment {
  checkpoint: string
  name: string
  lane?: string
  zone: string
  zone_name: string
  direction: Direction
  policy: 'once' | 're-entry' | 'counted'
  opens_at?: string
  closes_at?: string
}

export interface IncidentKindOption {
  kind: string
  severity: 'info' | 'warning' | 'urgent' | 'emergency'
  alarm: boolean
}

export interface ManifestSync {
  event: string
  event_id: string
  mode: string
  /** Base64 Bloom filter over every valid ticket id. */
  bloom: string
  bloom_bits: number
  bloom_hashes: number
  tickets: number
  /** Ids already admitted at this device's checkpoint. */
  redeemed: string[]
  seq: number
  venue: VenuePlan
  assignments: Assignment[]
  incident_kinds: IncidentKindOption[]
  now: string
  gc2_window: number
}

export interface EnrollResponse {
  device_id: string
  token: string
  name: string
  checkpoints: string[]
  client_certificate?: string
  event: string
  mode: string
  ca_fingerprint?: string
  assignments: Assignment[]
}

/** Venue geometry. Mirrors the Go `venue.Plan`. */
export interface Point {
  x: number
  y: number
}

export interface Zone {
  code: string
  name: string
  kind: string
  parent?: string
  restricted?: boolean
  capacity?: number
  shape?: Point[]
  colour?: string
}

export interface Seat {
  number: string
  kind?: string
  position?: Point
  blocked?: boolean
  note?: string
}

export interface Row {
  label: string
  seats?: Seat[]
  start?: Point
  end?: Point
  curve?: number
  aisle?: string
}

export interface Section {
  code: string
  name: string
  kind: 'seated' | 'standing' | 'table' | 'box'
  zone: string
  rows?: Row[]
  capacity?: number
  shape?: Point[]
  colour?: string
  entrances?: string[]
  node?: string
  view_note?: string
}

export interface Checkpoint {
  code: string
  name: string
  zone: string
  direction: Direction
  policy: 'once' | 're-entry' | 'counted'
  count_limit?: number
  requires?: string[]
  tiers?: string[]
  sections?: string[]
  opens_at?: string
  closes_at?: string
  position?: Point
  node?: string
  lane?: string
}

export interface Tier {
  code: string
  name: string
  zones: string[]
  colour?: string
  priority?: number
}

export interface Amenity {
  id: string
  kind: string
  name: string
  zone: string
  position: Point
  node?: string
  note?: string
  accessible?: boolean
  open_from?: string
  open_to?: string
}

export interface MapNode {
  id: string
  kind: string
  position: Point
  zone?: string
  name?: string
  level?: number
}

export interface MapEdge {
  from: string
  to: string
  kind?: string
  distance?: number
  cost?: number
  one_way?: boolean
  note?: string
}

export interface VenueMap {
  width: number
  height: number
  outline?: Point[]
  stage?: Point[]
  nodes?: MapNode[]
  edges?: MapEdge[]
  metres_per_unit?: number
  north_degrees?: number
}

export interface VenuePlan {
  zones: Zone[]
  sections?: Section[]
  checkpoints: Checkpoint[]
  tiers: Tier[]
  amenities?: Amenity[]
  map?: VenueMap
}

/** Wayfinding. Computed on the box so an usher and the attendee agree. */
export interface RouteLeg {
  from: string
  to: string
  kind: string
  instruction: string
  distance: number
  metres?: number
  level_change?: number
  note?: string
}

export interface Route {
  nodes: string[]
  legs: RouteLeg[]
  distance: number
  metres?: number
  seconds?: number
  step_free: boolean
}

export interface GuidanceStep {
  checkpoint: string
  name: string
  lane?: string
  zone: string
  zone_name: string
  ready: boolean
  missing?: string[]
  closed?: boolean
  opens_at?: string
  position?: Point
  node?: string
  route?: Route
}

export interface Destination {
  section: string
  section_name: string
  seat?: SeatRef
  seat_label?: string
  seat_kind?: string
  view_note?: string
  seat_note?: string
  entrances?: string[]
  position?: Point
  node?: string
  route?: Route
}

export interface Guidance {
  tier: string
  tier_name: string
  colour?: string
  entitled: string[]
  admitted?: string[]
  next: GuidanceStep[]
  later?: GuidanceStep[]
  destination?: Destination
  arrived: boolean
}

export interface TicketView {
  id: string
  tier: string
  tier_name: string
  colour?: string
  seat?: SeatRef
  seat_label?: string
  event: string
  event_id: string
  venue?: string
  support?: string
  doors?: string
  curfew?: string
  revoked?: boolean
  format: 'gc1' | 'gc2' | 'both'
  payload?: string
  guidance?: Guidance
  history?: TicketAdmission[]
  now: string
  gc2_window: number
  install?: { android?: string; ios?: string; why: string }
}

export interface TicketAdmission {
  checkpoint: string
  checkpoint_name: string
  zone: string
  zone_name: string
  direction: Direction
  at: string
}

export interface ClaimResponse {
  secret: string
  ticket_id: string
  event_id: string
  gc2_window: number
  now: string
  window_seconds: number
}

export interface NearbyAmenity {
  amenity: Amenity
  route?: Route
  open: boolean
}

/** Staff signals. */
export interface Incident {
  id: string
  kind: string
  severity: 'info' | 'warning' | 'urgent' | 'emergency'
  status: 'open' | 'acknowledged' | 'assigned' | 'resolved' | 'cancelled'
  checkpoint?: string
  checkpoint_name?: string
  zone?: string
  zone_name?: string
  device?: string
  reporter?: string
  note?: string
  head_count?: number
  queue_rate?: number
  assigned_to?: string
  history: IncidentEvent[]
  raised_hlc: string
  raised_at: string
  seq: number
}

export interface IncidentEvent {
  status: string
  actor: string
  note?: string
  hlc: string
  at: string
}

/** The control room's picture. */
export interface LiveStats {
  inside: number
  issued: number
  scans: number
  denied: number
  verdicts: Record<string, number>
  rate: number
  zones: ZoneStat[]
  gates: GateStat[]
  tiers: TierStat[]
  sections: SectionStat[]
  devices: DeviceStat[]
  at: string
}

export interface ZoneStat {
  code: string
  name: string
  kind: string
  occupied: number
  capacity?: number
  fill?: number
  over?: boolean
}

export interface GateStat {
  code: string
  name: string
  zone: string
  admitted: number
  denied: number
  rate: number
  trend: number[]
  last_scan?: string
  quiet?: boolean
}

export interface TierStat {
  code: string
  name: string
  colour?: string
  admitted: number
  issued: number
}

export interface SectionStat {
  code: string
  name: string
  zone: string
  admitted: number
  capacity?: number
  fill?: number
}

export interface DeviceStat {
  id: string
  name?: string
  scans: number
  last_seen?: string
  quiet?: boolean
}

export interface DashboardStats {
  live: LiveStats
  incidents: Incident[]
  incident_counts: Record<string, number>
  incident_response: {
    total: number
    acknowledged: number
    resolved: number
    still_open: number
    cancelled: number
    never_acknowledged: number
    unattended: number
    median_ack_seconds: number
    worst_ack_seconds: number
    median_fix_seconds: number
  }
  chain_head: string
  chain_rows: number
  flags: number
  streams: number
  dropped_streams: number
  devices: {
    id: string
    name?: string
    checkpoints: string[]
    revoked?: boolean
    last_seen?: string
  }[]
  pending_codes: number
  certificate_expires?: string
  mode: string
  now: string
}

export interface Announcement {
  id: string
  text: string
  at: string
  zone?: string
  priority?: boolean
}

/** An error the box returned, with a code the client can switch on. */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message)
    this.name = 'ApiError'
  }

  /**
   * True when the request is worth retrying.
   *
   * The distinction matters at a gate: a 503 means the box could not decide and
   * the scanner should try again, while a 403 means it never will and retrying
   * just burns battery.
   */
  get retryable(): boolean {
    return this.status === 0 || this.status === 429 || this.status >= 500
  }
}
