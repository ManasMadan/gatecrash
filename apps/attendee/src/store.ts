import { generateRotating, parsePayload } from 'gatecrash-client'
import type { TicketView, VenuePlan } from 'gatecrash-client'

/**
 * The wallet's local state.
 *
 * The design goal is that the app works with the phone in aeroplane mode. Once a
 * ticket has been opened and claimed, everything needed to get through a gate is on
 * the device: the ticket secret, the venue map, the last known guidance. The network
 * is used to refresh, never to function.
 *
 * That matters more here than anywhere else in the product. The scanner is on the
 * venue's own Wi-Fi by definition; an attendee is on a saturated cell network in a
 * field, and "open your ticket" cannot mean "wait for a request".
 */

const PREFIX = 'gatecrash.ticket.'

/** What is cached for one ticket. */
export interface Cached {
  ticketId: string
  /** The ticket as the box last described it. */
  view: TicketView
  /**
   * The per-ticket secret, base64, for a rotating ticket.
   *
   * Held in localStorage, which is honest about what it is: readable by anything
   * with access to the browser profile on this phone. That is the same exposure as
   * the emailed PDF this replaces, and the rotation is what limits the damage —
   * a stolen secret still only produces a code that dies in sixty seconds and that
   * the compare-and-set catches on second use.
   */
  secret?: string
  /** The box's clock minus ours at claim time, so codes stay valid on a wrong phone. */
  clockOffsetMillis: number
  cachedAt: string
}

export interface CachedVenue {
  plan: VenuePlan
  fingerprint: string
  cachedAt: string
}

function read<T>(key: string): T | null {
  try {
    const raw = localStorage.getItem(PREFIX + key)
    return raw === null ? null : (JSON.parse(raw) as T)
  } catch {
    return null
  }
}

function write(key: string, value: unknown): void {
  try {
    localStorage.setItem(PREFIX + key, JSON.stringify(value))
  } catch {
    // Private browsing, or storage full. The app still works for this session; it
    // just will not survive being closed, and the offline note says so.
  }
}

/** The ticket ids this phone has opened, most recent first. */
export function knownTickets(): string[] {
  return read<string[]>('known') ?? []
}

function remember(ticketId: string): void {
  const known = [ticketId, ...knownTickets().filter((id) => id !== ticketId)]
  // Several tickets on one phone is the normal case: somebody buys four and their
  // friends never install anything. Ten is more than anybody carries.
  write('known', known.slice(0, 10))
}

export function loadTicket(ticketId: string): Cached | null {
  return read<Cached>(`t.${ticketId}`)
}

export function saveTicket(cached: Cached): void {
  write(`t.${cached.ticketId}`, cached)
  remember(cached.ticketId)
}

export function forgetTicket(ticketId: string): void {
  try {
    localStorage.removeItem(`${PREFIX}t.${ticketId}`)
  } catch {
    // Ignored.
  }
  write(
    'known',
    knownTickets().filter((id) => id !== ticketId),
  )
}

export function loadVenue(): CachedVenue | null {
  return read<CachedVenue>('venue')
}

export function saveVenue(venue: CachedVenue): void {
  write('venue', venue)
}

/**
 * The QR payload to draw right now.
 *
 * For a printed ticket this is the payload the box issued, unchanged. For a rotating
 * ticket it is generated here, on the phone, with no network at all — which is the
 * whole point of claiming the secret once.
 *
 * The clock offset is what makes that work on a phone whose clock is wrong. The box's
 * absolute time may also be wrong; what matters is that the two agree, and the offset
 * is measured at claim time and applied on every generation.
 */
export async function currentPayload(cached: Cached): Promise<string | null> {
  if (cached.view.format !== 'gc2') {
    return cached.view.payload ?? null
  }
  if (!cached.secret) return null

  const secret = base64ToBytes(cached.secret)
  if (!secret) return null

  const boxMillis = Date.now() + cached.clockOffsetMillis
  const window = Math.floor(boxMillis / 1000 / 30)

  return generateRotating(secret, cached.view.event_id, cached.view.id, window)
}

/** Milliseconds until the drawn code changes, for the countdown. */
export function millisUntilRotation(cached: Cached): number {
  const boxMillis = Date.now() + cached.clockOffsetMillis
  return 30_000 - (boxMillis % 30_000)
}

/**
 * Extracts a ticket id from whatever somebody pasted or scanned.
 *
 * People arrive here by opening a link from an email, by scanning a QR from a
 * friend's screen, or by typing an id off a printout. All three should work, because
 * the alternative is somebody standing outside a venue unable to open their ticket.
 */
export function extractTicketId(input: string): string | null {
  const text = input.trim()
  if (!text) return null

  // A full ticket payload, scanned from a printed ticket.
  const parsed = parsePayload(text)
  if (parsed.format !== 'unknown') return parsed.ticketId

  // A link, from an email or a message.
  const fromUrl = /\/t\/([A-Za-z2-7]{26}|[0-9a-fA-F]{32})/.exec(text)
  if (fromUrl?.[1]) return fromUrl[1].toUpperCase()

  // A bare id, typed or pasted.
  const bare = /^([A-Za-z2-7]{26}|[0-9a-fA-F]{32})$/.exec(text)
  if (bare?.[1]) return bare[1].toUpperCase()

  return null
}

function base64ToBytes(text: string): Uint8Array | null {
  try {
    const binary = atob(text)
    const bytes = new Uint8Array(binary.length)
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
    return bytes
  } catch {
    return null
  }
}

/**
 * The ticket id in the URL fragment.
 *
 * A fragment rather than a path, for one specific reason: a fragment is never sent
 * to a server, never lands in an access log, and never appears in a Referer header.
 * A ticket id is the only credential an attendee has, and putting it in a path would
 * scatter it across every log between the phone and the box.
 */
export function ticketIdFromLocation(): string | null {
  const hash = window.location.hash.replace(/^#\/?/, '')
  const match = /^t\/(.+)$/.exec(hash)
  return match?.[1] ? extractTicketId(match[1]) : null
}

export function setTicketInLocation(ticketId: string): void {
  window.location.hash = `#/t/${ticketId}`
}
