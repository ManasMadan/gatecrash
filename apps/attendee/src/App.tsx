import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import QRCode from 'qrcode'
import { ApiError, Client } from 'gatecrash-client'
import type {
  Announcement,
  BackstageLinks,
  Destination,
  NearbyAmenity,
  TicketView,
} from 'gatecrash-client'
import { VenueMap } from 'gatecrash-ui'

import {
  currentPayload,
  extractTicketId,
  forgetTicket,
  knownTickets,
  loadTicket,
  loadVenue,
  millisUntilRotation,
  saveTicket,
  saveVenue,
  setTicketInLocation,
  ticketIdFromLocation,
  type Cached,
} from '@/store'

/**
 * The attendee wallet.
 *
 * Answers three questions and gets out of the way: what is my ticket, where do I go,
 * and where is the nearest toilet. Everything is cached, so it works with the phone
 * in aeroplane mode after the first load — which matters because an attendee is on a
 * saturated cell network in a field, not on the venue's own Wi-Fi.
 */
export function App() {
  const [ticketId, setTicketId] = useState<string | null>(() => ticketIdFromLocation())

  // The box is wherever this page was served from. No configuration, because the
  // attendee reached this page by opening a link the box handed out.
  const client = useMemo(() => new Client({ baseUrl: window.location.origin }), [])

  useEffect(() => {
    const onHash = () => setTicketId(ticketIdFromLocation())
    window.addEventListener('hashchange', onHash)
    return () => window.removeEventListener('hashchange', onHash)
  }, [])

  if (!ticketId) return <Landing client={client} onTicket={setTicketId} />
  return <Wallet client={client} ticketId={ticketId} onForget={() => setTicketId(null)} />
}

/** Getting to a ticket, for somebody who arrived without a link. */
function Landing({ client, onTicket }: { client: Client; onTicket: (id: string) => void }) {
  const [input, setInput] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [event, setEvent] = useState<string | null>(null)
  const known = knownTickets()

  useEffect(() => {
    client
      .meta()
      .then((meta) => setEvent(meta.event))
      .catch(() => setEvent(null))
  }, [client])

  const open = (raw: string) => {
    const id = extractTicketId(raw)
    if (!id) {
      setError(
        'That does not look like a ticket. Check the link in your email, or ask at the info tent.',
      )
      return
    }
    setTicketInLocation(id)
    onTicket(id)
  }

  return (
    <div className="wallet">
      <div className="masthead">
        <h1>{event ?? 'Your ticket'}</h1>
      </div>

      {known.length > 0 ? (
        <div className="card">
          <h2>On this phone</h2>
          {known.map((id) => {
            const cached = loadTicket(id)
            return (
              <button key={id} type="button" className="amenity" onClick={() => open(id)}>
                <span className="amenity__glyph" aria-hidden="true">
                  🎟
                </span>
                <span className="amenity__what">
                  <span className="amenity__name">{cached?.view.tier_name ?? 'Ticket'}</span>
                  <span className="amenity__detail">
                    {cached?.view.seat_label ?? id.slice(0, 8)}
                  </span>
                </span>
              </button>
            )
          })}
        </div>
      ) : null}

      <div className="card">
        <h2>Open a ticket</h2>
        <p className="muted" style={{ marginTop: 0 }}>
          Paste the link from your email, or type the code printed on your ticket.
        </p>
        {error ? <div className="error">{error}</div> : null}
        <div className="field" style={{ marginTop: 'var(--gc-gap)' }}>
          <label htmlFor="ticket">Ticket link or code</label>
          <input
            id="ticket"
            value={input}
            onChange={(changed) => setInput(changed.target.value)}
            placeholder="GTNA4OA55FXIBGKBLOVYM36YO4"
            autoComplete="off"
            autoCapitalize="characters"
            spellCheck={false}
          />
        </div>
        <button
          type="button"
          className="button"
          style={{ marginTop: 'var(--gc-gap)' }}
          onClick={() => open(input)}
        >
          Open
        </button>
      </div>
    </div>
  )
}

/** The ticket itself. */
function Wallet({
  client,
  ticketId,
  onForget,
}: {
  client: Client
  ticketId: string
  onForget: () => void
}) {
  // Cached first, network second. The screen paints from storage immediately and
  // refreshes underneath, which is what makes opening a ticket in a queue instant.
  const [cached, setCached] = useState<Cached | null>(() => loadTicket(ticketId))
  const [error, setError] = useState<string | null>(null)
  const [stale, setStale] = useState(false)
  const [venue, setVenue] = useState(() => loadVenue())
  const [announcements, setAnnouncements] = useState<Announcement[]>([])
  const [nearby, setNearby] = useState<NearbyAmenity[] | null>(null)
  const [amenityKind, setAmenityKind] = useState<string | null>(null)
  const [stepFree, setStepFree] = useState(false)
  const [backstage, setBackstage] = useState<BackstageLinks | null>(null)

  const refresh = useCallback(async () => {
    try {
      // The position is the last gate this ticket came through, which is the best
      // guess anybody has: there is no GPS indoors and the box has no idea where a
      // phone is beyond where it last scanned.
      const from = lastNode(cached?.view)
      const view = await client.ticket(ticketId, from, stepFree)
      const previous = loadTicket(ticketId)
      const next: Cached = {
        ticketId,
        view,
        ...(previous?.secret ? { secret: previous.secret } : {}),
        clockOffsetMillis: previous?.clockOffsetMillis ?? new Date(view.now).getTime() - Date.now(),
        cachedAt: new Date().toISOString(),
      }
      saveTicket(next)
      setCached(next)
      setStale(false)
      setError(null)

      // Claim on first sight for a rotating ticket. There is nothing to decide: the
      // secret is derived, claiming twice returns the same one, and a phone that
      // has not claimed cannot draw a code at all.
      if (view.format !== 'gc1' && !next.secret) {
        const claim = await client.claim(ticketId, deviceLabel())
        const claimed: Cached = {
          ...next,
          secret: claim.secret,
          // Measured at claim time: the box's clock is the authority for rotating
          // codes, and this phone's may be minutes out.
          clockOffsetMillis: new Date(claim.now).getTime() - Date.now(),
        }
        saveTicket(claimed)
        setCached(claimed)
      }
    } catch (caught) {
      // Offline is the expected case, not an error. If there is a cached ticket the
      // app carries on and says it is showing a stored copy.
      setStale(true)
      if (!loadTicket(ticketId)) {
        setError(
          caught instanceof ApiError && caught.status === 404
            ? 'That ticket is not for this event. Check the link, or ask at the info tent.'
            : 'Could not reach the venue. Connect to the event Wi-Fi and pull down to refresh.',
        )
      }
    }
  }, [cached?.view, client, stepFree, ticketId])

  useEffect(() => {
    void refresh()
    // Refreshed on an interval rather than on a stream: an attendee's phone should
    // not hold a connection open for an evening, and a minute-stale guidance panel
    // is fine when the ticket itself works offline.
    const timer = setInterval(() => void refresh(), 60_000)
    return () => clearInterval(timer)
    // Deliberately not depending on refresh: it closes over the cached view, and
    // re-running this effect on every refresh would restart the interval each time.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ticketId, stepFree])

  useEffect(() => {
    client
      .venue()
      .then((response) => {
        const next = { ...response, cachedAt: new Date().toISOString() }
        saveVenue(next)
        setVenue(next)
      })
      .catch(() => {
        // The cached plan is what the map draws. A venue plan does not change during
        // an event, so a failure here is invisible after the first load.
      })
  }, [client])

  useEffect(() => {
    client
      .meta()
      // Only the install links. Everything else in /v1/meta is either already on the
      // ticket or is the box talking about itself.
      .then((meta) => setBackstage(meta.backstage ?? null))
      .catch(() => {
        // Offline. The app is not offered rather than offered and broken.
        setBackstage(null)
      })
  }, [client])

  useEffect(() => {
    client
      .announcements()
      .then(setAnnouncements)
      .catch(() => setAnnouncements([]))
    const timer = setInterval(() => {
      client
        .announcements()
        .then(setAnnouncements)
        .catch(() => {})
    }, 30_000)
    return () => clearInterval(timer)
  }, [client])

  const findNearby = useCallback(
    async (kind: string | null) => {
      setAmenityKind(kind)
      const from = lastNode(cached?.view)
      if (!from) {
        setNearby([])
        return
      }
      try {
        setNearby(
          await client.nearby(ticketId, {
            from,
            ...(kind ? { kinds: [kind] } : {}),
            stepFree,
            limit: 6,
          }),
        )
      } catch {
        setNearby([])
      }
    },
    [cached?.view, client, stepFree, ticketId],
  )

  if (error) {
    return (
      <div className="wallet">
        <div className="error">{error}</div>
        <button type="button" className="button" onClick={() => void refresh()}>
          Try again
        </button>
        <button
          type="button"
          className="button button--quiet"
          onClick={() => {
            forgetTicket(ticketId)
            window.location.hash = ''
            onForget()
          }}
        >
          Open a different ticket
        </button>
      </div>
    )
  }

  if (!cached) {
    return (
      <div className="wallet">
        <p className="muted">Opening your ticket…</p>
      </div>
    )
  }

  const view = cached.view
  const guidance = view.guidance
  const destination = guidance?.destination

  return (
    <div className="wallet">
      <div className="masthead">
        <h1>{view.event}</h1>
        {view.venue ? <span className="masthead__venue">{view.venue}</span> : null}
      </div>

      {announcements
        .filter((announcement) => announcement.priority)
        .slice(-2)
        .map((announcement) => (
          <div key={announcement.id} className="announcement" data-priority="true">
            {announcement.text}
            <div className="announcement__when">{clockOf(announcement.at)}</div>
          </div>
        ))}

      <Ticket cached={cached} />

      <Backstage links={backstage} />

      {stale ? (
        <div className="offline-note">
          Showing the copy saved on this phone. Your ticket still works — the code is generated
          here, not fetched.
        </div>
      ) : null}

      {guidance && !guidance.arrived ? (
        <div className="card">
          <h2>Where to go</h2>
          {guidance.next.map((step) => (
            <div key={step.checkpoint} className="step">
              <span className="step__marker" data-state="now">
                →
              </span>
              <span className="step__what">
                <span className="step__name">
                  {step.name}
                  {step.lane ? ` · lane ${step.lane}` : ''}
                </span>
                <span className="step__hint">
                  into {step.zone_name}
                  {step.route?.seconds
                    ? ` · about ${Math.ceil(step.route.seconds / 60)} min walk`
                    : ''}
                </span>
              </span>
            </div>
          ))}
          {(guidance.later ?? []).map((step) => (
            <div key={step.checkpoint} className="step">
              <span className="step__marker" data-state="later">
                ·
              </span>
              <span className="step__what">
                <span className="step__name">{step.name}</span>
                <span className="step__hint">
                  {step.closed
                    ? `opens ${clockOf(step.opens_at ?? '')}`
                    : `after you have been through ${(step.missing ?? []).join(' and ')}`}
                </span>
              </span>
            </div>
          ))}
        </div>
      ) : null}

      {destination ? (
        <div className="card">
          <h2>Your seat</h2>
          <div className="step">
            <span className="step__marker">◎</span>
            <span className="step__what">
              <span className="step__name">{destination.section_name}</span>
              <span className="step__hint">
                {/* The row and the seat only. The section is the line above it, and
                    "Block A / Block A row A seat 1" is the same words twice. */}
                {seatDetail(destination)}
                {destination.view_note ? ` · ${destination.view_note}` : ''}
                {destination.seat_note ? ` · ${destination.seat_note}` : ''}
              </span>
            </span>
          </div>

          {destination.route ? (
            <>
              {/* The route as a list as well as on the map: a map is an image, and a
                  list is something a screen reader can read out and somebody can
                  follow while walking. */}
              <ol className="route">
                {destination.route.legs.map((leg, index) => (
                  <li key={`${leg.from}-${leg.to}-${index}`}>{leg.instruction}</li>
                ))}
              </ol>
              <p className="route__summary">
                {destination.route.metres ? `${Math.round(destination.route.metres)} m` : ''}
                {destination.route.seconds ? ` · about ${destination.route.seconds}s walk` : ''}
                {destination.route.step_free ? ' · step free' : ''}
              </p>
            </>
          ) : null}

          <button
            type="button"
            className="chip"
            aria-pressed={stepFree}
            onClick={() => setStepFree(!stepFree)}
            style={{ marginTop: 'var(--gc-gap)' }}
          >
            ♿ Step-free route
          </button>
        </div>
      ) : null}

      {venue ? (
        <div className="card">
          <h2>Venue</h2>
          <div className="map-frame">
            <VenueMap
              plan={venue.plan}
              {...(view.seat ? { seat: view.seat } : {})}
              {...(destination?.route ? { route: destination.route } : {})}
              {...(lastNode(view) ? { from: lastNode(view)! } : {})}
              {...(guidance ? { allowedZones: guidance.entitled } : {})}
              openCheckpoints={(guidance?.next ?? []).map((step) => step.checkpoint)}
              laterCheckpoints={(guidance?.later ?? []).map((step) => step.checkpoint)}
              highlightAmenities={(nearby ?? []).map((entry) => entry.amenity.id)}
              {...(view.seat?.section ? { focusSection: view.seat.section } : {})}
            />
          </div>
        </div>
      ) : null}

      <div className="card">
        <h2>Find</h2>
        <div className="chips">
          {[
            ['washroom', '🚻 Toilets'],
            ['food', '🍽 Food'],
            ['water', '💧 Water'],
            ['medical', '✚ Medical'],
            ['exit', '🚪 Exits'],
          ].map(([kind, label]) => (
            <button
              key={kind}
              type="button"
              className="chip"
              aria-pressed={amenityKind === kind}
              onClick={() => void findNearby(amenityKind === kind ? null : kind!)}
            >
              {label}
            </button>
          ))}
        </div>

        {nearby === null ? (
          <p className="muted">Tap one to find the nearest.</p>
        ) : nearby.length === 0 ? (
          <p className="muted">
            Nothing found from where you are. Scan in at a gate first, or ask any steward.
          </p>
        ) : (
          nearby.map((entry) => (
            <div key={entry.amenity.id} className="amenity">
              <span className="amenity__glyph" aria-hidden="true">
                {glyphFor(entry.amenity.kind)}
              </span>
              <span className="amenity__what">
                <span className="amenity__name">{entry.amenity.name}</span>
                <span className="amenity__detail">
                  {entry.route?.metres ? `${Math.round(entry.route.metres)} m` : 'nearby'}
                  {entry.route?.seconds ? ` · ${entry.route.seconds}s` : ''}
                  {entry.amenity.accessible ? ' · step free' : ''}
                  {entry.open ? '' : ' · '}
                  {entry.open ? null : <span className="amenity__closed">closed</span>}
                </span>
              </span>
            </div>
          ))
        )}
      </div>

      {announcements.length > 0 ? (
        <div className="card">
          <h2>From the organizer</h2>
          {announcements
            .slice(-6)
            .reverse()
            .map((announcement) => (
              <div
                key={announcement.id}
                className="announcement"
                data-priority={String(Boolean(announcement.priority))}
              >
                {announcement.text}
                <div className="announcement__when">{clockOf(announcement.at)}</div>
              </div>
            ))}
        </div>
      ) : null}

      {view.install ? (
        <div className="card">
          <h2>Crowd chat</h2>
          <p className="muted" style={{ marginTop: 0 }}>
            {view.install.why}
          </p>
          <div className="install" style={{ marginTop: 'var(--gc-gap)' }}>
            {view.install.android ? (
              <a href={view.install.android}>Android — install Backstage</a>
            ) : null}
            {view.install.ios ? <a href={view.install.ios}>iPhone — install Backstage</a> : null}
          </div>
        </div>
      ) : null}

      {view.support ? <p className="muted">Something wrong? {view.support}</p> : null}
    </div>
  )
}

/**
 * The optional mesh chat app, offered below the ticket.
 *
 * Below, and not above: the ticket is why somebody opened this, and an install prompt
 * above the QR is an install prompt somebody scrolls past at a gate. Rendered as nothing
 * at all unless the organizer signed links into the manifest, so an event that does not
 * use Backstage never mentions it.
 *
 * Only the link for the phone being held is shown. Offering an APK to an iPhone is how a
 * page teaches people to ignore it.
 */
function Backstage({ links }: { links: BackstageLinks | null }) {
  if (!links) return null

  // Platform sniffing, which is usually the wrong answer and is the right one here: the
  // question is not what the browser can do, it is which of two stores this person can
  // install from, and nothing but the user agent knows that.
  const agent = navigator.userAgent
  const isIOS =
    /iPad|iPhone|iPod/.test(agent) || (agent.includes('Mac') && 'ontouchend' in document)
  const href = isIOS ? links.ios : links.android
  if (!href) return null

  return (
    <div className="card backstage">
      <h2>Talk to people here</h2>
      <p className="muted">
        {links.note ??
          'Backstage passes messages phone to phone over Bluetooth, so it keeps working when the signal does not. Optional — your ticket works without it.'}
      </p>
      <a
        className="backstage__install"
        href={href}
        // noreferrer as well as noopener: the destination is a store link, and there is
        // no reason to tell it which ticket page somebody came from.
        rel="noopener noreferrer"
        target="_blank"
      >
        Get Backstage for {isIOS ? 'iPhone' : 'Android'}
      </a>
    </div>
  )
}

/** The ticket card: mostly QR, because that is the only part a gate looks at. */
function Ticket({ cached }: { cached: Cached }) {
  const canvas = useRef<HTMLCanvasElement>(null)
  const [remaining, setRemaining] = useState(() => millisUntilRotation(cached))
  const rotating = cached.view.format !== 'gc1'

  // Redrawn on the window boundary rather than on a fixed timer, so the code on
  // screen is always the one the box is currently accepting.
  useEffect(() => {
    let cancelled = false

    const draw = async () => {
      const payload = await currentPayload(cached)
      if (cancelled || !payload || !canvas.current) return
      await QRCode.toCanvas(canvas.current, payload, {
        // Error correction M rather than L: a phone screen picks up glare and
        // fingerprints, and the extra redundancy costs one QR version.
        errorCorrectionLevel: 'M',
        margin: 0,
        // Drawn large and scaled down by CSS, so it stays crisp on a high-density
        // screen without the browser resampling it.
        width: 512,
        color: { dark: '#000000ff', light: '#ffffffff' },
      })
    }

    void draw()
    if (!rotating)
      return () => {
        cancelled = true
      }

    const tick = setInterval(() => {
      const left = millisUntilRotation(cached)
      setRemaining(left)
      // Redrawn just after the boundary, with a small margin so a phone whose clock
      // ticks slightly early does not draw the previous window's code.
      if (left > 29_500) void draw()
    }, 500)

    return () => {
      cancelled = true
      clearInterval(tick)
    }
  }, [cached, rotating])

  const style = cached.view.colour
    ? ({ '--gc-tier-colour': cached.view.colour } as React.CSSProperties)
    : undefined

  return (
    <div className="ticket" style={style}>
      <div className="ticket__band" />
      {cached.view.revoked ? (
        <div className="ticket__revoked">This ticket has been cancelled</div>
      ) : null}
      <div className="ticket__body">
        <span className="ticket__tier">{cached.view.tier_name}</span>
        <div className="ticket__qr">
          <canvas ref={canvas} aria-label="Your ticket code" role="img" />
        </div>
        {cached.view.seat_label ? (
          <div className="ticket__seat">
            <small>Seat</small>
            {cached.view.seat_label}
          </div>
        ) : null}
        {rotating ? (
          <div className="ticket__rotation">
            <span>Changes in {Math.ceil(remaining / 1000)}s</span>
            <span className="ticket__rotation-bar">
              <span
                className="ticket__rotation-fill"
                style={{ width: `${(remaining / 30_000) * 100}%` }}
              />
            </span>
          </div>
        ) : null}
        {cached.view.history && cached.view.history.length > 0 ? (
          <p className="muted" style={{ margin: 0, textAlign: 'center' }}>
            Scanned in at {cached.view.history[cached.view.history.length - 1]!.checkpoint_name}
          </p>
        ) : null}
      </div>
    </div>
  )
}

/**
 * The best guess at where this phone is.
 *
 * The last gate the ticket came through. There is no GPS indoors and the box has no
 * idea where a phone is beyond where it last scanned, so this is the honest answer —
 * and it is a good one, because somebody asking "where is the nearest toilet" has
 * usually just walked through a door.
 */
function lastNode(view: TicketView | undefined): string | undefined {
  const history = view?.history
  if (!history || history.length === 0) return undefined
  const last = history[history.length - 1]!
  return view?.guidance?.next.find((step) => step.checkpoint === last.checkpoint)?.node ?? undefined
}

function deviceLabel(): string {
  return /iPhone|iPad/i.test(navigator.userAgent) ? 'iphone' : 'android'
}

/**
 * The part of a seat that is not already on the line above: row and seat.
 *
 * Falls back to the whole label when the seat has no row and number — a standing
 * ticket in a named area has a section and nothing else, and repeating the section
 * is better than showing an empty line.
 */
function seatDetail(destination: Destination): string {
  const seat = destination.seat
  if (seat?.row && seat.seat) return `Row ${seat.row} · Seat ${seat.seat}`
  return destination.seat_label ?? ''
}

function clockOf(iso: string): string {
  if (!iso) return ''
  return new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
}

function glyphFor(kind: string): string {
  const glyphs: Record<string, string> = {
    washroom: '🚻',
    food: '🍽',
    bar: '🍺',
    water: '💧',
    medical: '✚',
    exit: '🚪',
    info: 'ℹ',
    'lost-found': '🎒',
    charging: '🔌',
    atm: '💳',
    smoking: '🚬',
    merch: '👕',
    cloakroom: '🧥',
    accessible: '♿',
  }
  return glyphs[kind] ?? '•'
}
