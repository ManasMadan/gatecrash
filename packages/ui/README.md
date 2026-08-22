# gatecrash-ui

The verdict screen and the venue map from
[gatecrash](https://github.com/ManasMadan/gatecrash), as React components.

```sh
pnpm add gatecrash-ui gatecrash-client react
```

Two components and a sound. They are here as a package rather than buried in an app
because if you build your own scanner or your own attendee wallet, these are the parts
worth not rewriting — and the parts where the details took the longest to get right.

## VerdictScreen

A full-viewport colour flood with one enormous glyph, a synthesised tone and a distinct
vibration pattern.

```tsx
<VerdictScreen result={result} onDismiss={clear} gateName="North Gate" />
```

The design is not a style choice. A guard at a gate at 22:00 is watching a queue, not a
phone held at arm's length, so text is unreadable in exactly the situation that matters.
Colour, one glyph, a two-note rise or a low buzz, and a haptic pattern you can tell apart
through a jacket pocket — text is the fourth channel, not the first.

The screen clears itself, and that matters more than it sounds: a verdict left up is a
verdict the next person's scan gets confused with, which at a busy gate is a real error.
Admits clear fast because the queue is moving; refusals hold longer because somebody is
about to be told why.

The tones are synthesised with WebAudio rather than fetched, because at the moment they are
needed there may be no network.

## VenueMap

```tsx
// An attendee: their seat, their route, and only the doors they can use.
<VenueMap plan={plan} seat={seat} route={route} openCheckpoints={next} focusSection="block-a" />

// The control room: every door named, and occupancy shaded onto the zones.
<VenueMap plan={plan} showSeats={false} labelEveryGate occupancy={occupancy} />
```

Zones, seated sections with rows laid out along a curve, amenities, the walk route, and
live occupancy. Same component both times — the props are what differ, because an attendee
and an operator are asking different questions of the same map.

Two details that came from getting it wrong first: a focused seat map always includes the
stage, because somebody holding it cannot otherwise tell which way round they will be
sitting; and area labels are staggered by nesting depth, because a pit sits flush against
the front of the arena that contains it and both labels landed on the same line.

## Styling

Three stylesheets, imported separately so you can take the components without the theme:

```ts
import 'gatecrash-ui/tokens.css' // colours, spacing, the glyph size
import 'gatecrash-ui/verdict.css'
import 'gatecrash-ui/map.css'
```

Everything is driven by CSS custom properties on `:root`, so overriding a colour is one
line rather than a fork.

MIT.
