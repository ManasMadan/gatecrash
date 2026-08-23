# Verdicts

Fifteen of them, in three severities. Every one carries a sentence written by the box, so
every gate at an event says the same thing rather than each guard improvising.

The severity is what the scanner acts on: `admit` opens, `deny` refuses, and `redirect`
refuses **with somewhere to send them** — which is the difference between a guard who can
help and a guard who can only say no.

The order the engine checks these in is in [how a scan is decided](/guide/scanning), and it
is not arbitrary: the cheap and the certain come first, so a malformed QR does not cost a
signature verification.

| Verdict                  | Severity   | Shown to the guard                        | What it means                                                                                                                                                                                                               |
| ------------------------ | ---------- | ----------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ADMIT`                  | `admit`    | Let them in                               | Admit means let them in. Recorded, attributed, chained.                                                                                                                                                                     |
| `ALREADY_USED`           | `deny`     | Already scanned in                        | AlreadyUsed means this ticket has already been admitted at this checkpoint. The result carries the winning admission as evidence: which gate, which device, how long ago.                                                   |
| `INVALID_SIG`            | `deny`     | Not a real ticket                         | InvalidSig means the payload's cryptography does not check out. Either a forgery or a corrupt decode.                                                                                                                       |
| `UNKNOWN_TICKET`         | `deny`     | Not on the list                           | UnknownTicket means the id is not in this event's manifest.                                                                                                                                                                 |
| `REVOKED`                | `deny`     | Cancelled ticket                          | Revoked means the ticket was cancelled, charged back or reported stolen.                                                                                                                                                    |
| `WRONG_EVENT`            | `deny`     | Wrong event                               | WrongEvent means a valid ticket for a different show. Common at multi-day festivals and at venues running two rooms.                                                                                                        |
| `EXPIRED_WINDOW`         | `redirect` | Code expired, ask them to refresh the app | ExpiredWindow means a rotating GC2 code outside the accepted window. This is a screenshot, or a phone whose clock is badly wrong, and the fix is for the attendee to reopen their app — so it must not look like a forgery. |
| `WRONG_ZONE`             | `deny`     | Not allowed in this area                  | WrongZone means the ticket's tier does not entitle the holder to the zone behind this checkpoint. A general-admission ticket at the backstage door.                                                                         |
| `WRONG_DOOR`             | `redirect` | Wrong door, send them on                  | WrongDoor means the ticket is entitled to the zone but this is not its door: a Block C holder at Portal A, or a VIP at the general gate. The result carries the doors that do serve them, so staff can point.               |
| `PREREQUISITE_MISSING`   | `redirect` | Needs to come in the main way first       | PrerequisiteMissing means the holder has not yet been admitted somewhere they need to be first: at the pit gate without having entered the arena. The result names the missing zones and where to satisfy them.             |
| `SCANNER_NOT_AUTHORIZED` | `deny`     | This scanner is not signed in here        | ScannerNotAuthorized means the device is not enrolled, has been revoked, or is not assigned to this checkpoint. A stolen scanner produces this.                                                                             |
| `PASS_LIMIT_REACHED`     | `deny`     | No passes left                            | PassLimitReached means a counted checkpoint has issued all its passes: both drink tokens used, both guest passes spent.                                                                                                     |
| `WRONG_DIRECTION`        | `redirect` | They are not inside yet                   | WrongDirection means a bidirectional checkpoint was scanned in a direction that does not follow: an exit scan for somebody who is not inside.                                                                               |
| `DOORS_CLOSED`           | `redirect` | Doors not open yet                        | DoorsClosed means the checkpoint is outside its opening hours. Not the attendee's fault, and staff need to say something different.                                                                                         |
| `MALFORMED`              | `deny`     | Not a ticket, try again                   | Malformed means the scanned string is not a Gatecrash payload at all. A supermarket barcode, a boarding pass, a URL.                                                                                                        |

The "shown to the guard" column follows three rules: no jargon, no verdict names, no ticket
ids — and it says what to _do_ rather than what happened, wherever there is something to do.
It is read at a glance under a floodlight by somebody who has been on their feet for six
hours.

## The ones worth knowing

**`ALREADY_USED`** carries its evidence: which gate, which device, and how long ago. That is
what settles an argument at a door, and it is why the verdict is not just "no".

**`WRONG_DOOR`** and **`PREREQUISITE_MISSING`** are `redirect` rather than `deny`, and both
carry the checkpoint the holder should be at instead. A pit wristband scanned before the outer
gate is not a forgery — it is somebody in the wrong place, and the gate can say where to go.

**`EXPIRED_WINDOW`** is what a screenshot of a rotating code looks like ninety seconds later.
It is the entire reason rotating codes exist.

**`SCANNER_NOT_AUTHORIZED`** means the device is enrolled but not assigned to this checkpoint.
A device with no assignment scans nothing, deliberately: a scanner that works everywhere is a
scanner that admits to the pit when somebody picks up the wrong phone.

**`MALFORMED`** is the only verdict a scanner can reach with no network, no filter and no
state at all. It costs nothing to know that a QR is not a ticket.

## In TypeScript

```ts
import { severityOf, verdictCopy } from 'gatecrash-client'

severityOf('PREREQUISITE_MISSING') // 'redirect'
verdictCopy('ALREADY_USED') // the sentence a guard reads
```

The copy lives in the client package rather than in each app, so a scanner you write says the
same thing as the one that ships.
