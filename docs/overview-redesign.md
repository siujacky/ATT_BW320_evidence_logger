# Overview as a summary dashboard, with details in modals

Status: owner's goal of 2026-10-06 — "redesign the Overview make it a summary dashboard, for detail
allow click open and show a modal". Design preview (sample data): the Design canvas "Overview
redesign — design preview" (three artboards: the summary, a card's details open, the summary
during an AT&T outage).

## 1. Why

The Overview grew into one long page (about 5,900 px at 1440 px wide): the status, six tiles,
eight detailed cards (the Internet card alone lists every DNS answer), six history charts and the
recent incidents. The question it must answer at a glance — *is the line working, and if not,
whose fault is it?* — is lost in detail. The detail stays important (it is the evidence), but it
belongs one click away.

## 2. The page

Top to bottom, in the dashboard's existing look (tokens, type, cards, chips, tiles; light and
dark):

1. **Condition banners**, unchanged: alerts and actions (a changed gateway certificate, a fiber
   alarm, ...) stay above everything.
2. **Status card** (full width): the state icon, "Internet status now", the state ("Online",
   "AT&T outage", ...), the attribution when there is one, "for 3 h 2 min, since 3:49 PM", one line
   of key facts (internet probes answered, the gateway's round trip, the median internet round
   trip; for an outage the reason), the active incident's link, and on the right the **last 24
   hours** as a strip of the classifier's states per bucket with a legend (online share, degraded
   time, AT&T outage time). It opens **Status & availability**.
3. **Six key numbers** (the tiles of today, from `Status.stats`, 24 h with 7 days below):
   availability, AT&T outage time, degraded time, incidents, short drops, monitoring coverage.
4. **Nine summary cards** in a responsive grid (3 columns on a desktop, 2 on a tablet, 1 on a
   phone). Each card: its title, a status chip (text and tone), one key figure, one or two lines,
   and where it helps a 24-hour sparkline. Each opens its **details**:

   | Card | Summary | Details (the modal) |
   |---|---|---|
   | Internet | median internet round trip; probes answered; packet loss; DNS / web / hijack verdicts; RTT sparkline | the probes table; name resolution & web checks (a query's addresses folded into "N addresses"); round-trip time and packet-loss charts with their range control and table views |
   | AT&T gateway | broadband up/down; fiber (PON) state; uptime; WAN IPv4; outage redirect | today's gateway card (all its fields) and a link to the Gateway page |
   | Fiber optics | light received (dBm) on a gauge with the gateway's own warning and alarm thresholds; transmit power; temperature; Rx sparkline | today's fiber card and the fiber receive-power chart |
   | Traffic | live download / upload (the flow meter's reading); today's volume; download sparkline | the flow meter, the MRTG-style traffic chart and the WAN volume per day |
   | This PC's link | adapter (Wi-Fi band or Ethernet); signal; link rate; the route to the Internet | today's local link card |
   | Network | connections open at the last NAT read; devices listed; the most used organisations; firewall drops in 24 h | the samplers' state, the 24 h top devices and organisations, the firewall's 24 h counts, links to the Network page's tabs |
   | Gateway syslog | receiver state; messages; kept vs the limit; the gateway's setting | today's syslog card, its controls included |
   | Evidence | signed records; the last time-stamp; the MongoDB copy; the last verification | today's evidence card and links to verify and export |
   | Monitor & clock | running as / for; version; cycles; clock offset | today's monitor card |

5. **Recent incidents**: the three newest, one line each (when, duration, summary, attribution
   chip; an open one first, marked), each linking to its incident page; "All incidents".

The History section and the long tables leave the page itself: every chart and table lives in a
modal. The other pages (Incidents, Gateway, Syslog, Network, Evidence, Records) do not change.

## 3. The details modal

* A native `<dialog>` opened with `showModal()` (the browser makes the rest of the page inert and
  traps focus), labelled by its heading, with a close button ("Close", 40 px or larger); Esc closes
  it; a click on the backdrop closes it; focus moves into it and returns to the card that opened
  it. One details modal at a time. A confirmation dialog started inside it (e.g. the syslog card's
  "Stop sending") opens on top of it.
* **Address**: opening pushes `#/?detail=<card>` (Back closes it, a reload reopens it, the link can
  be shared on this PC). A modal opened from the address closes by replacing the address; one
  opened by a click closes by going back. Unknown cards are ignored.
* **Live**: while it is open its content follows every status update (every 10 s) and its charts
  their series (every minute), keeping focus and scroll position.
* **Size**: `min(1100px, 100vw - 32px)` wide, at most the window's height less 32 px; the header
  (icon, title, one line of context, close) stays put while the body scrolls. At phone width it
  fills the screen. The page behind does not scroll. No animation when the user prefers reduced
  motion.

## 4. The summary cards as controls

Each card is an `<article>` whose title is a `<button aria-haspopup="dialog">` stretched over the
whole card (a `::after` covering it), so the card is one click target and one Tab stop, the focus
ring outlines the card, and a screen reader announces "Internet, button, opens dialog" followed by
the card's text. A summary card holds no other control. Sparklines are decoration (`aria-hidden`)
with a visually hidden sentence ("median round trip 8 to 24 ms over the last 24 hours").

## 5. Data

No new API. `/api/status` (every 10 s, as today) feeds the status card, the tiles and most cards;
`/api/series?range=24h` (once a minute while the page is visible) feeds the 24-hour strip and the
sparklines; the flow meter reads `/api/traffic/live` (every 5 s) only while the Traffic card or its
modal is on screen; the Network card reads `/api/network/firewall?range=24h&limit=5` every 5
minutes (a monitor without the Network page answers 404: the line is left out). A modal's charts
use `/api/series?range=<its range>`.

As built, two reads were added to this plan. The Network card also reads
`/api/network/connections?range=24h&limit=1` with the firewall, every 5 minutes: the status names no
organisation, and the card names the most used ones (by the sites reached, in the order its details
list them); a monitor that answers 404 to both has no Network page, and the card says so and stops
asking. Its details read both again when they open and every minute while they are open. The recent
incidents read `/api/incidents?limit=3` once a minute, and at once when an incident opens or
closes, so that they never contradict the status card.

## 6. States

Every card says something true in every state: no data yet, a stale status (the monitor not
measuring), an outage (failing parts in critical tone; the parts that still work in good tone —
during an AT&T outage "This PC's link: connected" helps attribution), a feature the monitor does
not have (no syslog store, no Network page: the card says so), hostile text from the gateway or
the network (always rendered as text).

## 7. Verification

The dashboard harness (Node) and the Go tests: the summary for the demo's online and outage states,
each card's modal opened by click and keyboard, closed by Esc, the close button, the backdrop and
Back, focus returned, the address round trip and a deep link, live updates while open, hostile
strings, no external requests, CSP-safe code. A visual check of the demo in light and dark, desktop
and phone, online and outage.
