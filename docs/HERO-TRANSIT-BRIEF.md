# Hero brief — the transit sequence

**Decided 2026-07-29 with Haryshwa.** This **replaces** `docs/LANDING-BRIEF.md` §3a
("The hero scroll sequence — exploded view"). Everything else in `LANDING-BRIEF.md`
still stands: React route in `frontend/src/site/`, zero authenticated calls, off by
default on customer installs, no fear imagery, no fabricated screenshots.

Implemented in **`frontend/src/site/TransitField.tsx`** and `Landing.tsx`. It was ported
from a standalone prototype, `docs/preview/hero-transit.html`, which was approved as the
design target and then deleted once parity was confirmed — see §8a for that history and
for the constants it established.

---

## 1. What replaces what

| Action | File |
|---|---|
| Delete | `frontend/src/site/CyberField.tsx` |
| Delete | `frontend/src/site/ArbiterMark.tsx` |
| Add | `frontend/src/site/TransitField.tsx` |
| Rewrite | `frontend/src/site/Landing.tsx` (single full-bleed lane, not two) |

The exploded-view hero and the mark dissection are both retired. One hero.

**Why the mark component goes too:** the mark is no longer a separate object that
delaminates. It is now a *primitive drawn by the field at three scales* — the opening
gate, every idle station in the network, and the closing gate. Keeping a DOM/SVG mark
alongside a canvas one guarantees they drift apart.

---

## 2. The metaphor

An underground network. **Tunnels** are the links, **stations** are the checks, and the
**event is a train** running the line, pinging its position as it goes. The camera is a
drone flying alongside the train inside the environment — never inside the tunnel, never
on a rig bolted to it.

Every station is the Arbiter mark. The doors part along the mark's chord to admit the
train, close behind it while the check runs, and part again to release it.

---

## 3. The five stations

Copy is unchanged from the current `BEATS` array in `Landing.tsx`. Station colours are
the dashboard's tier semantics, so the train literally becomes the tier that handled it.

| # | Station | Asset label | Colour | Panel rows | Verdict chip |
|---|---|---|---|---|---|
| 0 | Collect | `web-prod-01` | `#888780` neutral | source / host / left the network | `read only` |
| 1 | Triage | `edge-gw-02` | `#378ADD` prefilter | severity / asset criticality / seen before | `prefilter tier` |
| 2 | Guardrails | `iam-core` | `#EF9F27` guardrail | pattern / suppressible / model override | `hard rule` |
| 3 | Local model | `db-prod-03` | `#7F77DD` llm | model / runs on / tokens billed | `ambiguous only` |
| 4 | Decision | `soc-relay` | `#E2574B` escalate | verdict / evidence / rationale | `escalated` |

**Ending: escalate only.** One story, told well. No suppress variant — if it's wanted
later it is a second tail on this table, not a rewrite.

Panel rows are illustrative sample data, consistent with `samples/events.jsonl`
(sshd brute force on a critical host). This is the one honest artifact the landing is
allowed, same licence as the verdict card — not a fabricated dashboard.

---

## 3a. Copy — two decided changes, and what they supersede

**Decided 2026-07-29.** Both diverge from documents currently marked source-of-truth.
Implement these; the older lines are withdrawn, not "also acceptable".

### The hero no longer names the category, and carries no CTAs

```
A shield you can raise before you can afford an army.
   ("before you can afford an army" in #6b6a66)

Arbiter is a self-hosted AI security analyst. It reads every line your
systems write, inside your network, and only wakes you when something
earns it.
```

**Withdrawn:** *"The SIEM that doesn't need an analyst, because the analyst is built
in."* It reads as a direct swipe at a category the buyer may already own and like.
`CONCEPT.md` § Positioning and `LANDING-BRIEF.md` § 2 both still print the old line —
they are stale on this point and should be updated in the same change.

**No Install / Sign in buttons in the hero.** They live in the nav and in the install
section. The hero's job is the sentence and the field; a button competes with both, and
a visitor who has scrolled zero pixels has been given no reason to press one.

*Note on the metaphor:* "shield" appears in copy only. `LANDING-BRIEF.md`'s ban on
shield/lock/hooded-figure **imagery** stands — no shield graphic anywhere, and the mark
stays the circle and chord.

### The problem section stops making tooling the villain

```
Detection tooling has never been better. Almost all of it assumes a person
on the other end — someone to write the rules, tune the noise, and read the
dashboard each morning.

Wazuh, Elastic, Security Onion: excellent, and free like a puppy. Someone
still has to raise it.

You have real log volume and no security hire. That seat stays empty whether
or not you buy the software.
```

**Withdrawn:** the per-gigabyte pricing attack. No pricing claim, comparison, or
implication appears on the landing page at all — which also retires the
"verify current pricing before publishing" hazard in `CONCEPT.md` § The problem.
The gap being sold against is the **empty seat**, not a vendor's invoice.

Same rule inside the flight: the Collect beat reads "nothing is shipped out, nothing is
sampled, nothing is thrown away" — no "billed by the gigabyte".

"Free like a puppy" survives because it is affectionate, not hostile.

---

## 4. Scroll timeline

One `useScroll` progress over a `660vh` scope with a single `100vh` sticky viewport.
Spring the driver once; never spring the consumers.

```
0.000 – 0.075   intro    mark draws, doors open, network fades up, camera dollies out
0.075 – 0.850   flight   5 blocks of (1 - 0.075 - 0.15) / 5 each:
                           first 46% dwell at station k
                           remaining 54% travel from k to k+1
0.850 – 1.000   outro    network fades out, camera pulls back 2.4x,
                         doors close, chord bars last, verdict seals
```

**Per-station dwell** (drives one block's first 46%):

- `0.00–0.16` doors open, train slides to the gate centre
- `0.16–0.82` doors shut, outer arcs spin, panel types in one row at a time
- `0.55` verdict lands — train colour eases to this station's tier colour
- `0.82–1.00` doors part on the far side, train leaves in the new colour

**Outro**, in order: panel and station labels clear by `out 0.22`; copy and the line map
fade by `out 0.5–0.7`; the mark fades up from `out 0.22`, halves close on an
`1-(1-t)^2.2` ease, chord draws from `out 0.55`; train shrinks and vanishes inside by
`out 0.7`; `escalated · evidence attached` and `A R B I T E R` fade in from `out 0.35`
and **hold** — the closed mark is the last frame, and it stays while the reader
continues into the sections below.

Reduced motion: hold the whole thing at a readable frame (`p = 0.42`) as
`Landing.tsx` already does with `useReducedMotion`. Every word stays in the DOM at all
opacities so the prerendered HTML is complete.

---

## 5. Layout — immersive, not split

The field is **full-bleed**. Copy sits over it, cross-fading in place; a `to top` scrim
keeps it legible. *(Copy was bottom-left until 2026-07-30; it is now centred in a 58ch
column — see `THEME-BRIEF.md` §2b.)* A five-stop line map sits at the right edge, current
stop lit in its tier colour, the rest at 34%.

**One content band** governs everything:

```css
--band: min(1680px, 94vw);
--gutter: max(1.75rem, calc((100vw - var(--band)) / 2));
```

Copy uses `--gutter`; the canvas centres its geometry across the same band — at `50%`
now that the copy is centred (it was `62%` while the copy sat left, to keep the two from
overlapping).
Without this the geometry drifts to the far right of an ultrawide while the copy hugs
the left, which is exactly how the first pass failed.

**The closing composition is centred in the viewport** — `W/2, H*0.46` — not on the
band centre. It is the final frame, so it gets the middle.

---

## 6. Scaling — both axes, every dimension

The failure to avoid: fixed-pixel sizes that are right on a laptop and unreadable on a
34-inch. Two mechanisms, and nothing may be left out of either.

**CSS — fluid type.** Take the smaller of a width- and height-derived size so short
viewports don't overflow:

```css
--fs-h1:   clamp(2.3rem, min(3.7vw, 8.4vh), 5.2rem);
--fs-h2:   clamp(1.45rem, min(2.35vw, 5vh), 3.1rem);
--fs-body: clamp(1rem, min(1.08vw, 2.3vh), 1.35rem);
--fs-eb:   clamp(.68rem, min(.8vw, 1.6vh), .95rem);
--fs-ui:   clamp(.82rem, min(.92vw, 1.9vh), 1.08rem);
--fs-tiny: clamp(.6rem, min(.66vw, 1.35vh), .85rem);
```

Padding and gaps in `em`, so they follow the type.

**Canvas — one scale factor**, recomputed on resize:

```js
SC = clamp(min(H / 820, W / 1440), 0.85, 2.3);
FL = 560 * SC;   // focal length
```

`SC` multiplies **every** drawn dimension: tunnel wall gauge, station glyph radii,
packet length and width, panel width and row rhythm, all canvas type, stroke weights,
ping rings, kink markers. Grep the ported component for a bare numeric literal in a
`lineWidth`, `font`, or clamp ceiling — if it isn't multiplied by `SC`, it's a bug.

---

## 7. Rendering notes

- **Canvas 2D, no WebGL, no new dependency.** `LANDING-BRIEF.md`'s ban on Three.js
  stands; this satisfies it without the layered-DOM approach, which cannot do the
  depth-sorted network.
- Geometry: stations on a Catmull-Rom spline at `z = i * 1000`, lateral spread
  `±580 / ±340`. Tunnels are polylines with one mid kink, drawn as two parallel walls
  plus a dim centre rail and a cross-tie every fourth sample — that reads as bored
  tunnel rather than glowing cable.
- Camera: drone at `~340` off-axis, orbiting slowly, trailing the train by `0.3` of a
  segment, aimed `0.13` ahead of it, position eased toward its target each frame so it
  lags and settles. Distance `×(1 + out * 1.4)` during the outro.
- Depth: `vis(z) = 1 - (z/2900)^0.6`. Far geometry fades into the backdrop, not to
  black.
- Bloom: bright elements to a half-res offscreen canvas, composited once with
  `filter: blur(6px)` and `globalCompositeOperation: 'lighter'`. One filtered draw call,
  not one per element.
- Only the train, the active gate, and the pings carry colour. Everything else stays
  cold steel — that is what makes the verdict colour mean something.
- Cap `devicePixelRatio` at 2. Regenerate station geometry lazily as `trav` advances and
  drop stations more than 3 behind.

---

## 8. Acceptance

1. At 1440×900, 2560×1080 and 390×844 the copy is comfortably readable and the field
   fills the frame at the same relative scale. No fixed-pixel text anywhere.
2. Scrolling back up runs the whole sequence in reverse, including the doors.
3. With reduced motion, the page is complete and static at a readable frame.
4. The last frame is the closed mark, centred, with the escalate caption — and it holds.
5. No authenticated request fires from `/` at any scroll position. Network tab shows
   nothing but the document and its assets.
6. `oxlint` clean; prerender of `/` still produces complete HTML.
7. Grep the built page for `SIEM`, `Splunk`, `gigabyte`, `per GB` — zero hits. No
   pricing claim and no competitor comparison ships.
8. The hero contains no button. First CTA the reader meets is in the nav.

---

## 8a. The constants are the design — do not retune them

**History.** `docs/preview/hero-transit.html` was a standalone canvas 2D prototype,
approved by Haryshwa 2026-07-29 ("this is exactly what I want my landing page to look
[like]") and used as the acceptance target for the port. Parity was confirmed in a
browser and the preview was deleted on 2026-07-30, as intended — a second
implementation of the same animation would have rotted into a misleading reference.
It was never committed, so it is not recoverable from git history.

**What that means now.** `frontend/src/site/TransitField.tsx` is the only
implementation and therefore the reference. The table below is the record of what the
preview established; the component must continue to match it.

These numbers are not defaults and they are not taste. Each was arrived at by
iteration against a specific complaint — the tunnel gauge because the wires blew out,
`SC` because the type was unreadable on an ultrawide, the camera offset because a
centred camera read as being bolted to the track. **Do not retune them while working
on something else.** Changing one is a design decision that needs the same scrutiny
the original had.

| Constant | Value | What it governs |
|---|---|---|
| `INTRO` / `OUTRO` | `0.075` / `0.15` | scroll spent opening and closing the doors |
| `SPAN` | `(1 - INTRO - OUTRO) / 5` | one station block |
| `DWELL` | `0.46` | share of a block spent stopped at the platform |
| `SPACING` | `1000` | world distance between stations |
| `FAR` / `NEAR` | `2900` / `30` | depth clip |
| `FL` | `560 * SC` | focal length |
| `SC` | `clamp(min(H/820, W/1440), 0.85, 2.3)` | scales every drawn dimension |
| band / centre | `min(W*0.94, 1680)`, centre at `50%` of it (was `62%` pre-centred copy), `CY = H*0.42` | geometry alignment |
| camera | trails `0.3`, looks `+0.13` ahead (`+0.02` stopped), distance `340`/`430` × outro `(1 + out*1.4)`, eased `0.05`/frame | the drone |
| `visible(z)` | `1 - (z/FAR)^0.6` | aerial perspective |
| `LOGO` | `atan2(20.4 - 3.6, 9 - 15)` | chord angle, from Nav.tsx's SVG |
| closing mark | `W/2, H*0.46`, radius `min(W*0.52, H) * 0.26` | centred final frame |

Draw order per frame is also load-bearing — backdrop, distant estate, station tunnels,
the travelled line, pings, idle station marks, active gate, packet + bloom composite,
platform panel, centred mark, vignette. Reordering it changes what occludes what.

**Regression check, now that there is nothing to diff against:** scroll the hero at
1440×900, 2560×1080 and 390×844 and confirm the doors open, five stations each stop the
packet and print a panel, the packet carries each tier's colour onward, and the doors
close centred on the escalate caption and hold. Scroll back up; it must run in reverse
cleanly. The timeline maths is also worth unit-testing directly — beat ranges strictly
ascending, `trav` never regressing, each beat at full opacity only while its own station
is the active stop.

---

## 9. Same-change doc updates

These are stale the moment §3a lands, and leaving them creates a second source of truth:

- `CONCEPT.md` § Positioning — replace the SIEM line with the shield line; keep the
  internal reasoning (per-asset pricing, "it is the analyst") which is unaffected.
- `LANDING-BRIEF.md` § 2 — same line, plus drop the per-GB copy guidance and the
  "verify current pricing" caveat, since no pricing claim ships.
- `LANDING-BRIEF.md` § 3a — replace wholesale with a pointer to this file.
- `CLAUDE.md` § Next steps item 0 — it points at the now-deleted `CyberField`
  approach; point it at this brief.
