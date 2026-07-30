# Landing page brief — the public face of Arbiter AI

**Goal:** the first thing someone sees when they search for Arbiter AI. A public
marketing landing page whose **Sign in** leads into the dashboard built in
`docs/FRONTEND-BRIEF.md`.

**Decided 2026-07-28.** This partially revives ADR-002 Decision 1, which was withdrawn
on 2026-07-26 — but only at the frontend, and with the coupling that made it dangerous
removed. Read §1 before writing any code.

---

## 1. Architecture — read this first

```
/          → public landing page      (no auth, no data, static copy only)
/app/*     → the dashboard            (unchanged: sign-in wall, all five views)
```

**The landing is a React route in the app — not a standalone HTML file.**
*(Clarified 2026-07-28 after a first attempt built `frontend/site/index.html` as hand-
written static HTML, which silently made Magic, framer-motion, and ui-ux pro max
inapplicable and produced a visually flat page.)*

Landing source lives in `frontend/src/site/` as React components, routed at `/` by the
same router that serves `/app`. Its own folder keeps marketing copy from tangling with
view code, but it is app code and uses the full stack.

For search visibility, prerender `/` to static HTML **at build time** — do not
hand-write the markup to achieve it. If prerendering needs a plugin, that is an
acceptable build-time dependency (build-time deps don't count against constraint 4,
which is about what ships to the customer).

### The three rules that keep this safe

1. **The landing makes zero authenticated API calls.** No `/api/summary`, no counts,
   no "N threats triaged" ticker. Not even the aggregate lifetime numbers — ADR-002's
   zero-recon tier is not being revived. The landing is static copy and nothing else.
   The only network call it may trigger is the CSRF bootstrap, and only once the user
   navigates to sign in.

2. **`arbiter/api/server.py` does not change.** No public routes, no anonymous tier.
   Its auth gate answers `401` for everything except login, and that stays true. The
   landing is frontend-only.

3. **Off by default on customer installs.** A customer who installs Arbiter gets the
   login screen at `/`, not marketing copy. Gate it on a build-time flag
   (`VITE_PUBLIC_LANDING`, default off) so the installed bundle doesn't even contain
   the marketing routes. The landing exists for the public site deployment.

**Sign in** on the landing routes to `/app` (or `/app/login`). Same origin, same
session cookie, same CSRF bootstrap — no second auth system, no changes to
`src/lib/api.ts`.

---

## 2. What the page has to do

The visitor is a founder or lone engineer at a company with real log volume, no
security hire, and no budget for enterprise tooling or an outsourced SOC. They are
skeptical of installing a binary with deep read access. The page has to land three things, in this order:

1. **What it is** — an AI security analyst that runs inside your network.
2. **Why it's trustworthy** — nothing leaves; you can read every decision it makes.
3. **How to get it** — install, or look at the code.

Copy source of truth is `CONCEPT.md`. Do not invent claims. Specifically:

- The positioning line is **"A shield you can raise before you can afford an army."**
  *(Changed 2026-07-29. The previous line — "The SIEM that doesn't need an analyst,
  because the analyst is built in" — is withdrawn: it swipes at a category the visitor
  may already own and like, and names a competitor's shape rather than the buyer's
  problem. "Shield" is a metaphor in copy only; the imagery ban in §3 still forbids
  drawing one.)*
- **No pricing claim, comparison, or implication ships on this page at all.** Not a
  number, not "priced per gigabyte", not an implication about who that punishes. This
  also retires the "verify current pricing before publishing externally" hazard —
  there is nothing to verify because nothing is published. Arbiter's own per-asset
  pricing stays an internal positioning note in `CONCEPT.md`.
- **Existing tooling is not the villain — the empty seat is.** Detection tooling is
  good; almost all of it assumes someone is reading it. That someone is who the buyer
  does not have. Frame every comparison as a difference in shape, never in virtue.
- Free OSS stacks are **"free like a puppy"** — someone still has to raise it. Keep
  the line; it is affectionate, not hostile, which is exactly the register wanted.

### Sections

| Section | Content |
|---|---|
| Hero | Positioning line, one-sentence explanation, primary CTA (Install) + secondary (Sign in) |
| The problem | Per-GB SIEM pricing; OSS SIEMs need an analyst you don't have; you're the target now |
| How it works | The triage loop: collect → cheap prefilter → LLM only on ambiguous cases → escalate with evidence or suppress with a written rationale |
| Why you can trust it | Nothing leaves the network; local open-weights inference; every suppression carries a rationale; shadow mode first; memory is a readable database, not fine-tuned weights |
| Install | Link to GitHub Releases for the `.pyz` + `SHA256SUMS`. **Never publish a pipe-to-shell one-liner** — Arbiter's own prefilter escalates that pattern, and publishing it would be self-refuting |
| Footer | GitHub, docs, sign in |

**Shadow mode deserves its own beat.** "It scores alongside you for weeks before it's
allowed to suppress anything" is the single most reassuring fact about the product for
a skeptical buyer. Don't bury it in a feature grid.

---

## 3. Design

Use 21st.dev Magic (`/ui`) for every section and ui-ux pro max to refine each one, per
`AGENTS.md` § "Required tooling". If a section is a heading over three columns of
paragraph text, you have not used them.

**Restrained does not mean plain.** The failure mode to avoid is not "too exciting,"
it's "looks like an unstyled Tailwind starter." Calm and precise means confident
typography, real depth, and deliberate motion — not the absence of design. Aim for the
register of Linear, Vercel, or Stripe's security pages: dark, spare, expensive-looking.

Concretely, the page needs:

- **A hero with a visual, not just centered text.** The best asset this product has is
  its actual output: a verdict. A stylized verdict card — `ESCALATE` on a brute-force
  signature with its evidence summary, or `SUPPRESS` with its written rationale — shows
  what Arbiter does better than any paragraph. Clearly illustrative, drawn in-app from
  static sample data, obviously not a live instance. (This is distinct from the "no
  fake dashboards" rule below: one honest artifact, not a fabricated screenshot.)
- **Depth.** Layered surfaces, subtle gradient or grain, hairline borders that catch
  light. The current flat `#0a0a0a` everywhere is what makes it read as unfinished.
- **A real type scale.** The hero should dominate; section labels should be small and
  quiet. Vary weight and size with intent instead of defaulting to one size for
  everything.
- **Motion on scroll.** framer-motion is already a dependency: sections easing in as
  they enter the viewport, the verdict card assembling itself once. Gate all of it
  behind `useReducedMotion`, as `Login.tsx` and `LiveFeed.tsx` already do.
- **Rhythm.** Vary the section layouts. Four identical bordered cards in a row, twice,
  is monotony rather than restraint.

Still off-limits, and these are the actual "don'ts": no fear-based imagery (no shields,
locks, hooded figures, red alert glows), no fabricated product screenshots, no invented
customer logos or testimonials, no live counters pulling real numbers.

It must still feel like the same product as the dashboard — same palette, same colour
semantics (red escalate, green suppress, blue prefilter, purple LLM). Someone who signs
in should not feel handed off to different software. The landing is simply allowed more
expression than an incident surface is.

---

## 3a. The hero scroll sequence

**Superseded 2026-07-29 by `docs/HERO-TRANSIT-BRIEF.md`.** The exploded-view plan
(the dashboard delaminating into planes in a CSS 3D perspective container) was replaced
by the transit sequence: an underground network where tunnels are the links, stations
are the checks, and the event is a train that stops at each station to be judged and
leaves in the colour of the tier that judged it.

Read that file for the station table, the scroll timeline, the scaling rules and the
acceptance checks. It is implemented in `frontend/src/site/TransitField.tsx`, and it is
still canvas 2D with no new dependency — the Three.js prohibition below stands and was
never needed.

`CyberField.tsx` and `ArbiterMark.tsx` implemented the withdrawn plan and have been
deleted. The mark is no longer a separate component: the field draws it at three scales
(the opening gate, every idle station, the closing gate), because two implementations of
one logo drift apart.

## 4. Constraints

All of `AGENTS.md` § "Hard constraints" applies, and constraints 1 and 2 matter *more*
here, because marketing pages are where third-party scripts usually creep in:

- **No CDN fonts, icons, CSS, or JS.** Self-host everything.
- **No analytics.** No Google Analytics, no Plausible, no Vercel Analytics, nothing.
  A product whose pitch is "nothing leaves your network" cannot ship a tracker on its
  own front page. If traffic numbers are wanted later, take them from server logs.
- **No embedded video, fonts, or images from third-party hosts.**
- Dependencies stay minimal and reviewable.

Since this page will be publicly deployed, also:

- Real `<title>`, meta description, Open Graph tags, and a favicon — search visibility
  is the entire reason this page exists.
- Semantic HTML and a sensible heading hierarchy. Indexability comes from build-time
  prerendering (§1), not from hand-writing static markup — the copy must be present in
  the served HTML without JS executing, but the source stays React.
- Accessible: keyboard navigable, sufficient contrast, alt text.

---

## 5. Done when

- `/` renders the landing with no authenticated API call — verify in the Network tab
  that nothing hits `/api/*` until Sign in is clicked.
- **No request leaves the origin.** Filter the Network tab by third-party domains and
  confirm it's empty. This is the constraint most likely to be broken here.
- Sign in navigates to `/app` and the existing login flow works untouched.
- `/app` still requires auth; deep-linking to it while signed out lands on Login.
- With `VITE_PUBLIC_LANDING` off, `/` is the login screen and no marketing code is in
  the bundle.
- The built `index.html` contains the hero copy as text (prerender worked), and the
  page has title/description/OG tags.
- Every section was generated with `/ui` and refined with ui-ux pro max — state which,
  per section, in your summary.
- `python3 -m pytest -q` still passes — nothing in `arbiter/` should have changed.
