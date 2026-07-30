# Theme brief — the whole page follows the visitor's system

**Decided 2026-07-30 with Haryshwa.** Applies to both the public landing and the
dashboard behind `/app`, in one change, so signing in never crosses a theme boundary.

Two decisions:

1. **The site follows `prefers-color-scheme` by default, with a manual override.**
   Light is what most systems default to, which is the point — the product should not
   feel like it only belongs in a darkened room. The override is specified in §1a;
   it is an override, never a replacement for the media query.
2. **The field repaints with the page.** *(Revised the same day. A first pass kept the
   hero dark in both schemes; reviewed against a light page it read as an unexplained
   black hole rather than a deliberate band.)* A light field is a second art direction,
   not an inversion — §2a specifies it — and both directions must now be maintained in
   step. Every future change to `TransitField.tsx` gets checked in both schemes.

---

## 1. Mechanism

Pure CSS, media-query driven. **No JS, no class toggling, no `localStorage`.** This is
not laziness — it is what makes the prerendered page correct on first paint. Any
JS-driven theme has a flash of the wrong one, and this page is server-prerendered.

```css
:root {
  color-scheme: light dark;   /* scrollbars, form controls, native UI follow too */
  /* light tokens — the default */
}

@media (prefers-color-scheme: dark) {
  :root { /* dark token overrides */ }
}
```

No `.band-dark` scope is needed any more: the hero is the same theme as the page, so
Landing's copy, the line map and the scroll hint all read the ordinary tokens.

**The canvas cannot read CSS variables**, so `TransitField.tsx` needs the scheme as
data. Match the media query once and pass it in — a `useSyncExternalStore` or a
`matchMedia` listener in Landing, handed down as a prop — and re-render the field on
change. Do not sample `getComputedStyle` per frame.

## 1a. The override toggle

*(Added 2026-07-30. An earlier revision ruled a toggle out for flashing the wrong theme
on a prerendered page. That risk is real and the blocking script below is what removes
it — do not ship the toggle without it.)*

A three-state control in the nav, immediately left of Sign in, cycling
**System → Light → Dark** and starting at System, so a visitor can always get back to
"whatever my OS says" without clearing storage.

- The button writes `data-theme="light" | "dark"` on `<html>`, or removes the attribute
  for System, and mirrors the choice to `localStorage`.
- CSS gains `[data-theme="dark"] :root`-equivalent overrides alongside the media query.
  The media query stays the default; the attribute only overrides it when present.
- **A tiny blocking script in `index.html`'s `<head>`** — before any stylesheet — reads
  `localStorage` and sets the attribute. It must be inline and synchronous; a module
  import runs too late and the flash comes back.
- The canvas reads the resolved scheme, not the media query directly, so the field
  follows the override too.
- Label the state, don't just show an icon: an icon alone can't say whether you are in
  System or in an explicit mode.

---

## 2. Tokens

Replace the 34 hardcoded hexes in `frontend/src/site/` with these. Names are semantic,
not literal — nothing may be called `--white`.

| Token | Light | Dark | Use |
|---|---|---|---|
| `--bg` | `#FAF9F7` | `#080808` | page background |
| `--surface` | `#FFFFFF` | `#0c0c0b` | raised cards, the verdict card |
| `--ink` | `#14140F` | `#F2F1EE` | primary text |
| `--ink-2` | `#4A4945` | `#a9a8a3` | body copy |
| `--ink-3` | `#6E6D67` | `#9b9a95` | secondary links |
| `--ink-4` | `#8A8981` | `#5F5E5A` | eyebrows, footer, quiet labels |
| `--hair` | `#E4E2DC` | `#22221f` | hairline borders |
| `--hair-2` | `#D6D3CB` | `#2a2a28` | button borders |
| `--cta-bg` | `#14140F` | `#F2F1EE` | primary button fill |
| `--cta-ink` | `#FAF9F7` | `#0A0A0A` | primary button text |
| `--mark` | `#B4841F` | `#d9a943` | the Arbiter mark's amber |

The mark's amber **must** darken in light mode. `#d9a943` on white is roughly 2:1 — it
disappears. `#B4841F` holds the same hue at usable contrast.

### Tier colours — semantics survive, values don't

`red = escalate, green = suppress, blue = prefilter, purple = LLM, amber = guardrail`
is the product's language and does not change. The current values are tuned for dark
backgrounds and several fail on white.

| Meaning | Light | Dark |
|---|---|---|
| escalate | `#C2402F` | `#E2574B` |
| suppress | `#2E8B67` | `#5DCAA5` |
| prefilter | `#2168B8` | `#378ADD` |
| llm | `#5A50B8` | `#7F77DD` |
| guardrail | `#A76B12` | `#EF9F27` |
| neutral | `#6E6D67` | `#888780` |

The canvas uses these too — the packet, the active gate and the platform panel all
carry the tier colour, so they take the light variants on a light page. See §2a.

---

## 2a. The light field — a second art direction, not an inversion

The dark field works because a bright thing moves through an abyss. On paper that
mechanism is gone, and the read becomes precision rather than atmosphere. Three
rendering changes, not just colours:

- **The bloom pass is dropped in light mode.** It composites with `lighter`; adding
  light to white does nothing. Replace it with a soft tier-coloured halo drawn normally
  (`source-over`) behind the packet and the active gate.
- **The packet's core inverts.** White-on-tier disappears on paper; light mode uses a
  dark core (`70,50,10` under the tier colour) so the capsule still reads as lit.
- **The vignette becomes a paper wash** — the page background at ~0.55 alpha at the
  edges instead of black at 0.68, so geometry dissolves into the page rather than into
  a shadow.

| Element | Light | Dark |
|---|---|---|
| field background | `#F5F3EF` | `#080808` |
| tunnel wall | `104,118,136` @ 0.62 | `74,100,126` @ 0.50 |
| tunnel rail | `70,84,102` @ 0.50 | `52,74,98` @ 0.40 |
| idle station glyph | `118,130,146` @ 0.52 | `110,118,126` @ 0.46 |
| haze | `168,178,192` @ 0.16 | `24,38,54` @ 0.24 |
| vignette | page bg @ 0.55 | `8,8,8` @ 0.68 |
| packet / active gate | tier colour, light variant | tier colour, dark variant |

Depth still works unchanged: `visible(z)` lowers alpha with distance, so far geometry
fades toward whichever background it is on.

**The seam is gone as a consequence.** The band's background is the page background, so
there is no edge to hide and no scrim colour to get wrong — the scrim fades to the page
background in both schemes.

## 2b. Alignment: hero left, sections centred

**The hero's copy is left-aligned** against `--gutter`, bottom of the sticky viewport —
the headline, the lead, and each station beat. **The sections below the flight are
centred.** Settled 2026-07-30 after trying both: centred display type over a centred
field left nothing for the eye to start from, and the hero is the one place with a
moving object to balance against.

Because the hero copy is left again, the field's projection centre goes back to `62%`
of the band (`HERO-TRANSIT-BRIEF.md` §5 and §8a updated to match). At `50%` the
geometry sits behind the copy instead of beside it.

## 2c. Measure — the typography bug this pass must fix

Shipped state is broken: one `58ch` column wraps everything, and `ch` resolves against
**the element's own font size**. Body text at ~11px per character gives a ~640px box;
the `h1` then inherits that box at 71px type, which is about nine characters per line.
The headline currently stacks into two-word lines and reads as a poem.

**Measure is set per element, in that element's own units.** Never once on a shared
wrapper.

| Element | Measure | Notes |
|---|---|---|
| hero `h1` | `max-width: 14ch` | ~14 characters of *its own* size; 2–3 lines at every width |
| hero lead | `max-width: 42ch` | |
| beat `h2` | `max-width: 20ch` | |
| beat body | `max-width: 46ch` | |
| section prose | `max-width: 62ch` | |

Also:

- `text-wrap: balance` on every heading, so the last line is never a single word.
- `text-wrap: pretty` on paragraphs.
- Headline size keys off **both** axes — `clamp(2rem, min(6.4vw, 9.5vh), 5.4rem)` — or a
  short laptop window gets a headline taller than the viewport it sits in.

Check by counting lines, not by eyeballing size: the headline holds 2–3 lines at 390,
834, 1440 and 2560 wide. If it hits five, the measure is inherited from the wrong
element again.

---

## 4. The dashboard

Same change, per the decision. `/app` is five views of Tailwind classes, so this is
mechanical rather than delicate.

- `index.css` — `body` currently hardcodes `bg-neutral-950 text-neutral-100`. Move it
  to the tokens above.
- Tailwind v4's `dark:` variant already keys off `prefers-color-scheme` with no config,
  so `text-red-600 dark:text-red-400` is the pattern throughout.
- `lib/theme.ts` — `DECISION_STYLE` and `TIER_STYLE` hardcode `text-red-400`,
  `bg-emerald-500`, etc. Each becomes a light/dark pair using the table above. This is
  the one file where getting it wrong silently breaks the product's colour language, so
  do it first and check every badge in both schemes.
- The dark app is not being abandoned — dark is still what an incident surface should
  look like at 3am, and a visitor whose system is dark gets exactly that.

---

## 5. Done when

1. Both schemes look deliberate at 1440×900, 2560×1080 and 390×844, **including the
   field**. Toggle the OS setting with the page open; the page and the canvas both
   change, and nothing needs a reload.
2. No flash of the wrong theme on first paint, including on the prerendered `/`.
3. Body text ≥ 4.5:1 and large text ≥ 3:1 against its background **in both schemes**.
   Check the mark's amber and every tier colour specifically — they are the failures
   waiting to happen.
4. The field repaints with the page and there is no visible seam where the hero ends —
   the band and the page share a background.
5. Sign-in does not cross a theme boundary: `/` and `/app` agree in both schemes.
6. `grep -rn "#" frontend/src/site` returns only token definitions — no component
   holds a literal colour.
7. `TransitField.tsx` has exactly one palette switch driven by a prop, checked in both
   schemes. Its geometry constants (`HERO-TRANSIT-BRIEF.md` §8a) are untouched — this
   pass changes colour, never timing, camera or composition.
