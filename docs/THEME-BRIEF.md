# Theme brief — the whole page follows the visitor's system

**Decided 2026-07-30 with Haryshwa.** Applies to both the public landing and the
dashboard behind `/app`, in one change, so signing in never crosses a theme boundary.

Two decisions:

1. **The site follows `prefers-color-scheme`.** No toggle, no stored preference, no
   JavaScript. Light is what most systems default to, which is the point — the product
   should not feel like it only belongs in a darkened room.
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

A manual override toggle can be added later if wanted. It is deliberately out of scope:
it would reintroduce the first-paint flash this design avoids.

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

## 2b. Copy is centred

The sections under the hero, and the hero caption itself, are centred in a `58ch`
column rather than left-aligned against the gutter. Reviewed 2026-07-30: left-aligned
copy under a centred field read as unbalanced on a wide viewport. This supersedes
`HERO-TRANSIT-BRIEF.md` §5's "copy sits over it, bottom-left".

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
