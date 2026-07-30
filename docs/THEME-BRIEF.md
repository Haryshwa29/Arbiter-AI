# Theme brief — follow the visitor's system, keep the hero dark

**Decided 2026-07-30 with Haryshwa.** Applies to both the public landing and the
dashboard behind `/app`, in one change, so signing in never crosses a theme boundary.

Two decisions:

1. **The site follows `prefers-color-scheme`.** No toggle, no stored preference, no
   JavaScript. Light is what most systems default to, which is the point — the product
   should not feel like it only belongs in a darkened room.
2. **The hero stays dark, in both schemes.** It is a deliberate full-bleed band, not a
   theming failure. The field is a canvas scene lit for near-black: its bloom composites
   additively (which does nothing on white), its tunnels are bright strokes on dark, and
   the packet reads because it is the only warm thing in an abyss. Inverting that is a
   second art direction, not a palette swap, and it is not being attempted now.

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

**The dark band is a token scope, not a set of conditionals.** Re-declare the same
token names inside it and every component within renders dark with no knowledge that it
is doing so:

```css
.band-dark {
  color-scheme: dark;
  /* the dark values, unconditionally, in both schemes */
}
```

Wrap the sticky hero scope in `.band-dark`. Nothing inside it — Landing's copy, the
line map, the scroll hint — needs a single theme branch.

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

**The canvas keeps the dark values in both schemes** — it always renders on `#080808`.
Only DOM chrome (verdict card chip, dashboard badges) switches.

---

## 3. The seam

Where the dark hero band meets the light page, the hero's bottom scrim currently fades
to `#080808`. In light mode that produces a dark smear against a light section.

Fix: the scrim fades to the **band's** background, and the band simply ends. A crisp
edge between a dark hero and a light page is a deliberate, common composition — do not
try to blend them. Check it in both schemes; it is the single most likely place for
this change to look broken.

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

1. Both schemes look deliberate at 1440×900, 2560×1080 and 390×844. Toggle the OS
   setting with the page open; nothing should need a reload.
2. No flash of the wrong theme on first paint, including on the prerendered `/`.
3. Body text ≥ 4.5:1 and large text ≥ 3:1 against its background **in both schemes**.
   Check the mark's amber and every tier colour specifically — they are the failures
   waiting to happen.
4. The hero band is dark in both schemes and its bottom edge is clean in light.
5. Sign-in does not cross a theme boundary: `/` and `/app` agree in both schemes.
6. `grep -rn "#" frontend/src/site` returns only token definitions — no component
   holds a literal colour.
7. The canvas is untouched by any of this. `TransitField.tsx` has no theme branch.
