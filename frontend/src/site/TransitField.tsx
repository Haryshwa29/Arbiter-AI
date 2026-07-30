/**
 * The transit field — the landing's one piece of geometry.
 *
 * An underground network drawn in canvas 2D. Tunnels are the links, stations
 * are the checks, and the event is a train running the line: it pings its
 * position as it travels, stops at each station where the Arbiter mark closes
 * around it, and leaves in the colour of the tier that judged it. The camera
 * is a drone flying alongside inside the environment — never in the tunnel,
 * never bolted to it.
 *
 * Every station IS the Arbiter mark. `mark()` draws the circle-and-chord at
 * three scales: the opening gate, each idle station in the distance, and the
 * closing gate at the end. That is why the mark is not a separate component —
 * two implementations of one logo drift apart.
 *
 * Canvas rather than DOM/SVG because the network is depth-sorted and rebuilt
 * every frame; canvas rather than WebGL because AGENTS.md forbids the
 * dependency and 2D is sufficient. No new packages.
 *
 * Scroll drives everything through one number. `p` is Landing's spring; this
 * component subscribes to it and never re-renders — React owns mounting, the
 * rAF loop owns pixels. Reduced motion holds the timeline at a readable frame.
 */

import { useEffect, useRef } from "react";
import { useMotionValueEvent, useReducedMotion, type MotionValue } from "framer-motion";

/** Which of the two token sets (docs/THEME-BRIEF.md §1) the field is painting. */
export type Scheme = "light" | "dark";

export type TierKey = "neutral" | "prefilter" | "guardrail" | "llm" | "escalate" | "suppress";

/**
 * Dashboard tier semantics: the packet becomes the tier that handled it.
 * Light/dark pair per THEME-BRIEF.md §2 — the canvas can't read CSS
 * variables, so this is the one place these hexes are defined as numbers.
 * `suppress` isn't used by any station (the flight's ending is escalate-only,
 * §3), kept for parity with lib/theme.ts's DECISION_STYLE.
 */
export const TIER_COLOUR: Record<TierKey, Record<Scheme, readonly number[]>> = {
  neutral: { light: [110, 109, 103], dark: [136, 135, 128] },
  prefilter: { light: [33, 104, 184], dark: [55, 138, 221] },
  guardrail: { light: [167, 107, 18], dark: [239, 159, 39] },
  llm: { light: [90, 80, 184], dark: [127, 119, 221] },
  escalate: { light: [194, 64, 47], dark: [226, 87, 75] },
  suppress: { light: [46, 139, 103], dark: [93, 202, 165] },
};

/** The Arbiter mark's amber (index.css's --mark), duplicated as numbers — the
 * canvas draws the mark at three scales and can't read the CSS variable. */
const MARK_COLOUR: Record<Scheme, readonly number[]> = {
  light: [180, 132, 31],
  dark: [217, 169, 67],
};

/**
 * Everything else the field needs per scheme (THEME-BRIEF.md §2a). Light is a
 * second art direction, not an inversion of dark — see the three rendering
 * changes in the frame loop that key off `scheme` alongside this palette:
 * bloom is dropped for a normal-composite halo, the packet core inverts, and
 * the vignette becomes a page-coloured wash.
 *
 * `ink`/`ink2`/`ink3`/`surface` mirror index.css's tokens of the same name —
 * duplicated as rgb triples for the platform panel and station labels, which
 * are canvas text/fills the CSS variables can't reach.
 */
const PALETTE: Record<
  Scheme,
  {
    bg: string;
    wall: readonly number[];
    wallAlpha: number;
    rail: readonly number[];
    railAlpha: number;
    glyph: readonly number[];
    glyphAlpha: number;
    haze: readonly number[];
    hazeAlpha: number;
    vignette: readonly number[];
    vignetteAlpha: number;
    core: readonly number[];
    ink: readonly number[];
    ink2: readonly number[];
    ink3: readonly number[];
    surface: readonly number[];
  }
> = {
  light: {
    bg: "#F5F3EF",
    wall: [104, 118, 136],
    wallAlpha: 0.62,
    rail: [70, 84, 102],
    railAlpha: 0.5,
    glyph: [118, 130, 146],
    glyphAlpha: 0.52,
    haze: [168, 178, 192],
    hazeAlpha: 0.16,
    vignette: [245, 243, 239],
    vignetteAlpha: 0.55,
    core: [70, 50, 10],
    ink: [20, 20, 15],
    ink2: [74, 73, 69],
    ink3: [110, 109, 103],
    surface: [255, 255, 255],
  },
  dark: {
    bg: "#080808",
    wall: [74, 100, 126],
    wallAlpha: 0.5,
    rail: [52, 74, 98],
    railAlpha: 0.4,
    glyph: [110, 118, 126],
    glyphAlpha: 0.46,
    haze: [24, 38, 54],
    hazeAlpha: 0.24,
    vignette: [8, 8, 8],
    vignetteAlpha: 0.68,
    core: [255, 255, 255],
    ink: [242, 241, 238],
    ink2: [169, 168, 163],
    ink3: [155, 154, 149],
    surface: [12, 12, 11],
  },
};

type Station = {
  title: string;
  asset: string;
  rows: [string, string][];
  verdict: string;
  tier: TierKey;
};

/**
 * Illustrative sample data, consistent with samples/events.jsonl — an sshd
 * brute force on a critical host. One honest artifact, not a fabricated
 * dashboard, same licence as the verdict card.
 */
export const STATIONS: Station[] = [
  {
    title: "Collect",
    asset: "web-prod-01",
    rows: [
      ["source", "sshd journal"],
      ["host", "web-prod-01"],
      ["left the network", "no"],
    ],
    verdict: "read only",
    tier: "neutral",
  },
  {
    title: "Triage",
    asset: "edge-gw-02",
    rows: [
      ["severity", "4 of 5"],
      ["asset criticality", "5 of 5"],
      ["seen before", "4 times"],
    ],
    verdict: "prefilter tier",
    tier: "prefilter",
  },
  {
    title: "Guardrails",
    asset: "iam-core",
    rows: [
      ["pattern", "curl | sh"],
      ["suppressible", "never"],
      ["model override", "no"],
    ],
    verdict: "hard rule",
    tier: "guardrail",
  },
  {
    title: "Local model",
    asset: "db-prod-03",
    rows: [
      ["model", "local open weights"],
      ["runs on", "your hardware"],
      ["tokens billed", "0"],
    ],
    verdict: "ambiguous only",
    tier: "llm",
  },
  {
    title: "Decision",
    asset: "soc-relay",
    rows: [
      ["verdict", "escalate"],
      ["evidence", "12 fail, 1 success"],
      ["rationale", "written"],
    ],
    verdict: "escalated",
    tier: "escalate",
  },
];

const N = STATIONS.length;

/** Scroll budget: doors open, five station blocks, doors close and hold. */
const INTRO = 0.075;
const OUTRO = 0.15;
const SPAN = (1 - INTRO - OUTRO) / N;
/** Share of a station block spent stopped at the platform. */
const DWELL = 0.46;

/** Chord angle of the nav mark: its line runs (15,3.6) → (9,20.4). */
const LOGO = Math.atan2(20.4 - 3.6, 9 - 15);

const SPACING = 1000;
const FAR = 2900;
const NEAR = 30;
/** Frame the flight is held at when the visitor prefers reduced motion. */
const HELD_FRAME = 0.42;

type Vec = [number, number, number];
type Screen = { x: number; y: number; s: number; z: number };

type Limb = {
  d: Vec;
  kink: Vec;
  at: number;
  len: number;
  w: number;
  children: Limb[];
};

type Node = {
  i: number;
  x: number;
  y: number;
  z: number;
  wires: Limb[];
  distant: { origin: Vec; limb: Limb; r: number }[];
  phase: number;
};

type Phase = {
  intro: number;
  /** Position along the line, in stations. */
  trav: number;
  /** Progress through the current platform stop, 0 when moving. */
  dwell: number;
  /** Progress of the run between stations, 0 when stopped. */
  travelling: number;
  stop: number;
  /** Progress of the closing sequence. */
  out: number;
};

const cl = (v: number, a: number, b: number) => (v < a ? a : v > b ? b : v);
const lerp = (a: number, b: number, t: number) => a + (b - a) * t;
const sub = (a: Vec, b: Vec): Vec => [a[0] - b[0], a[1] - b[1], a[2] - b[2]];
const add = (a: Vec, b: Vec): Vec => [a[0] + b[0], a[1] + b[1], a[2] + b[2]];
const mul = (a: Vec, s: number): Vec => [a[0] * s, a[1] * s, a[2] * s];
const dot = (a: Vec, b: Vec) => a[0] * b[0] + a[1] * b[1] + a[2] * b[2];
const cross = (a: Vec, b: Vec): Vec => [
  a[1] * b[2] - a[2] * b[1],
  a[2] * b[0] - a[0] * b[2],
  a[0] * b[1] - a[1] * b[0],
];
const norm = (v: Vec): Vec => {
  const l = Math.hypot(v[0], v[1], v[2]) || 1;
  return [v[0] / l, v[1] / l, v[2] / l];
};
const rgba = (c: readonly number[], a: number) =>
  `rgba(${Math.round(c[0])},${Math.round(c[1])},${Math.round(c[2])},${a})`;

/**
 * Deterministic PRNG. The network must be identical on the server-prerendered
 * frame and in the browser, and identical between reloads — a random estate
 * that reshuffles on refresh reads as noise rather than a place.
 */
function makeRandom(seed: number) {
  let s = seed;
  return () => {
    s = (s * 1103515245 + 12345) & 0x7fffffff;
    return s / 0x7fffffff;
  };
}

function scrollPhase(p: number): Phase {
  if (p < INTRO) {
    return { intro: p / INTRO, trav: 0, dwell: 0, travelling: 0, stop: 0, out: 0 };
  }
  if (p > 1 - OUTRO) {
    const out = cl((p - (1 - OUTRO)) / OUTRO, 0, 1);
    return { intro: 1, trav: N - 1, dwell: 1, travelling: 0, stop: N - 1, out };
  }
  const q = (p - INTRO) / SPAN;
  const k = Math.min(N - 1, Math.floor(q));
  const f = Math.min(1, q - k);
  // The last station has no onward run — its whole block is the platform stop.
  if (k === N - 1) {
    return { intro: 1, trav: k, dwell: f, travelling: 0, stop: k, out: 0 };
  }
  if (f < DWELL) {
    return { intro: 1, trav: k, dwell: f / DWELL, travelling: 0, stop: k, out: 0 };
  }
  const travelling = (f - DWELL) / (1 - DWELL);
  return {
    intro: 1,
    trav: k + Math.pow(travelling, 0.9),
    dwell: 0,
    travelling,
    stop: k,
    out: 0,
  };
}

export function TransitField({ p, scheme }: { p: MotionValue<number>; scheme: Scheme }) {
  const canvas = useRef<HTMLCanvasElement | null>(null);
  const target = useRef(0);
  const reduced = useReducedMotion();
  // Read in the frame loop rather than a `useEffect` dependency: the effect
  // below owns the canvas's whole lifetime (geometry, rAF loop, pings), and
  // tearing all of that down on a theme toggle would reset mid-scroll state
  // (the packet's position, its lerped colour) for a change that is only a
  // palette swap. Same pattern as `target` for the scroll value.
  const schemeRef = useRef(scheme);
  useEffect(() => {
    schemeRef.current = scheme;
  }, [scheme]);

  useMotionValueEvent(p, "change", (v) => {
    target.current = v;
  });

  useEffect(() => {
    const cv = canvas.current;
    const ctx = cv?.getContext("2d");
    if (!cv || !ctx) return;

    // Bright elements are composited from a half-res buffer in one blurred
    // draw call. Per-element shadowBlur would cost an order of magnitude more.
    const bloom = document.createElement("canvas");
    const bctx = bloom.getContext("2d");
    if (!bctx) return;

    const random = makeRandom(41977);

    const limb = (angle: number, len: number, w: number): Limb => {
      const tilt = (random() - 0.5) * 1.15;
      const perp = angle + Math.PI / 2;
      return {
        d: [
          Math.cos(angle) * Math.cos(tilt),
          Math.sin(angle) * Math.cos(tilt),
          Math.sin(tilt) * 0.75,
        ],
        kink: [
          Math.cos(perp) * (random() - 0.5) * 0.6,
          Math.sin(perp) * (random() - 0.5) * 0.6,
          (random() - 0.5) * 0.4,
        ],
        at: 0.36 + random() * 0.28,
        len,
        w,
        children: [],
      };
    };

    const makeNode = (i: number): Node => {
      const wires: Limb[] = [];
      for (let f = 0; f < 8; f++) {
        const a = (f / 8) * Math.PI * 2 + random() * 0.45;
        const trunk = limb(a, 460 + random() * 460, 1);
        if (random() < 0.75) trunk.children.push(limb(a + (random() - 0.5) * 2.4, 240 + random() * 260, 0.68));
        if (random() < 0.45) trunk.children.push(limb(a + (random() - 0.5) * 2.8, 190 + random() * 210, 0.5));
        wires.push(trunk);
      }
      const distant: Node["distant"] = [];
      for (let g = 0; g < 14; g++) {
        const origin: Vec = [
          (random() - 0.5) * 3400,
          (random() - 0.5) * 2100,
          (random() - 0.5) * 2000,
        ];
        const l = limb(random() * Math.PI * 2, 1300 + random() * 1500, 0.55);
        l.children.push(limb(random() * Math.PI * 2, 600 + random() * 800, 0.4));
        distant.push({ origin, limb: l, r: 0.4 + random() * 0.5 });
      }
      return {
        i,
        x: (random() - 0.5) * 580,
        y: (random() - 0.5) * 340,
        z: i * SPACING,
        wires,
        distant,
        phase: random() * Math.PI * 2,
      };
    };

    // The estate is fixed-length: five stations plus lead-in and run-out, so
    // nothing is generated mid-scroll and the line is the same every visit.
    const nodes: Node[] = [];
    for (let i = -2; i < N + 2; i++) nodes.push(makeNode(i));
    // nodes[k] holds i = k - 2 by construction (contiguous, built once above),
    // so this is a direct index instead of a per-call linear scan. The rail
    // sampling loop below calls this ~600 times a frame at 0.018 spacing —
    // a scan through nine nodes each time was measured costing tens of
    // milliseconds of frame time, well past the fixed geometry's own draw cost.
    const nodeAt = (i: number) => nodes[i + 2];

    let W = 0;
    let H = 0;
    let SC = 1;
    let FL = 560;
    let CX = 0;
    let CY = 0;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);

    function fit() {
      const host = cv!.parentElement;
      W = host ? host.clientWidth : window.innerWidth;
      H = host ? host.clientHeight : window.innerHeight;
      cv!.width = Math.max(1, Math.round(W * dpr));
      cv!.height = Math.max(1, Math.round(H * dpr));
      cv!.style.width = `${W}px`;
      cv!.style.height = `${H}px`;
      ctx!.setTransform(dpr, 0, 0, dpr, 0, 0);
      bloom.width = Math.max(1, Math.round(W * 0.5));
      bloom.height = Math.max(1, Math.round(H * 0.5));
      // One factor scales every drawn dimension, so the field reads the same
      // on a laptop and on a 34-inch ultrawide.
      SC = cl(Math.min(H / 820, W / 1440), 0.85, 2.3);
      FL = 560 * SC;
      // Geometry centres in the same content band the copy is aligned to,
      // otherwise it drifts to the far right of a wide viewport. At 50% now
      // that the copy is centred too (THEME-BRIEF.md §2b) — it was 62% while
      // the copy sat bottom-left, to keep the two from overlapping.
      const band = Math.min(W * 0.94, 1680);
      CX = (W - band) / 2 + band * 0.5;
      CY = H * 0.42;
    }
    fit();

    /** Catmull-Rom through the station centres — the line's alignment. */
    function spline(a: number, b: number, c: number, d: number, t: number) {
      const t2 = t * t;
      return (
        0.5 *
        (2 * b + (-a + c) * t + (2 * a - 5 * b + 4 * c - d) * t2 + (-a + 3 * b - 3 * c + d) * t2 * t)
      );
    }

    function at(u: number): Vec {
      const i = Math.floor(u);
      const t = u - i;
      const a = nodeAt(i - 1);
      const b = nodeAt(i);
      const c = nodeAt(i + 1);
      const e = nodeAt(i + 2);
      if (!a || !b || !c || !e) return [0, 0, u * SPACING];
      return [
        spline(a.x, b.x, c.x, e.x, t),
        spline(a.y, b.y, c.y, e.y, t),
        spline(a.z, b.z, c.z, e.z, t),
      ];
    }

    function basis(u: number) {
      const t = norm(sub(at(u + 0.005), at(u - 0.005)));
      const n = norm(cross([0, 1, 0], t));
      return { p: at(u), t, n, b: cross(t, n) };
    }

    let cam: Vec = [0, 0, 0];
    let camSmoothed: Vec | null = null;
    let F: Vec = [0, 0, 1];
    let R: Vec = [1, 0, 0];
    let U: Vec = [0, 1, 0];

    function project(q: Vec): Screen | null {
      const v = sub(q, cam);
      const z = dot(v, F);
      if (z < NEAR || z > FAR) return null;
      const s = FL / z;
      return { x: CX + dot(v, R) * s, y: CY - dot(v, U) * s, s, z };
    }

    /** Aerial perspective: distance fades into the backdrop, not to black. */
    const visible = (z: number) => cl(1 - Math.pow(z / FAR, 0.6), 0, 1);

    const kinkOf = (o: Vec, l: Limb) => add(o, add(mul(l.d, l.len * l.at), mul(l.kink, l.len * 0.26)));

    /** A tunnel: two walls, a dim centre rail, a cross-tie at the bend. */
    function tunnel(origin: Vec, l: Limb, dim: number) {
      const pts = [origin, kinkOf(origin, l), add(origin, mul(l.d, l.len))];
      for (let k = 1; k < pts.length; k++) {
        const a = project(pts[k - 1]);
        const b = project(pts[k]);
        if (!a || !b) continue;
        const v = visible(b.z);
        if (v <= 0.02) continue;
        const w = cl(b.s * (k === 1 ? 5 : 3.4) * l.w, 0.3 * SC, 6 * l.w * SC);
        const dx = b.x - a.x;
        const dy = b.y - a.y;
        const len = Math.hypot(dx, dy) || 1;
        const px = -dy / len;
        const py = dx / len;
        const h = w * 0.5;
        ctx!.strokeStyle = rgba(pal.wall, v * dim * pal.wallAlpha);
        ctx!.lineWidth = Math.max(0.3, w * 0.24);
        ctx!.beginPath();
        ctx!.moveTo(a.x + px * h, a.y + py * h);
        ctx!.lineTo(b.x + px * h, b.y + py * h);
        ctx!.stroke();
        ctx!.beginPath();
        ctx!.moveTo(a.x - px * h, a.y - py * h);
        ctx!.lineTo(b.x - px * h, b.y - py * h);
        ctx!.stroke();
        ctx!.strokeStyle = rgba(pal.rail, v * dim * pal.railAlpha);
        ctx!.lineWidth = Math.max(0.25, w * 0.16);
        ctx!.beginPath();
        ctx!.moveTo(a.x, a.y);
        ctx!.lineTo(b.x, b.y);
        ctx!.stroke();
      }
      const bend = project(kinkOf(origin, l));
      if (bend && bend.s > 0.05) {
        ctx!.fillStyle = rgba(pal.wall, visible(bend.z) * dim * 0.45);
        ctx!.fillRect(bend.x - SC, bend.y - SC, 2 * SC, 2 * SC);
      }
      for (const child of l.children) tunnel(kinkOf(origin, l), child, dim * 0.85);
    }

    /**
     * The Arbiter mark. `open` parts the two halves along the chord's normal,
     * which is what makes a station a door: 0 is shut, 1 is wide.
     */
    function mark(
      pt: { x: number; y: number },
      r: number,
      open: number,
      spin: number,
      colour: readonly number[],
      alpha: number,
      angle: number,
    ) {
      const ox = Math.cos(angle + Math.PI / 2) * r * 1.75 * open;
      const oy = Math.sin(angle + Math.PI / 2) * r * 1.75 * open;
      ctx!.lineWidth = Math.max(0.8, r * 0.06);
      ctx!.strokeStyle = rgba(colour, alpha);
      ctx!.beginPath();
      ctx!.arc(pt.x + ox, pt.y + oy, r, angle, angle + Math.PI);
      ctx!.stroke();
      ctx!.beginPath();
      ctx!.arc(pt.x - ox, pt.y - oy, r, angle + Math.PI, angle + Math.PI * 2);
      ctx!.stroke();
      ctx!.beginPath();
      ctx!.moveTo(pt.x + Math.cos(angle) * r, pt.y + Math.sin(angle) * r);
      ctx!.lineTo(pt.x - Math.cos(angle) * r, pt.y - Math.sin(angle) * r);
      ctx!.strokeStyle = rgba(colour, alpha * (1 - open * 0.85));
      ctx!.stroke();
      if (r > 9) {
        // Two outer arcs, rotating while the check runs.
        ctx!.strokeStyle = rgba(colour, alpha * 0.72);
        ctx!.lineWidth = Math.max(0.7, r * 0.05);
        ctx!.beginPath();
        ctx!.arc(pt.x, pt.y, r * 1.34, spin, spin + 1.4);
        ctx!.stroke();
        ctx!.beginPath();
        ctx!.arc(pt.x, pt.y, r * 1.34, spin + Math.PI, spin + Math.PI + 0.5);
        ctx!.stroke();
      }
    }

    /** The platform sign: what this layer checked, and what it concluded. */
    function panel(
      x0: number,
      y0: number,
      rows: [string, string][],
      title: string,
      verdict: string,
      colour: readonly number[],
      alpha: number,
    ) {
      const pw = Math.round(210 * SC);
      const rh = Math.round(17 * SC);
      const ph = Math.round(36 * SC) + rows.length * rh + Math.round(22 * SC);
      const x = cl(x0, W * 0.3, W - pw - 18 * SC);
      const y = cl(y0, 16 * SC, H * 0.5);
      const pad = Math.round(13 * SC);
      ctx!.fillStyle = rgba(pal.surface, 0.92 * alpha);
      ctx!.strokeStyle = rgba(pal.glyph, 0.4 * alpha);
      ctx!.lineWidth = Math.max(1, SC * 0.9);
      ctx!.beginPath();
      ctx!.rect(x, y, pw, ph);
      ctx!.fill();
      ctx!.stroke();
      ctx!.fillStyle = rgba(colour, 0.95 * alpha);
      ctx!.fillRect(x, y, Math.max(3, 3 * SC), ph);
      ctx!.font = `${(11 * SC).toFixed(1)}px ui-monospace, monospace`;
      ctx!.textAlign = "left";
      ctx!.fillStyle = rgba(pal.ink, 0.95 * alpha);
      ctx!.fillText(title.toLowerCase(), x + pad, y + 22 * SC);
      ctx!.font = `${(10 * SC).toFixed(1)}px ui-monospace, monospace`;
      rows.forEach((row, i) => {
        const yy = y + 40 * SC + i * rh;
        ctx!.fillStyle = rgba(pal.ink3, 0.9 * alpha);
        ctx!.fillText(row[0], x + pad, yy);
        ctx!.textAlign = "right";
        ctx!.fillStyle = rgba(pal.ink2, 0.92 * alpha);
        ctx!.fillText(row[1], x + pw - pad, yy);
        ctx!.textAlign = "left";
      });
      const vy = y + ph - 14 * SC;
      const vw = ctx!.measureText(verdict).width + 16 * SC;
      ctx!.fillStyle = rgba(colour, 0.18 * alpha);
      ctx!.fillRect(x + pad - 2, vy - 11 * SC, vw, 15 * SC);
      ctx!.fillStyle = rgba(colour, alpha);
      ctx!.fillText(verdict, x + pad + 6, vy);
      return { x, y, w: pw, h: ph };
    }

    let shown = 0;
    let seconds = 0;
    let last = 0;
    let orbit = 0.6;
    let spin = 0;
    let colour: number[] = [...TIER_COLOUR.neutral[schemeRef.current]];
    let pal = PALETTE[schemeRef.current];
    const pings: { p: Vec; t: number }[] = [];
    let pingAge = 0;
    let raf = 0;

    function frame(ts: number) {
      raf = requestAnimationFrame(frame);
      const dt = last ? Math.min((ts - last) / 16.7, 3) : 1;
      last = ts;
      seconds += dt * 0.0167;
      pal = PALETTE[schemeRef.current];

      const want = reduced ? HELD_FRAME : target.current;
      shown += (want - shown) * cl(0.09 * dt, 0, 1);
      const ph = scrollPhase(shown);
      const stage = STATIONS[ph.stop];
      const stageColour = TIER_COLOUR[stage.tier][schemeRef.current];

      // The verdict lands part-way through the stop; the packet takes that
      // tier's colour and carries it down the line.
      if (ph.dwell > 0.55) {
        for (let i = 0; i < 3; i++) {
          colour[i] = lerp(colour[i], stageColour[i], cl(0.08 * dt, 0, 1));
        }
      }
      spin += (ph.dwell > 0 ? 0.07 : 0.012) * dt;
      orbit += (ph.dwell > 0 ? 0.0022 : 0.0009) * dt;

      const packet = at(ph.trav);
      pingAge += dt;
      if (pingAge > 30 && ph.travelling > 0 && ph.intro >= 1) {
        pingAge = 0;
        pings.push({ p: [...packet] as Vec, t: 0 });
      }

      // Drone: trails the packet, orbits slowly, eased toward its target so
      // it lags and settles rather than snapping to a rig.
      const trail = basis(ph.trav - 0.3);
      const dist =
        ((ph.dwell > 0 ? 430 : 340) + 22 * Math.sin(seconds * 0.4)) *
        (0.22 + 0.78 * cl(ph.intro * 1.35 - 0.2, 0, 1)) *
        (1 + ph.out * 1.4);
      const wanted = add(
        trail.p,
        add(mul(trail.n, Math.cos(orbit) * dist * 0.85), mul(trail.b, Math.sin(orbit) * dist * 0.5 + dist * 0.42)),
      );
      camSmoothed = camSmoothed
        ? add(camSmoothed, mul(sub(wanted, camSmoothed), cl((ph.intro < 1 ? 0.12 : 0.05) * dt, 0, 1)))
        : wanted;
      cam = camSmoothed;
      const look = basis(ph.trav + (ph.dwell > 0 ? 0.02 : 0.13)).p;
      F = norm(sub(look, cam));
      R = norm(cross([0, 1, 0], F));
      U = cross(F, R);

      ctx!.fillStyle = pal.bg;
      ctx!.fillRect(0, 0, W, H);
      const haze = ctx!.createRadialGradient(CX, CY, 10, CX, CY, H * 0.95);
      haze.addColorStop(0, rgba(pal.haze, pal.hazeAlpha));
      haze.addColorStop(1, rgba(pal.haze, 0));
      ctx!.fillStyle = haze;
      ctx!.fillRect(0, 0, W, H);
      ctx!.lineCap = "round";
      ctx!.lineJoin = "round";
      bctx!.setTransform(1, 0, 0, 1, 0, 0);
      bctx!.clearRect(0, 0, bloom.width, bloom.height);

      const net = cl((ph.intro - 0.55) / 0.4, 0, 1) * cl(1 - ph.out / 0.78, 0, 1);

      if (net > 0.01) {
        const far = [...nodes].sort(
          (a, b) =>
            Math.hypot(b.x - cam[0], b.y - cam[1], b.z - cam[2]) -
            Math.hypot(a.x - cam[0], a.y - cam[1], a.z - cam[2]),
        );

        // The rest of the estate: other lines, other stations, out in the dark.
        for (const node of far) {
          for (const d of node.distant) {
            const origin = add([node.x, node.y, node.z], d.origin);
            const at0 = project(origin);
            if (!at0) continue;
            tunnel(origin, d.limb, 0.4 * net);
            if (at0.s > 0.05) {
              mark(
                at0,
                cl(at0.s * 30 * d.r, 1.5 * SC, 26 * SC),
                0,
                spin * 0.3 + node.phase,
                pal.glyph,
                visible(at0.z) * pal.glyphAlpha * net,
                LOGO,
              );
            }
          }
        }
        for (const node of far) {
          if (!project([node.x, node.y, node.z])) continue;
          for (const wire of node.wires) tunnel([node.x, node.y, node.z], wire, net * 0.9);
        }

        // The line being travelled: same construction, one gauge heavier.
        const rail: { at: Screen; world: Vec }[] = [];
        for (let u = ph.trav - 1.25; u < ph.trav + 1.4; u += 0.018) {
          const world = at(u);
          const s = project(world);
          if (s) rail.push({ at: s, world });
        }
        for (let k = 1; k < rail.length; k++) {
          const a = rail[k - 1].at;
          const b = rail[k].at;
          const v = visible(b.z);
          if (v <= 0.02) continue;
          const dv = sub(rail[k].world, packet);
          const glow = 1 / (1 + Math.pow(Math.hypot(dv[0], dv[1], dv[2]) / 300, 2.2));
          const w = cl(b.s * 22, 0.9 * SC, 24 * SC);
          const dx = b.x - a.x;
          const dy = b.y - a.y;
          const len = Math.hypot(dx, dy) || 1;
          const px = -dy / len;
          const py = dx / len;
          const h = w * 0.5;
          ctx!.strokeStyle = rgba(
            [
              lerp(pal.wall[0], colour[0], glow * 0.85),
              lerp(pal.wall[1], colour[1], glow * 0.85),
              lerp(pal.wall[2], colour[2], glow * 0.85),
            ],
            v * net * (0.4 + 0.5 * glow),
          );
          ctx!.lineWidth = Math.max(0.4, w * 0.11);
          ctx!.beginPath();
          ctx!.moveTo(a.x + px * h, a.y + py * h);
          ctx!.lineTo(b.x + px * h, b.y + py * h);
          ctx!.stroke();
          ctx!.beginPath();
          ctx!.moveTo(a.x - px * h, a.y - py * h);
          ctx!.lineTo(b.x - px * h, b.y - py * h);
          ctx!.stroke();
          ctx!.strokeStyle = rgba(pal.rail, v * net * pal.railAlpha);
          ctx!.lineWidth = Math.max(0.3 * SC, w * 0.07);
          ctx!.beginPath();
          ctx!.moveTo(a.x, a.y);
          ctx!.lineTo(b.x, b.y);
          ctx!.stroke();
          if (k % 4 === 0) {
            ctx!.strokeStyle = rgba(pal.rail, v * net * 0.38);
            ctx!.beginPath();
            ctx!.moveTo(b.x + px * h, b.y + py * h);
            ctx!.lineTo(b.x - px * h, b.y - py * h);
            ctx!.stroke();
          }
        }

        // Position pings: the packet broadcasting where it is.
        for (let i = pings.length - 1; i >= 0; i--) {
          const ring = pings[i];
          ring.t += dt;
          if (ring.t > 90) {
            pings.splice(i, 1);
            continue;
          }
          const s = project(ring.p);
          if (!s) continue;
          ctx!.beginPath();
          ctx!.arc(s.x, s.y, cl(s.s * 10, 1, 10) + ring.t * 0.9 * cl(s.s, 0.15, 1.4), 0, Math.PI * 2);
          ctx!.strokeStyle = rgba(colour, (1 - ring.t / 90) * 0.45 * visible(s.z) * net);
          ctx!.lineWidth = Math.max(1, SC * 0.9);
          ctx!.stroke();
        }

        // While running, the gate ahead is the one about to receive the packet.
        const activeIndex = ph.travelling > 0.5 ? Math.min(N - 1, ph.stop + 1) : ph.stop;
        const active = nodeAt(activeIndex);
        const gate = active ? project([active.x, active.y, active.z]) : null;

        for (const node of far) {
          const s = project([node.x, node.y, node.z]);
          if (!s) continue;
          const v = visible(s.z) * net;
          if (v <= 0.02 || node === active) continue;
          const r = cl(s.s * 40, 2 * SC, 48 * SC);
          mark(s, r, 0, spin * 0.25 + node.phase, pal.glyph, v * pal.glyphAlpha, LOGO);
          if (r > 13 * SC) {
            ctx!.font = `${(10 * SC).toFixed(1)}px ui-monospace, monospace`;
            ctx!.textAlign = "left";
            ctx!.fillStyle = rgba(pal.ink3, v * 0.55);
            ctx!.fillText(STATIONS[((node.i % N) + N) % N].asset, s.x + r * 1.6, s.y + 3);
          }
        }

        if (gate) {
          const v = visible(gate.z) * net;
          const r = cl(gate.s * 44, 3 * SC, 58 * SC);
          const ahead = project(at(ph.trav + 0.02));
          const angle = ahead ? Math.atan2(ahead.y - gate.y, ahead.x - gate.x) : 0;
          // Doors: shut as the packet arrives, part again as it leaves.
          const open =
            ph.dwell > 0
              ? ph.dwell < 0.16
                ? 1 - ph.dwell / 0.16
                : ph.dwell > 0.82
                  ? (ph.dwell - 0.82) / 0.18
                  : 0
              : 1;
          mark(gate, r, open, spin, colour, v * 0.95, angle);
          const g = bctx!.createRadialGradient(gate.x * 0.5, gate.y * 0.5, 1, gate.x * 0.5, gate.y * 0.5, r * 1.6);
          g.addColorStop(0, rgba(colour, v * (ph.dwell > 0 ? 0.45 : 0.18)));
          g.addColorStop(1, rgba(colour, 0));
          bctx!.fillStyle = g;
          bctx!.beginPath();
          bctx!.arc(gate.x * 0.5, gate.y * 0.5, r * 1.6, 0, Math.PI * 2);
          bctx!.fill();
          if (r > 13 * SC) {
            ctx!.font = `${(10.5 * SC).toFixed(1)}px ui-monospace, monospace`;
            ctx!.textAlign = "left";
            ctx!.fillStyle = rgba(pal.ink, v * 0.8);
            ctx!.fillText(STATIONS[activeIndex].asset, gate.x + r * 1.5, gate.y + 3);
          }
        }

        const head = project(packet);
        const nose = project(at(ph.trav + 0.012));
        if (head && nose) {
          const v = visible(head.z) * net;
          const angle = Math.atan2(nose.y - head.y, nose.x - head.x);
          const len = cl(head.s * 30, 3 * SC, 32 * SC);
          const wide = cl(head.s * 10, 1.2 * SC, 11 * SC);
          const g = bctx!.createRadialGradient(head.x * 0.5, head.y * 0.5, 0, head.x * 0.5, head.y * 0.5, len * 2.1);
          g.addColorStop(0, rgba(colour, v * 0.7));
          g.addColorStop(1, "rgba(0,0,0,0)");
          bctx!.fillStyle = g;
          bctx!.beginPath();
          bctx!.arc(head.x * 0.5, head.y * 0.5, len * 2.1, 0, Math.PI * 2);
          bctx!.fill();
          drawBloom();
          ctx!.save();
          ctx!.translate(head.x, head.y);
          ctx!.rotate(angle);
          ctx!.fillStyle = rgba(colour, v * 0.9);
          ctx!.beginPath();
          ctx!.ellipse(0, 0, len, wide, 0, 0, Math.PI * 2);
          ctx!.fill();
          // White-on-tier disappears on paper (THEME-BRIEF.md §2a): the core
          // inverts to a dark fill under the tier colour in light mode.
          ctx!.fillStyle = rgba(pal.core, v * 0.92);
          ctx!.beginPath();
          ctx!.ellipse(0, 0, len * 0.45, wide * 0.45, 0, 0, Math.PI * 2);
          ctx!.fill();
          ctx!.restore();
        } else {
          drawBloom();
        }

        // The platform sign clears out before the doors close, or it would
        // still be sitting off to one side under the final mark.
        if (ph.dwell > 0.1 && gate && ph.out < 0.3) {
          const alpha =
            cl((ph.dwell - 0.12) / 0.16, 0, 1) *
            (ph.dwell > 0.9 && ph.out === 0 ? cl((1 - ph.dwell) / 0.1, 0, 1) : 1) *
            cl(1 - ph.out / 0.22, 0, 1);
          if (alpha > 0.01) {
            const rows = stage.rows.slice(0, cl(Math.floor((ph.dwell - 0.14) * 8), 1, 3));
            const box = panel(
              gate.x + cl(gate.s * 54, 14, 70),
              gate.y - cl(gate.s * 54, 14, 70) - 100,
              rows,
              stage.title,
              stage.verdict,
              stageColour,
              alpha,
            );
            ctx!.strokeStyle = rgba(pal.glyph, 0.32 * alpha);
            ctx!.lineWidth = Math.max(1, SC * 0.9);
            ctx!.beginPath();
            ctx!.moveTo(gate.x, gate.y);
            ctx!.lineTo(box.x, box.y + box.h);
            ctx!.stroke();
          }
        }
      } else {
        drawBloom();
      }

      // The mark, centred: doors open on the way in, close on the way out and
      // hold as the last frame.
      if (ph.intro < 1 || ph.out > 0) {
        const cx = W / 2;
        const cy = H * 0.46;
        const r = Math.min(W * 0.52, H) * 0.26;
        let open: number;
        let alpha: number;
        let arc: number;
        if (ph.out > 0) {
          const e = 1 - Math.pow(1 - ph.out, 2.2);
          open = 1 - e;
          arc = 1;
          alpha = cl(ph.out / 0.22, 0, 1);
        } else {
          arc = 1 - Math.pow(1 - cl(ph.intro / 0.5, 0, 1), 3);
          open = cl((ph.intro - 0.45) / 0.55, 0, 1);
          alpha = 1 - open;
        }
        const ox = Math.cos(LOGO + Math.PI / 2) * r * 1.9 * open;
        const oy = Math.sin(LOGO + Math.PI / 2) * r * 1.9 * open;
        ctx!.save();
        ctx!.translate(cx, cy);
        const markColour = MARK_COLOUR[schemeRef.current];
        ctx!.lineWidth = 2.2 * SC;
        ctx!.strokeStyle = rgba(markColour, alpha * 0.95);
        ctx!.beginPath();
        ctx!.arc(ox, oy, r, LOGO, LOGO + Math.PI * arc);
        ctx!.stroke();
        ctx!.beginPath();
        ctx!.arc(-ox, -oy, r, LOGO + Math.PI, LOGO + Math.PI + Math.PI * arc);
        ctx!.stroke();
        // The chord is barred last on the way out, drawn first on the way in.
        const chord = ph.out > 0 ? cl((ph.out - 0.55) / 0.45, 0, 1) : 1 - open;
        if (chord > 0.01) {
          ctx!.beginPath();
          ctx!.moveTo(Math.cos(LOGO) * r, Math.sin(LOGO) * r);
          ctx!.lineTo(Math.cos(LOGO) * r * (1 - 2 * chord), Math.sin(LOGO) * r * (1 - 2 * chord));
          ctx!.strokeStyle = rgba(markColour, alpha * 0.92);
          ctx!.stroke();
        }
        if (ph.out > 0) {
          const seal = cl((ph.out - 0.35) / 0.4, 0, 1);
          const verdictColour = TIER_COLOUR[STATIONS[N - 1].tier][schemeRef.current];
          if (ph.out < 0.7) {
            ctx!.fillStyle = rgba(verdictColour, (1 - ph.out / 0.7) * 0.9);
            ctx!.beginPath();
            ctx!.ellipse(
              0,
              0,
              14 * SC * (1 - ph.out * 0.5),
              5 * SC * (1 - ph.out * 0.5),
              LOGO + Math.PI / 2,
              0,
              Math.PI * 2,
            );
            ctx!.fill();
          }
          if (seal > 0.01) {
            const caption = "escalated · evidence attached";
            ctx!.textAlign = "center";
            ctx!.font = `${(12 * SC).toFixed(1)}px ui-monospace, monospace`;
            const tw = ctx!.measureText(caption).width;
            ctx!.fillStyle = rgba(verdictColour, seal * 0.22);
            ctx!.fillRect(-tw / 2 - 9 * SC, r + 30 * SC, tw + 18 * SC, 20 * SC);
            ctx!.fillStyle = rgba(verdictColour, seal);
            ctx!.fillText(caption, 0, r + 44 * SC);
            ctx!.fillStyle = rgba(markColour, seal * 0.9);
            ctx!.fillText("A R B I T E R", 0, -r - 26 * SC);
            ctx!.textAlign = "left";
          }
        }
        ctx!.restore();
      }

      // A page-coloured wash in light mode instead of black (THEME-BRIEF.md
      // §2a): there's no seam to hide, so geometry dissolves into the page
      // rather than into a shadow.
      const vignette = ctx!.createRadialGradient(CX, CY, H * 0.36, CX, CY, H * 1.1);
      vignette.addColorStop(0, rgba(pal.vignette, 0));
      vignette.addColorStop(1, rgba(pal.vignette, pal.vignetteAlpha));
      ctx!.fillStyle = vignette;
      ctx!.fillRect(0, 0, W, H);
    }

    /**
     * Bright elements composite from the half-res buffer. In dark mode that's
     * an additive bloom (`lighter` — light stacking on light). In light mode
     * `lighter` does nothing (light added to white is still white), so this
     * drops to a normal composite: the same radial gradients read as a soft
     * tier-coloured halo sitting behind the packet and the gate instead.
     */
    function drawBloom() {
      ctx!.save();
      ctx!.filter = "blur(6px)";
      if (schemeRef.current === "dark") ctx!.globalCompositeOperation = "lighter";
      ctx!.drawImage(bloom, 0, 0, W, H);
      ctx!.restore();
    }

    window.addEventListener("resize", fit);
    raf = requestAnimationFrame(frame);
    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("resize", fit);
    };
  }, [reduced]);

  return (
    <canvas
      ref={canvas}
      aria-hidden="true"
      style={{ display: "block", width: "100%", height: "100%" }}
    />
  );
}
