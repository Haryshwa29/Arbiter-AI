/**
 * The landing page as ONE composition.
 *
 * A single scroll timeline drives everything. The flight scope is a tall
 * scroll region containing one sticky viewport; the field is rendered once
 * inside it and never re-mounts.
 *
 * Immersive, not split: the field is full-bleed and the copy sits over it,
 * bottom-left against --gutter, cross-fading in place (THEME-BRIEF.md §2b —
 * briefly centred on 2026-07-30 and moved back the same day: centred display
 * type over a centred field left nothing for the eye to start from). The
 * sections below the flight ARE centred — see `Sections()` — it's only the
 * hero that isn't. An earlier pass gave the copy its own 44% lane, which
 * read as two things side by side rather than one place you are inside. A
 * `to top` scrim keeps the type legible over the geometry, and the line map
 * at the right edge doubles as the section index.
 *
 * Measure (THEME-BRIEF.md §2c) is set per element in that element's own
 * units — `ch` resolves against the element's own font size, so a measure
 * set once on a shared wrapper is inherited by every font size nested
 * inside it. That was the bug: one 58ch wrapper computed from ~11px body
 * text, inherited by a 71px h1, wrapped the headline to nine characters a
 * line. `h1`/`lead`/`h2`/`body` below each carry their own max-width.
 *
 * Beat timing matches the station blocks in TransitField (INTRO, SPAN, DWELL),
 * so a caption is at full opacity exactly while the packet is standing at the
 * station it describes, and fades as it runs to the next one.
 *
 * Indexing and accessibility: every word is in the DOM at all times. Scroll
 * touches opacity only — nothing is display:none, nothing is conditionally
 * rendered — so the prerendered HTML is complete and a reduced-motion visitor
 * gets the entire page with the flight held at a readable frame.
 */

import { useEffect, useRef, useState } from "react";
import {
  motion,
  useMotionValue,
  useScroll,
  useSpring,
  useTransform,
  useReducedMotion,
  type MotionValue,
} from "framer-motion";
import { TransitField, STATIONS, TIER_COLOUR } from "./TransitField";
import { useResolvedScheme, type Scheme } from "../lib/scheme";

const DESKTOP_QUERY = "(min-width: 900px)";
const RELEASES_URL = "https://github.com/Haryshwa29/Arbiter-AI/releases";
const REPO_URL = "https://github.com/Haryshwa29/Arbiter-AI";

/** Must match TransitField: intro, five station blocks, outro. */
const INTRO = 0.075;
const OUTRO = 0.15;
const SPAN = (1 - INTRO - OUTRO) / STATIONS.length;
const DWELL = 0.46;

/**
 * One beat per station, keyed to that station's block so copy and geometry
 * are the same object. Fades up as the doors shut, holds through the check,
 * fades as the packet runs on.
 */
const BEATS: { eyebrow: string; head: string; body: string }[] = [
  {
    eyebrow: "Collect",
    head: "Everything your systems say, all of it.",
    body: "An agent watches your log streams where they already are. Nothing is shipped out, nothing is sampled, nothing is thrown away.",
  },
  {
    eyebrow: "Triage",
    head: "Almost all of it is nothing.",
    body: "A cheap score weighs how severe the event is against how much that machine matters and what this exact signature has done before. No AI, no cost, instant.",
  },
  {
    eyebrow: "Guardrails",
    head: "Some things are never explained away.",
    body: "Credential dumping, privilege escalation, a shell piped from the internet. Hard rules sit on both sides of the model — it cannot talk its way past them.",
  },
  {
    eyebrow: "Local model",
    head: "Only the genuinely ambiguous gets read.",
    body: "The handful that scoring couldn't settle reach an open-weights model running on your own hardware. Nothing about the event leaves the building.",
  },
  {
    eyebrow: "Decision",
    head: "It wakes you, or it writes down why it didn't.",
    body: "Escalations arrive with the evidence already assembled. Suppressions carry a written rationale you can read back months later. There is no silent verdict.",
  },
];

/** [fade-in start, full, hold-until, faded-out] for station k. */
function beatRange(k: number): [number, number, number, number] {
  const start = INTRO + k * SPAN;
  const dwellEnd = start + SPAN * DWELL;
  const last = k === STATIONS.length - 1;
  return [start, start + SPAN * 0.08, last ? 1 - OUTRO : dwellEnd, last ? 1 - OUTRO * 0.4 : dwellEnd + SPAN * 0.22];
}

export function Landing() {
  const reduced = useReducedMotion();
  const scheme = useResolvedScheme();
  const [isDesktop, setIsDesktop] = useState(false);
  /** A frame mid-flight, for the stacked layout where nothing drives the field. */
  const still = useMotionValue(0.42);

  useEffect(() => {
    const mq = window.matchMedia(DESKTOP_QUERY);
    const update = () => setIsDesktop(mq.matches);
    update();
    mq.addEventListener("change", update);
    return () => mq.removeEventListener("change", update);
  }, []);

  // The stacked layout is also what SSR and first paint render, since the
  // viewport-match effect hasn't run yet. That is deliberate: the prerendered
  // HTML then contains every layer's copy at full opacity rather than five
  // blocks at opacity 0, and a phone gets one held frame instead of a
  // scroll-driven animation it did not ask to pay for.
  //
  // Flight is a separate component, not an inline branch here, because its
  // `scope` ref must be attached to a mounted DOM node in the SAME commit
  // that `useScroll({ target: scope })` first subscribes — otherwise
  // Framer's scroll listener binds to a still-null ref and never notices
  // the div arriving on a later render (mutating .current doesn't retrigger
  // the effect that reads it). Keeping the hook here, gated by `isDesktop`,
  // reproduced exactly that bug: the field would render its opening frame
  // and then never move again, however far the page was scrolled.
  if (!isDesktop) return <Stacked still={still} scheme={scheme} />;
  return <Flight reduced={reduced} scheme={scheme} />;
}

function Flight({ reduced, scheme }: { reduced: boolean | null; scheme: Scheme }) {
  const scope = useRef<HTMLDivElement>(null);
  const { scrollYProgress } = useScroll({ target: scope, offset: ["start start", "end end"] });

  // One spring on the driver, never on the consumers. Shared inertia is what
  // makes the field, the doors and the copy read as one moving object rather
  // than several things animating near each other.
  const smooth = useSpring(scrollYProgress, { stiffness: 78, damping: 24, mass: 0.6 });
  const held = useTransform(smooth, (v) => (reduced ? 0.42 : v));

  return (
    <div style={{ background: "var(--bg)", color: "var(--ink)" }}>
      {/* 726vh = 660vh * 1.1: 10% more scroll distance per the same normalized
          timeline, so the sequence reads 10% slower without touching any of
          the decided INTRO/SPAN/DWELL/OUTRO proportions. */}
      <div ref={scope} style={{ position: "relative", height: "726vh" }}>
        <div style={{ position: "sticky", top: 0, height: "100vh", overflow: "hidden" }}>
          <div style={{ position: "absolute", inset: 0 }}>
            <TransitField p={held} scheme={scheme} />
          </div>

          {/* Keeps the type legible where it overlaps the geometry. */}
          <div
            style={{
              position: "absolute",
              inset: 0,
              zIndex: 2,
              pointerEvents: "none",
              background:
                "linear-gradient(to top, var(--bg) 2%, color-mix(in srgb, var(--bg) 90%, transparent) 22%, color-mix(in srgb, var(--bg) 35%, transparent) 46%, transparent 68%)",
            }}
          />

          <div
            style={{
              position: "absolute",
              inset: "auto 0 0 0",
              zIndex: 3,
              display: "grid",
              justifyItems: "start",
              alignContent: "end",
              padding: "0 var(--gutter) 10vh",
              pointerEvents: "none",
            }}
          >
            <Hero p={held} />
            {BEATS.map((b, i) => (
              <Beat key={b.eyebrow} p={held} range={beatRange(i)} {...b} />
            ))}
          </div>

          <LineMap p={held} scheme={scheme} />
          <ScrollHint p={held} />
        </div>
      </div>

      <Sections />
    </div>
  );
}

/**
 * No pinning, no scroll timeline: the hero, one held frame of the field, then
 * every layer as ordinary prose. Used on narrow viewports and by the
 * prerender, so the indexed HTML is the complete page.
 */
function Stacked({ still, scheme }: { still: MotionValue<number>; scheme: Scheme }) {
  return (
    <div style={{ background: "var(--bg)", color: "var(--ink)" }}>
      <div style={{ padding: "8vh var(--gutter) 0" }}>
        <h1 style={{ ...h1, maxWidth: "14ch" }}>
          A shield you can raise <span style={{ color: "var(--ink-3)" }}>before you can afford an army.</span>
        </h1>
        <p style={{ ...body, maxWidth: "42ch", marginTop: "1em" }}>
          Arbiter is a self-hosted AI security analyst. It reads every line your systems write, inside
          your network, and only wakes you when something earns it.
        </p>
      </div>

      <div style={{ position: "relative", height: "52vh", margin: "6vh 0" }}>
        <TransitField p={still} scheme={scheme} />
        <div
          style={{
            position: "absolute",
            inset: 0,
            pointerEvents: "none",
            background:
              "linear-gradient(to top, var(--bg) 1%, color-mix(in srgb, var(--bg) 55%, transparent) 22%, transparent 55%, color-mix(in srgb, var(--bg) 60%, transparent) 99%)",
          }}
        />
      </div>

      <section style={{ ...section, paddingTop: 0 }}>
        <div style={{ display: "grid", gap: "3.2em", maxWidth: "min(1180px, var(--band))", margin: "0 auto" }}>
          {BEATS.map((b) => (
            <div key={b.eyebrow}>
              <p style={eyebrowStyle}>{b.eyebrow}</p>
              <h2 style={{ ...h2, maxWidth: "20ch" }}>{b.head}</h2>
              <p style={{ ...body, maxWidth: "46ch", marginTop: "1em" }}>{b.body}</p>
            </div>
          ))}
        </div>
      </section>

      <Sections />
    </div>
  );
}

function Hero({ p }: { p: MotionValue<number> }) {
  const opacity = useTransform(p, [0, INTRO * 0.55, INTRO * 1.1], [1, 1, 0]);
  const y = useTransform(p, [0, INTRO * 1.1], [0, -44]);
  return (
    <motion.div style={{ gridArea: "1 / 1", opacity, y }}>
      <h1 style={{ ...h1, maxWidth: "14ch" }}>
        A shield you can raise <span style={{ color: "var(--ink-3)" }}>before you can afford an army.</span>
      </h1>
      <p style={{ ...body, maxWidth: "42ch", marginTop: "1em" }}>
        Arbiter is a self-hosted AI security analyst. It reads every line your systems write, inside
        your network, and only wakes you when something earns it.
      </p>
    </motion.div>
  );
}

/**
 * Beats are stacked in the same grid cell as each other and the hero, so they
 * cross-fade in place. Nothing translates across the field.
 */
function Beat({
  p,
  range,
  eyebrow,
  head,
  body: copy,
}: {
  p: MotionValue<number>;
  range: [number, number, number, number];
  eyebrow: string;
  head: string;
  body: string;
}) {
  const opacity = useTransform(p, range, [0, 1, 1, 0]);
  const y = useTransform(p, range, [22, 0, 0, -22]);
  return (
    <motion.div style={{ gridArea: "1 / 1", opacity, y }}>
      <p style={eyebrowStyle}>{eyebrow}</p>
      <h2 style={{ ...h2, maxWidth: "20ch" }}>{head}</h2>
      <p style={{ ...body, maxWidth: "46ch", marginTop: "1em" }}>{copy}</p>
    </motion.div>
  );
}

/** Five stops down the right edge — the metaphor doing double duty as an index. */
function LineMap({ p, scheme }: { p: MotionValue<number>; scheme: Scheme }) {
  return (
    <div
      style={{
        position: "absolute",
        right: "calc(var(--gutter) * 0.6)",
        top: "50%",
        transform: "translateY(-50%)",
        zIndex: 4,
        display: "grid",
        gap: "1.1em",
        fontFamily: "ui-monospace, monospace",
        fontSize: "var(--fs-tiny)",
        letterSpacing: "0.14em",
        pointerEvents: "none",
      }}
    >
      {STATIONS.map((s, i) => (
        <Stop key={s.title} p={p} index={i} label={s.title.toLowerCase()} colour={TIER_COLOUR[s.tier][scheme]} />
      ))}
    </div>
  );
}

function Stop({
  p,
  index,
  label,
  colour,
}: {
  p: MotionValue<number>;
  index: number;
  label: string;
  colour: readonly number[];
}) {
  const [a, b, c, d] = beatRange(index);
  const lit = useTransform(p, [a, b, c, d], [0, 1, 1, 0]);
  const opacity = useTransform(lit, (v) => 0.34 + v * 0.66);
  const color = useTransform(lit, (v) => (v > 0.5 ? `rgb(${colour.join(",")})` : "var(--ink-3)"));
  return (
    <motion.div
      style={{
        display: "flex",
        alignItems: "center",
        gap: "0.7em",
        justifyContent: "flex-end",
        opacity,
        color,
      }}
    >
      <span>{label}</span>
      <i
        style={{
          width: "0.62em",
          height: "0.62em",
          borderRadius: "50%",
          border: "1px solid currentColor",
          display: "block",
          flex: "none",
        }}
      />
    </motion.div>
  );
}

function ScrollHint({ p }: { p: MotionValue<number> }) {
  const opacity = useTransform(p, [0, 0.02, 0.05], [1, 1, 0]);
  return (
    <motion.div
      style={{
        position: "absolute",
        bottom: "2.2rem",
        left: 0,
        right: 0,
        textAlign: "center",
        opacity,
        zIndex: 4,
        fontFamily: "ui-monospace, monospace",
        fontSize: "var(--fs-tiny)",
        letterSpacing: "0.24em",
        color: "var(--ink-4)",
        pointerEvents: "none",
      }}
    >
      SCROLL
    </motion.div>
  );
}

/**
 * Fade-and-rise on scroll into view, gated behind reduced-motion exactly as
 * Login.tsx and LiveFeed.tsx already do (AGENTS.md § Design). `once: true`
 * means it plays on the way down and stays settled on the way back up —
 * a section re-entering view doesn't restart its own animation.
 */
function useReveal(reduced: boolean | null, delay = 0) {
  return {
    initial: reduced ? false : ({ opacity: 0, y: 14 } as const),
    whileInView: { opacity: 1, y: 0 },
    viewport: { once: true, margin: "-10% 0px" },
    transition: { duration: 0.5, ease: [0.16, 1, 0.3, 1] as const, delay },
  };
}

const hairline = "border-t border-[var(--hair)]";

/**
 * Everything after the flight. Three sections, three different rhythms —
 * prose-only, prose-plus-artifact, then a two-column close — so the page
 * doesn't read as the same bordered block repeated three times.
 */
function Sections() {
  const reduced = useReducedMotion();

  return (
    <>
      <section style={{ ...section, paddingTop: "16vh" }} className={hairline}>
        <motion.div style={grid} {...useReveal(reduced)}>
          <p style={eyebrowStyle}>The problem</p>
          <Lines
            lead="Detection tooling has never been better. Almost all of it assumes a person on the other end — someone to write the rules, tune the noise, and read the dashboard each morning."
            lines={[
              "Wazuh, Elastic, Security Onion: excellent, and free like a puppy. Someone still has to raise it.",
              "You have real log volume and no security hire. That seat stays empty whether or not you buy the software.",
            ]}
          />
        </motion.div>
      </section>

      <section style={section} className={`${hairline} relative overflow-hidden`}>
        {/* Barely-there tonal wash, not a color — depth without a gradient
            that reads as "AI startup blob". */}
        <div
          className="pointer-events-none absolute inset-0"
          style={{
            background:
              "radial-gradient(60% 50% at 15% 0%, color-mix(in srgb, var(--ink) 6%, transparent), transparent)",
          }}
        />
        <motion.div style={{ ...grid, position: "relative" }} {...useReveal(reduced)}>
          <p style={eyebrowStyle}>Why you can trust it</p>
          <Lines
            lead="Shadow mode first. A new install scores alongside you for weeks before it earns the right to suppress anything."
            lines={[
              "Inference runs locally on an open-weights model. Nothing about an event ever leaves your network to reach a cloud API.",
              "Memory is a plain, readable database — not fine-tuned weights. You can see exactly why it believes what it believes.",
            ]}
          />
          <VerdictCard reduced={reduced} />
        </motion.div>
      </section>

      <section style={{ ...section, paddingBottom: "20vh" }} className={hairline}>
        <motion.div style={grid} {...useReveal(reduced)}>
          <h2 style={{ ...h2, maxWidth: "18ch" }}>Install it, read it, then run it.</h2>
          <p style={{ ...body, maxWidth: "62ch", marginTop: "0.7em" }}>
            Released builds ship as a single readable zipapp plus a short bootstrap script, verified
            against published checksums. Arbiter's own prefilter would escalate a pipe-to-shell
            one-liner, so the install instructions never ask you to run one.
          </p>
          <div className="flex flex-wrap justify-center gap-3">
            <a href={RELEASES_URL} className={ctaClass}>
              Get the latest release
            </a>
            <a href={REPO_URL} className={ghostClass}>
              Look at the code
            </a>
          </div>
        </motion.div>
      </section>
    </>
  );
}

/**
 * The one honest artifact: a verdict, drawn from static sample data. Clearly
 * illustrative, not a screenshot of a live instance. The border is a 1px
 * gradient wrapper (brighter at the top edge, fading down) rather than a
 * flat stroke, so it reads as a surface catching light instead of an outline.
 * Rows assemble in on scroll — the card builds itself once, gated the same
 * way as everything else on the page.
 */
function VerdictCard({ reduced }: { reduced: boolean | null }) {
  const rows: [string, string][] = [
    ["tier", "prefilter"],
    ["evidence", "12 failed, 1 success, one source"],
  ];
  return (
    <div
      className="rounded-[10px] p-px"
      style={{
        background:
          "linear-gradient(180deg, color-mix(in srgb, var(--ink) 14%, transparent), color-mix(in srgb, var(--ink) 2%, transparent))",
        maxWidth: "min(560px, 46vw)",
        marginTop: "1rem",
      }}
    >
      <div
        className="rounded-[10px]"
        style={{
          background: "var(--surface)",
          padding: "1.3em 1.4em",
          fontFamily: "ui-monospace, monospace",
          fontSize: "var(--fs-ui)",
          lineHeight: 1.8,
          color: "var(--ink-3)",
          textAlign: "left",
        }}
      >
        <motion.div
          style={{ color: "var(--ink)" }}
          initial={reduced ? false : { opacity: 0, y: 6 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: "-10% 0px" }}
          transition={{ duration: 0.4, delay: 0.05 }}
        >
          sshd:brute_force:web-prod-01
        </motion.div>
        {rows.map(([k, v], i) => (
          <motion.div
            key={k}
            initial={reduced ? false : { opacity: 0, y: 6 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, margin: "-10% 0px" }}
            transition={{ duration: 0.4, delay: 0.05 + (i + 1) * 0.08 }}
          >
            {k}
            {" ".repeat(Math.max(1, 9 - k.length))}
            {v}
          </motion.div>
        ))}
        <motion.div
          style={{ marginTop: "0.6em" }}
          initial={reduced ? false : { opacity: 0, y: 6 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: "-10% 0px" }}
          transition={{ duration: 0.4, delay: 0.05 + (rows.length + 1) * 0.08 }}
        >
          <span
            style={{
              display: "inline-block",
              padding: "0.2em 0.6em",
              borderRadius: 4,
              fontSize: "var(--fs-tiny)",
              letterSpacing: "0.12em",
              background: "color-mix(in srgb, var(--tier-escalate) 16%, transparent)",
              color: "var(--tier-escalate)",
            }}
          >
            ESCALATE
          </span>
          <span style={{ marginLeft: "0.6em", color: "var(--ink-3)" }}>
            block ip /32 · ttl 30m · recommend
          </span>
        </motion.div>
      </div>
    </div>
  );
}

/**
 * `lead` is the section's opening statement — a size and weight step above
 * the rest, so each block has one thing the eye lands on first instead of
 * three identically-weighted lines.
 */
function Lines({ lead, lines }: { lead: string; lines: string[] }) {
  return (
    <div style={{ display: "grid", gap: "1.1em" }}>
      <p style={{ ...leadStrong, maxWidth: "62ch", margin: 0 }}>{lead}</p>
      {lines.map((l) => (
        <p key={l} style={{ ...body, maxWidth: "62ch", margin: 0 }}>
          {l}
        </p>
      ))}
    </div>
  );
}

const section: React.CSSProperties = { padding: "14vh var(--gutter)", position: "relative" };

/**
 * Sections below the flight read as one centred column of prose
 * (THEME-BRIEF.md §2b) — unlike the hero above them, which is left-aligned.
 * `justifyItems` centres each grid item (including a fixed-width artifact
 * like the verdict card) and `textAlign` centres the prose inside it. Each
 * child still carries its own measure (§2c) rather than relying on this
 * wrapper's width.
 */
const grid: React.CSSProperties = {
  display: "grid",
  gap: "1.6em",
  maxWidth: "min(1180px, var(--band))",
  margin: "0 auto",
  width: "100%",
  justifyItems: "center",
  textAlign: "center",
};

const h1: React.CSSProperties = {
  fontSize: "var(--fs-h1)",
  lineHeight: 1.02,
  letterSpacing: "-0.035em",
  fontWeight: 500,
  margin: 0,
  textWrap: "balance",
};

const h2: React.CSSProperties = {
  fontSize: "var(--fs-h2)",
  lineHeight: 1.14,
  letterSpacing: "-0.02em",
  fontWeight: 500,
  margin: 0,
  textWrap: "balance",
};

const body: React.CSSProperties = {
  fontSize: "var(--fs-body)",
  lineHeight: 1.62,
  color: "var(--ink-2)",
  margin: 0,
  textWrap: "pretty",
};

/** The one line each section opens on — a step up in size and weight so
 * the eye has somewhere to land first, instead of three equal-weight lines. */
const leadStrong: React.CSSProperties = {
  fontSize: "var(--fs-lead)",
  lineHeight: 1.55,
  fontWeight: 500,
  letterSpacing: "-0.01em",
  color: "var(--ink)",
  margin: 0,
  textWrap: "pretty",
};

const eyebrowStyle: React.CSSProperties = {
  fontFamily: "ui-monospace, monospace",
  fontSize: "var(--fs-eb)",
  letterSpacing: "0.2em",
  color: "var(--ink-4)",
  margin: "0 0 1em",
};

const ctaClass =
  "inline-flex items-center rounded-md bg-[var(--cta-bg)] px-[1.2em] py-[0.7em] text-[length:var(--fs-ui)] font-medium text-[var(--cta-ink)] no-underline transition-opacity duration-200 hover:opacity-85";

const ghostClass =
  "inline-flex items-center rounded-md border border-[var(--hair-2)] px-[1.2em] py-[0.7em] text-[length:var(--fs-ui)] text-[var(--ink)] no-underline transition-colors duration-200 hover:border-[var(--ink-3)] hover:bg-[color-mix(in_srgb,var(--ink)_4%,transparent)]";
