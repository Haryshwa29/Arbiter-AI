"""Render repository-owned architecture diagrams (build-time Pillow only).

Run with Python + Pillow. No network, fonts or services are fetched.
SVGs are the static, searchable source illustrations; GIFs animate only edges.
"""
from pathlib import Path
import html
import math
import os

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "architecture"
BG, PANEL, INK, MUTED, LINE = "#101820", "#18232e", "#edf2f5", "#b0becb", "#536575"
BLUE, PURPLE, RED, GREEN, AMBER = "#8bbcff", "#c4a7ff", "#ff9c95", "#94d7b4", "#eac080"
W = 1000

# Every diagram is a top-to-bottom directed graph. Text is always visible.
CHAPTERS = [
    ("01-intake", "01 / INTAKE", "From a signal to a durable event", "Customer network / collection does not invoke the model", [
        [("sensors", "Security tools + host observations", ["Windows / Sysmon / Defender / osquery", "Network logs, attachments, optional AWS readers"], BLUE)],
        [("collect", "Collectors + adapters", ["Read approved sources; preserve raw evidence", "Maintain source checkpoints and explicit source configuration"], BLUE)],
        [("schema", "SecurityEvent v1.0", ["Validate identity, UTC time, severity and field bounds", "Reject invalid input; payload limit: 256 KiB"], BLUE)],
        [("queue", "Durable SQLite queue", ["WAL + deduplication by event identity + restart recovery", "10,000 pending/processing records; retry on queue pressure"], BLUE)],
        [("worker", "One analysis worker", ["Priority first; one in 100 claims preserves FIFO progress", "Select indexed event ID before loading the full payload"], BLUE)],
        [("context", "Correlation + context + Event adapter", ["Link recent related signals and observed asset context", "Adapt to the stable, dependency-free Event brain contract"], BLUE)],
    ], [("sensors", "collect"), ("collect", "schema"), ("schema", "queue"), ("queue", "worker"), ("worker", "context")], "Next: deterministic checks decide whether local AI is needed."),
    ("02-triage", "02 / TRIAGE", "Rules first. Local AI when needed.", "A detection decision never grants permission to execute a response", [
        [("event", "Normalized Event + scoped memory", ["Asset criticality, signature history, curated environment facts", "Facts are scope-checked against this event"], BLUE)],
        [("rails", "Pre-model security guardrails", ["Recognized dangerous signals normally escalate directly", "A narrow standing-fact exception routes to AI review, never auto-suppression"], AMBER)],
        [("filter", "Deterministic prefilter", ["Source/severity, asset criticality and verdict history", "Decide strong signals cheaply; send ambiguity to local AI"], BLUE)],
        [("local", "Local Ollama reasoning", ["Only ambiguous cases or an explicitly downgraded guardrail", "Evidence + rationale + bounded manual investigation advice"], PURPLE)],
        [("validate", "Validate the model answer", ["Recheck guardrails; validate output and suppression confidence", "Failure or low-confidence suppression becomes an escalation"], AMBER)],
        [("quiet", "Suppress", ["Written rationale", "Retain an observation"], GREEN), ("alert", "Escalate", ["Evidence + reason", "Requires review"], RED)],
        [("persist", "Persist the verdict", ["Memory history + JSONL trail + queryable SQLite audit", "Record decision tier and model provenance where available"], BLUE)],
    ], [("event", "rails"), ("rails", "filter"), ("filter", "local"), ("local", "validate"), ("validate", "quiet"), ("validate", "alert"), ("quiet", "persist"), ("alert", "persist")], "Shortcut paths: guardrail -> Escalate; decisive prefilter -> either verdict."),
    ("03-review-response", "03 / REVIEW + RESPONSE", "Explain the alert. Bound the action.", "An alert, an acknowledgement and a device action are different states", [
        [("read", "Same-origin API + live SSE", ["Operational reads require a session; writes require CSRF", "Admin checks protect privileged controls; local owner is loopback-only"], BLUE)],
        [("explain", "Operator-facing alert explanation", ["Why it triggered / executable / parent / account / command", "Uncertainty + next steps; model advice is labelled separately"], RED)],
        [("review", "Record a review", ["Acknowledgement marks reviewed; it does not mark benign", "Feedback changes scoped memory/history, not model weights"], BLUE)],
        [("deadline", "Independent L1 response workflow", ["Critical 60s / high 5m / medium 30m / low: no deadline", "Default expiry: overdue review only; no device change"], AMBER)],
        [("gate", "Explicit approval + fresh evidence + scope", ["Eligible correlation and exact peer; protect management networks", "Per-incident timed action needs separate authorization"], AMBER)],
        [("execute", "Typed native firewall operation", ["Supported peer block only; five-minute OS-owned expiry", "Check native rule state; no model-generated shell execution"], RED)],
        [("undo", "Verify / audit / expire / undo", ["Persist action and review state; verify removal when possible", "Undo removes a rule; it cannot restore interrupted sessions"], GREEN)],
    ], [("read", "explain"), ("explain", "review"), ("review", "deadline"), ("deadline", "gate"), ("gate", "execute"), ("execute", "undo")], "The action path is conditional. Most reviews need no native operation."),
    ("04-boundaries", "04 / BOUNDARIES", "Separate reasoning from authority", "Optional L2 is an agent feature; the public simulator is a separate system", [
        [("l1", "L1 escalation in the terminal agent", ["Same local telemetry; independent L2 is explicitly enabled", "Default: advice only; no automatic model download"], BLUE)],
        [("dossier", "Independent bounded L2 dossier", ["Rebuild trusted evidence; assign fact IDs; limit to 64 records", "Reject stale, cross-host, replayed or unsupported action evidence"], BLUE)],
        [("l2", "Separate local investigation + challenge", ["Distinct local model; metadata must report more than 4B parameters", "Structured assessment, gaps, alternatives, recovery and critique"], PURPLE)],
        [("policy", "L2 policy + typed executor gate", ["Model recommends human review or an exact supported peer block", "Automatic eligibility requires explicit local policy and scope"], AMBER)],
        [("customer", "Customer installation", ["Local inference + local state", "No runtime CDN or analytics"], GREEN), ("demo", "Public simulator", ["Consented cloud AI exception", "No native device actuator"], BLUE)],
        [("future", "Planned: controller + trusted edge", ["Authenticated remote telemetry and signed typed action requests", "Architecture target, not a shipped remote execution channel"], MUTED)],
    ], [("l1", "dossier"), ("dossier", "l2"), ("l2", "policy")], "Lower boxes describe deployment boundaries, not outbound data flow."),
]


def font(size, bold=False):
    folder = Path(os.environ.get("WINDIR", "C:/Windows")) / "Fonts"
    candidates = [folder / ("segoeuib.ttf" if bold else "segoeui.ttf"),
                  Path("/usr/share/fonts/truetype/dejavu/DejaVuSans" + ("-Bold" if bold else "") + ".ttf")]
    for path in candidates:
        if path.exists():
            return ImageFont.truetype(str(path), size)
    raise SystemExit("Install Segoe UI or DejaVu Sans locally; no fonts are downloaded.")


def render(chapter):
    name, kicker, title, subtitle, rows, edges, footer = chapter
    height = 240 + len(rows) * 196 + 74
    nodes = {}
    for row_index, row in enumerate(rows):
        width = 860 if len(row) == 1 else 414
        for col, (key, label, lines, color) in enumerate(row):
            nodes[key] = (70 + col * 446, 210 + row_index * 196, width, 142, label, lines, color)
    segments = []
    for start, end in edges:
        a, b = nodes[start], nodes[end]
        x1, y1, x2, y2 = a[0] + a[2]/2, a[1] + a[3], b[0] + b[2]/2, b[1]
        middle = (y1+y2)/2
        segments.append([(x1,y1),(x1,middle),(x2,middle),(x2,y2)])
    if name == "02-triage":
        # Draw real early exits around the expanded AI path, rather than
        # suggesting that every record passes through model inference.
        for start, end, outside, landing, lift in [
            ("rails", "alert", 976, 824, 20),
            ("filter", "alert", 956, 900, 36),
            ("filter", "quiet", 28, 190, 20),
        ]:
            a, b = nodes[start], nodes[end]
            side = a[0] + a[2] if outside > W/2 else a[0]
            y1, y2 = a[1] + a[3]/2, b[1]
            segments.append([(side,y1),(outside,y1),(outside,y2-lift),
                             (landing,y2-lift),(landing,y2)])
    svg = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{height}" viewBox="0 0 {W} {height}" role="img" aria-labelledby="title desc">',
           f'<title id="title">{html.escape(title)}</title><desc id="desc">{html.escape(subtitle)}. Read the accompanying architecture walkthrough for a complete text equivalent.</desc>',
           f'<rect width="{W}" height="{height}" fill="{BG}"/>']
    base = Image.new("RGB", (W,height), BG)
    draw = ImageDraw.Draw(base)
    def text(x,y,value,size,color=INK,bold=False):
        face=font(size,bold)
        if draw.textlength(value,font=face) > W-140:
            raise ValueError(f"Text overflow: {value}")
        draw.text((x,y),value,font=face,fill=color)
        svg.append(f'<text x="{x}" y="{y+size}" fill="{color}" font-family="Segoe UI,DejaVu Sans,sans-serif" font-size="{size}" font-weight="{600 if bold else 400}">{html.escape(value)}</text>')
    text(70,40,kicker,20,BLUE,True)
    text(70,82,title,37,INK,True)
    text(70,142,subtitle,19,MUTED)
    for points in segments:
        draw.line(points,fill=LINE,width=3)
        x,y=points[-1]
        draw.polygon([(x,y),(x-6,y-9),(x+6,y-9)],fill=LINE)
        svg.append(f'<polyline points="{" ".join(f"{x},{y}" for x,y in points)}" fill="none" stroke="{LINE}" stroke-width="3"/>')
        svg.append(f'<path d="M{x-6},{y-9} L{x},{y} L{x+6},{y-9}" fill="none" stroke="{LINE}" stroke-width="3"/>')
    for x,y,width,h,label,lines,color in nodes.values():
        draw.rounded_rectangle((x,y,x+width,y+h),radius=12,fill=PANEL,outline=LINE,width=1)
        draw.line((x+1,y+20,x+1,y+h-20),fill=color,width=4)
        svg.append(f'<rect x="{x}" y="{y}" width="{width}" height="{h}" rx="12" fill="{PANEL}" stroke="{LINE}"/><path d="M{x+1},{y+20} V{y+h-20}" stroke="{color}" stroke-width="4"/>')
        text(x+24,y+19,label,25,color,True)
        for i,line in enumerate(lines):
            if draw.textlength(line,font=font(20)) > width-48:
                raise ValueError(f"Node text overflow: {line}")
            text(x+24,y+64+i*29,line,20,MUTED)
    text(70,height-70,footer,18,MUTED)
    svg.append('</svg>')
    OUT.mkdir(parents=True,exist_ok=True)
    (OUT/f'{name}.svg').write_text('\n'.join(svg)+'\n',encoding='utf-8')
    base.save(OUT/f'{name}.png',optimize=True)
    # One quiet loop; all text and geometry stay fixed for readable scrolling.
    frames=[]
    for frame in range(48):
        canvas=base.copy(); painter=ImageDraw.Draw(canvas)
        for edge_index,points in enumerate(segments):
            phase=(frame/48-edge_index*.14)%1
            lengths=[math.dist(a,b) for a,b in zip(points,points[1:])]
            distance=phase*sum(lengths)
            for a,b,length in zip(points,points[1:],lengths):
                if distance <= length and length:
                    t=distance/length; x=a[0]+(b[0]-a[0])*t; y=a[1]+(b[1]-a[1])*t
                    painter.ellipse((x-5,y-5,x+5,y+5),fill=BLUE)
                    break
                distance-=length
        frames.append(canvas.quantize(colors=96))
    frames[0].save(OUT/f'{name}.gif',save_all=True,append_images=frames[1:],duration=100,loop=0,optimize=True,disposal=1)
    print(f'{name}: {W}x{height}; {(OUT/f"{name}.gif").stat().st_size//1024} KiB')


if __name__ == '__main__':
    for chapter in CHAPTERS:
        render(chapter)
