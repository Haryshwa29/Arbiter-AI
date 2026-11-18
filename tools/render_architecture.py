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
    ("01-intake", "01 / GATHER THE EVIDENCE", "Read, organize and keep the clues", "Collection gathers information; it does not ask AI to change a device", [
        [("sensors", "Security tools report what they saw", ["Windows, Sysmon, Defender, osquery, Wazuh and Suricata", "Optional sources work only when enabled and permitted"], BLUE)],
        [("collect", "Read the sources you enabled", ["Keep the original reports so a person can inspect them", "Remember where reading stopped so collection can resume"], BLUE)],
        [("schema", "Put the evidence in a common format", ["Check computer, user, time, process and network details", "Reject broken or oversized records; keep the originals"], BLUE)],
        [("queue", "Save a waiting line of events", ["Avoid duplicate records and recover waiting work after a restart", "The line has a limit; report when new work exceeds capacity"], BLUE)],
        [("worker", "Choose the next event to examine", ["Urgent events usually go first; older events also get a turn", "One worker reads the selected event and prepares it for review"], BLUE)],
        [("context", "Connect related clues", ["Look at nearby events, the computer's role and past decisions", "Pass useful evidence to the rules and, when needed, the AI"], BLUE)],
    ], [("sensors", "collect"), ("collect", "schema"), ("schema", "queue"), ("queue", "worker"), ("worker", "context")], "Next: deterministic checks decide whether local AI is needed."),
    ("02-triage", "02 / DECIDE WHAT NEEDS ATTENTION", "Rules first. Qwen3.5 when needed.", "The AI can recommend a decision; it cannot authorize changes to a device", [
        [("event", "Start with the event and relevant history", ["Check how important the computer is and what happened before", "Use approved facts only when they fit this exact event"], BLUE)],
        [("rails", "Safety rules: must someone review this?", ["Known risky signals normally create an alert without asking AI", "An exact approved fact can allow AI review, never dismissal by itself"], AMBER)],
        [("filter", "Quick rules: is the answer already clear?", ["Keep clearly routine records quietly; flag clearly risky ones", "Ask the AI when the rules do not have enough support to decide"], BLUE)],
        [("local", "Qwen3.5: a replaceable local AI model", ["Read unclear alerts and explain a recommendation", "Another compatible local model can replace Qwen3.5"], PURPLE)],
        [("validate", "Check the AI's recommendation", ["Safety rules still apply; a fluent explanation is not proof", "If the AI fails or is too unsure, ask a person to review"], AMBER)],
        [("quiet", "Keep an observation", ["Write why it was quieted", "Keep the record"], GREEN), ("alert", "Flag for review", ["Show the evidence and reason", "Ask a person to investigate"], RED)],
        [("persist", "Save the decision and its reason", ["Keep the evidence, history and rule or model that decided", "Make the result available for a person to check later"], BLUE)],
    ], [("event", "rails"), ("rails", "filter"), ("filter", "local"), ("local", "validate"), ("validate", "quiet"), ("validate", "alert"), ("quiet", "persist"), ("alert", "persist")], "Side arrows show where safety rules or quick rules can decide without AI."),
    ("03-review-response", "03 / EXPLAIN AND REVIEW", "Show the person what to check", "Seeing an alert or marking it reviewed does not change the computer", [
        [("read", "Control who can see and change things", ["The dashboard reads through the protected application interface", "Sensitive controls need the right permission; local access stays local"], BLUE)],
        [("explain", "Explain the alert in everyday language", ["Say what triggered, where it came from and what remains unknown", "Show manual checks; label AI suggestions as advice"], RED)],
        [("review", "Record what the person decided", ["Marking an alert reviewed does not prove it harmless", "Corrections update matching history; they do not retrain Qwen3.5"], BLUE)],
        [("deadline", "Track when a review is due", ["More urgent cases get shorter review windows", "An overdue case normally stays overdue; it does not change a device"], AMBER)],
        [("gate", "Check approval, fresh evidence and the target", ["A supported response needs permission and a precise target", "Protect essential connections; reject stale or unsupported requests"], AMBER)],
        [("execute", "Apply only the supported temporary action", ["Where enabled, block one approved peer for five minutes", "Use fixed operations; never run commands invented by the AI"], RED)],
        [("undo", "Check the action, expiry and removal", ["Record what happened and check that a rule was removed", "Undo cannot restore a connection that was already interrupted"], GREEN)],
    ], [("read", "explain"), ("explain", "review"), ("review", "deadline"), ("deadline", "gate"), ("gate", "execute"), ("execute", "undo")], "The action path is conditional. Most reviews need no native operation."),
    ("04-boundaries", "04 / KEEP RESPONSIBILITIES SEPARATE", "An AI opinion is not permission", "The optional second opinion and public demonstration have separate limits", [
        [("l1", "L1 first reviewer: Qwen3.5:4b", ["Review unclear events; escalate those needing a deeper review", "Only Qwen's escalations enter Gemma's queue"], BLUE)],
        [("dossier", "Give the second brain the recorded facts", ["Qwen's earlier opinion is context, not independent proof", "Historical records stay historical and grant no action rights"], BLUE)],
        [("l2", "L2 final reviewer: Gemma4:12b", ["Assess the evidence, then challenge that decision in a second pass", "Keep or suppress Qwen's alert with a written explanation"], PURPLE)],
        [("policy", "Check the decision; preserve both reviews", ["Suppression needs checked facts, confidence and an accepted challenge", "Uncertainty or failure retains the alert; no device action rights"], AMBER)],
        [("customer", "Customer installation", ["AI and records stay local", "No tracking or remote assets"], GREEN), ("demo", "Public demonstration", ["Separate consented cloud demo", "Cannot change your device"], BLUE)],
        [("future", "Planned: coordinate protected devices", ["A future controller would send authenticated, restricted requests", "This remote design is planned; it is not a shipped protection claim"], MUTED)],
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
