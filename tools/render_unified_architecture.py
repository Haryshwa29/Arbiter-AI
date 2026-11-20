"""Render the current six-worker documentation diagram; local Pillow only."""
from pathlib import Path
import html
import math

from PIL import Image, ImageDraw
from render_architecture import font

OUT = Path(__file__).resolve().parents[1] / 'docs' / 'architecture'
W, H = 1440, 2540
BG, INK, MUTED = '#0d1420', '#eef3fa', '#b8c5d8'
BLUE, PURPLE, RED, GREEN, GOLD = '#82b7ff', '#c4a0ff', '#ff939b', '#7cddb0', '#f2c777'
base = Image.new('RGB', (W, H), BG)
d = ImageDraw.Draw(base)
svg = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" role="img" aria-labelledby="title desc">',
       '<title id="title">Arbiter AI: five decision workers and one CPU report worker</title>',
       '<desc id="desc">Only successful Qwen3.5:4b escalations enter the L2 pre-filter. Supported routine cases can be suppressed; unresolved cases, including missing context, reach Gemma4:12b. Proposed Gemma suppressions require a checking call. All L1 and L2 exits pass shared final guardrails. Saved decisions reach the dashboard immediately; a separate CPU worker prepares reports without model calls. Scoped live pattern memory feeds each pre-filter. Either model is replaceable. Classification grants no device-action rights.</desc>',
       f'<rect width="{W}" height="{H}" fill="{BG}"/>']
paths = []


def text(x, y, value, size=22, color=INK, bold=False, width=None):
    face = font(size, bold)
    assert x >= 0 and y >= 0 and y+size+8 < H, 'Text outside canvas: '+value
    assert d.textlength(value, font=face) <= (width if width else W-x-28), 'Text overflow: '+value
    d.text((x, y), value, font=face, fill=color)
    svg.append(f'<text x="{x}" y="{y+size}" fill="{color}" font-family="Segoe UI,DejaVu Sans,sans-serif" font-size="{size}" font-weight="{700 if bold else 400}">{html.escape(value)}</text>')


def box(y, title, lines, color=BLUE, x=330, width=780, height=130):
    assert x >= 0 and x+width < W and y+height < H
    fill = '#241c35' if color == PURPLE else '#172335'
    d.rounded_rectangle((x, y, x+width, y+height), radius=16, fill=fill, outline=color, width=2)
    svg.append(f'<rect x="{x}" y="{y}" width="{width}" height="{height}" rx="16" fill="{fill}" stroke="{color}" stroke-width="2"/>')
    text(x+22, y+14, title, 26, color, True, width-44)
    for i, line in enumerate(lines):
        assert 56+i*28+26 <= height, 'Text outside box: '+line
        text(x+22, y+56+i*28, line, 21, MUTED, width=width-44)


def edge(points, color=BLUE, label=(), label_x=0, label_y=0):
    paths.append((points, color))
    d.line(points, fill=color, width=3)
    svg.append(f'<polyline points="{" ".join(f"{x},{y}" for x,y in points)}" fill="none" stroke="{color}" stroke-width="3" stroke-linejoin="round"/>')
    a, b = points[-2:]
    theta = math.atan2(b[1]-a[1], b[0]-a[0])
    x, y = b
    wings = [(x-11*math.cos(theta)+s*6*math.sin(theta), y-11*math.sin(theta)-s*6*math.cos(theta)) for s in (-1, 1)]
    d.polygon([b, *wings], fill=color)
    svg.append(f'<polygon points="{x},{y} {wings[0][0]},{wings[0][1]} {wings[1][0]},{wings[1][1]}" fill="{color}"/>')
    for i, line in enumerate(label):
        text(label_x, label_y+i*24, line, 18, color, True)


text(54, 30, 'ARBITER AI / CURRENT PROJECT DESIGN / NOVEMBER 2026', 21, BLUE, True)
text(54, 76, 'Two brains decide. A separate worker explains.', 38, INK, True)
text(54, 134, 'Five decision workers + one CPU report worker. Models and evidence stay local.', 25, MUTED)
box(205, 'Enabled sources or isolated practice replay',
    ['Read original security reports; check and normalize each record.', 'Collection permissions and device actions remain separate.'])
edge([(720, 335), (720, 380)])
box(380, 'Durable waiting line: keep events through restart',
    ['Save pending work in SQLite. Limit capacity and show overload.', 'Keep source identity, original facts and timestamps.'])
edge([(720, 510), (720, 555)])
box(555, 'WORKER 1 / Gateway: connect the clues',
    ['Choose a saved event; add nearby activity and relevant local facts.', 'Prepare the evidence before either model reviews it.'])
edge([(720, 685), (720, 730)])
box(730, 'WORKER 2 / L1 rules + Qwen3.5:4b',
    ['Quick rules handle clear cases. Qwen reviews unclear activity.', 'It can quiet an event or raise a warning with a short reason.', 'L1 can review another event while Gemma works.'], PURPLE, height=155)
edge([(720, 885), (720, 990)], PURPLE,
    ['Only successful Qwen model escalations'], 742, 919)
box(990, 'WORKER 3 / Independent L2 pre-filter',
    ['Quiet an eligible routine case only with supporting evidence.', 'Pass unresolved warnings to Gemma, even with missing context.'])
edge([(720, 1120), (720, 1225)], PURPLE,
    ['Unresolved: ask the second brain'], 742, 1151)
box(1225, 'WORKER 4 / L2: Gemma4:12b',
    ["Read original facts without Qwen's opinion text.", 'Return a compact decision, explanations and supplied evidence IDs.', 'Proposed suppression needs a checking call and 90% confidence.'], PURPLE, height=155)
edge([(720, 1380), (720, 1490)], GOLD,
    ['Check the proposed outcome'], 742, 1417)
edge([(330, 808), (98, 808), (98, 1555), (330, 1555)], BLUE,
    ['Other L1 exits:', 'quiet decisions,', 'mandatory rules,', 'failed Qwen calls.', '', 'Bypass Gemma;', 'still checked.'], 122, 954)
edge([(1110, 1055), (1338, 1055), (1338, 1555), (1110, 1555)], GREEN,
    ['Supported', 'routine case:', 'bypass Gemma;', 'still checked.'], 1135, 1138)
box(1490, 'WORKER 5 / Shared final guardrail',
    ['Check every L1 and L2 exit, including pre-filter shortcuts.', 'Protected risk, failed review or rejected suppression stays visible.'], GOLD)
edge([(720, 1620), (720, 1725)])
box(1725, 'Save the final decision, facts and actual model context',
    ['Keep visible for investigation OR quiet with a recorded reason.', 'Preserve L1, L2 and final outcomes; queue a durable report job.'], GREEN)
edge([(720, 1855), (720, 1900), (355, 1900), (355, 1970)], BLUE,
    ['Decision visible now'], 182, 1923)
edge([(720, 1855), (720, 1900), (1085, 1900), (1085, 1970)], GOLD,
    ['Report job: separate work'], 864, 1923)
box(1970, 'Authenticated dashboard / API',
    ['Show saved decisions and both reviewers.', 'Partial facts first; final report when ready.'],
    BLUE, x=50, width=610, height=135)
box(1970, 'WORKER 6 / CPU report writer',
    ['Six local templates use saved evidence.', 'No AI call. Decisions do not wait for it.'],
    GOLD, x=780, width=610, height=135)
edge([(780, 2038), (660, 2038)], GOLD)
text(54, 2160, 'REMEMBER ELIGIBLE LIVE REPEATS / LOCAL SQLITE MEMORY', 22, GREEN, True)
box(2210, 'Qwen-approved patterns feed L1 rules',
    ['Exact host, source, content and model scope.', 'Record origin, reason and template.'],
    GREEN, x=50, width=650, height=135)
box(2210, 'Gemma-approved patterns feed L2 rules',
    ['Challenge and final gates must pass first.', 'A match avoids another Gemma review.'],
    GREEN, x=740, width=650, height=135)
text(54, 2375, 'Expires after 1 hour or 25 hits; revocable. File/API/demo/replay cannot teach or use shortcuts.', 22, MUTED)
text(54, 2420, 'Either brain can use a compatible local replacement. Ollama is the runner, not the model.', 22, MUTED)
text(54, 2470, 'Classification does not authorize commands or device changes. New report-worker speed: retest next.', 22, GOLD, True)
svg.append('</svg>')
OUT.mkdir(parents=True, exist_ok=True)
(OUT/'arbiter-flow.svg').write_text('\n'.join(svg)+'\n', encoding='utf-8')
(OUT.parent/'architecture.svg').write_text('\n'.join(svg)+'\n', encoding='utf-8')
base.save(OUT/'arbiter-flow.png', optimize=True)
frames = []
for frame in range(40):
    im = base.copy()
    painter = ImageDraw.Draw(im)
    for index, (points, color) in enumerate(paths):
        distance = ((frame/40-index*.07) % 1)*sum(math.dist(a, b) for a, b in zip(points, points[1:]))
        for a, b in zip(points, points[1:]):
            length = math.dist(a, b)
            if length and distance <= length:
                t = distance/length
                x, y = a[0]+(b[0]-a[0])*t, a[1]+(b[1]-a[1])*t
                painter.ellipse((x-5, y-5, x+5, y+5), fill=color)
                break
            distance -= length
    frames.append(im.quantize(colors=128))
frames[0].save(OUT/'arbiter-flow.gif', save_all=True, append_images=frames[1:], duration=100, loop=0, optimize=True, disposal=1)
print('Rendered current diagram:', W, 'x', H, ';', len(frames), 'animation frames')
