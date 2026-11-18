"""Build the single README architecture flow; local Pillow, no network access."""
from pathlib import Path
import html
import math

from PIL import Image, ImageDraw
from render_architecture import font

OUT = Path(__file__).resolve().parents[1] / 'docs' / 'architecture'
W, H = 1120, 3160
INK, MUTED = '#eef3fa', '#b8c5d8'
BLUE, PURPLE, RED, GREEN, GOLD = '#82b7ff', '#c4a0ff', '#ff939b', '#7cddb0', '#f2c777'
base = Image.new('RGB', (W, H), '#0d1420')
d = ImageDraw.Draw(base)
svg = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" role="img" aria-labelledby="title desc">',
       '<title id="title">Arbiter AI: one event, from evidence to explained decision</title>',
       '<desc id="desc">Follow an event through reading reports, organizing evidence, saving a waiting line, connecting clues, safety rules, quick sorting, optional Qwen3.5 review, answer checks, saved decisions and human review. Qwen3.5 can be replaced with another compatible local AI model. The model cannot authorize a device action.</desc>',
       f'<rect width="{W}" height="{H}" fill="#0d1420"/>']


def rect(box, fill, stroke=None, radius=16):
    x,y,w,h=box
    d.rounded_rectangle((x,y,x+w,y+h),radius=radius,fill=fill,outline=stroke,width=2)
    svg.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{radius}" fill="{fill}" stroke="{stroke or fill}" stroke-width="2"/>')


def text(x,y,value,size=23,color=INK,bold=False,max_width=None):
    face=font(size,bold)
    if max_width and d.textlength(value,font=face)>max_width:
        raise ValueError('Text overflow: '+value)
    d.text((x,y),value,font=face,fill=color)
    svg.append(f'<text x="{x}" y="{y+size}" fill="{color}" font-family="Segoe UI,DejaVu Sans,sans-serif" font-size="{size}" font-weight="{700 if bold else 400}">{html.escape(value)}</text>')


def band(y,n,title,subtitle,color,fill):
    rect((24,y,W-48,70),fill,radius=12)
    rect((42,y+15,38,38),color,radius=10)
    text(54,y+18,n,22,'#0d1420',True)
    text(96,y+11,title,25,color,True)
    text(96,y+42,subtitle,17,MUTED)


def node(y,n,title,lines,color=BLUE,fill='#172335'):
    rect((210,y,700,150),fill,color)
    rect((228,y+18,38,34),color,radius=9)
    text(238,y+19,n,20,'#0d1420',True)
    text(280,y+17,title,27,color,True,max_width=605)
    for i,line in enumerate(lines): text(236,y+65+31*i,line,22,MUTED,max_width=646)


paths=[]


def edge(points,color=BLUE,label=None,lx=0,ly=0):
    paths.append((points,color))
    d.line(points,fill=color,width=3)
    svg.append(f'<polyline points="{" ".join(f"{x},{y}" for x,y in points)}" fill="none" stroke="{color}" stroke-width="3" stroke-linejoin="round"/>')
    a,b=points[-2:]; theta=math.atan2(b[1]-a[1],b[0]-a[0]); x,y=b
    wings=[(x-11*math.cos(theta)+s*6*math.sin(theta),y-11*math.sin(theta)-s*6*math.cos(theta)) for s in (-1,1)]
    d.polygon([b,*wings],fill=color)
    svg.append(f'<polygon points="{x},{y} {wings[0][0]},{wings[0][1]} {wings[1][0]},{wings[1][1]}" fill="{color}"/>')
    if label:
        for i,line in enumerate(label.split('|')):
            width=d.textlength(line,font=font(18,True))+12
            rect((lx-6,ly+i*24,width,25),'#0d1420',radius=3)
            text(lx,ly+i*24,line,18,color,True)


def decision(y,n,title,line):
    pts=[(560,y),(910,y+80),(560,y+160),(210,y+80)]
    d.polygon(pts,fill='#302719',outline=GOLD,width=2)
    svg.append(f'<polygon points="{" ".join(f"{x},{yy}" for x,yy in pts)}" fill="#302719" stroke="{GOLD}" stroke-width="2"/>')
    text(410,y+37,n+'  '+title,26,GOLD,True,max_width=550)
    text(365,y+83,line,20,MUTED,max_width=640)


text(52,35,'ARBITER AI / SYSTEM ARCHITECTURE',21,BLUE,True)
text(52,78,'From raw evidence to a clear next step',39,INK,True)
text(52,135,'Rules handle clear cases. Qwen3.5 reviews the unclear ones.',24,MUTED)

for x,title,lines,color,fill in [
    (50,'COMPUTER REPORTS',['Windows / Sysmon','Defender / osquery'],BLUE,'#162840'),
    (310,'NETWORK + DEVICES',['Wazuh / Suricata','Syslog / devices'],BLUE,'#162840'),
    (570,'OPTIONAL INPUTS',['Enabled AWS readers','Approved sources only'],BLUE,'#162840'),
    (830,'PRACTICE / REPLAY',['Separate test records','No device changes'],PURPLE,'#29203d'),
]:
    rect((x,205,240,112),fill,color)
    text(x+15,218,title,18,color,True,max_width=210)
    for i,line in enumerate(lines): text(x+15,250+i*25,line,18,MUTED,max_width=210)

# Source paths converge; demo uses an isolated instance of the same pipeline.
for x in (170,430,690,950): edge([(x,317),(x,341),(560,341),(560,425)],BLUE)
band(355,'1','COLLECT + KEEP EVIDENCE','Gather reports without letting the AI change a device.',BLUE,'#192c46')
node(435,'01','Read security reports',['Read logs and alerts from the sources you enable.','Keep originals so a person can check what happened.'])
edge([(560,585),(560,635)])
node(635,'02','Organize and check',['Put computer, user, time and network details in one format.','Reject broken records; keep the original evidence.'])
edge([(560,785),(560,835)])
node(835,'03','Save events in a waiting line',['Save waiting events so a restart does not lose the queue.','Limit the queue; show when incoming work exceeds capacity.'])
edge([(560,985),(560,1055)])
band(1000,'2','CONNECT CLUES + DECIDE','Review urgent events first; let older waiting events progress too.',BLUE,'#192c46')
node(1080,'04','Connect the clues',['Link nearby events; check the computer\'s role and history.','Use approved facts only when they fit this exact event.'])
edge([(560,1230),(560,1280)])
decision(1280,'05','Must someone review?','Safety rules check for known risky signals')
edge([(560,1440),(560,1540)],BLUE,'No forced review',570,1460)
decision(1540,'06','Can quick rules decide?','Clearly routine, clearly risky, or still unclear?')
edge([(560,1700),(560,1820)],PURPLE,'Unclear: ask the AI',574,1740)
node(1820,'07','Qwen3.5: replaceable local AI',['Review unclear alerts and explain a recommendation.','Swap in another compatible local AI model if needed.'],PURPLE,'#241c35')
edge([(560,1970),(560,2050)],PURPLE,'Model answer',574,1990)
node(2050,'08','Check the AI recommendation',['Check the answer against rules and required evidence.','If the AI fails or is too unsure, ask a person to review.'],PURPLE,'#241c35')

# Conditional early exits are explicit and labelled, rather than hidden in prose.
edge([(910,1360),(1060,1360),(1060,2300),(810,2300),(810,2425)],RED,'Yes: ask|for review',925,1390)
edge([(910,1620),(1000,1620),(1000,2280),(865,2280),(865,2425)],RED,'Needs review',925,1650)
edge([(210,1620),(60,1620),(60,2300),(280,2300),(280,2425)],GREEN,'Routine, with|enough support',72,1660)
edge([(560,2200),(560,2290),(370,2290),(370,2425)],GREEN,'Enough routine evidence',285,2230)
edge([(560,2200),(560,2290),(700,2290),(700,2425)],RED,'Risky / still uncertain',605,2230)
text(454,2350,'THE TWO OUTCOMES',18,MUTED,True)
for x,title,lines,color,fill in [
    (90,'KEEP AS AN OBSERVATION',['Quiet the alert with a written reason.','Keep the record for later checks.'],GREEN,'#163027'),
    (600,'FLAG FOR REVIEW',['Show why it needs someone\'s attention.','A warning alone does not block anything.'],RED,'#351e28'),
]:
    rect((x,2425,430,130),fill,color)
    text(x+20,2442,title,23,color,True,max_width=390)
    for i,line in enumerate(lines): text(x+20,2484+i*28,line,19,MUTED,max_width=390)
edge([(305,2555),(305,2590),(560,2590),(560,2630)],GREEN)
edge([(815,2555),(815,2590),(560,2590),(560,2630)],RED)
node(2630,'09','Save the decision and reason',['Record the decision, evidence, and rule or model used.','Keep a history so a person can check the reasoning.'],BLUE)
edge([(560,2780),(560,2830)])
node(2830,'10','Show a person the next step',['Explain what happened, where, and what needs checking.','Suggestions do not authorize changes to the computer.'],BLUE)
text(52,3010,'TRUST BOUNDARY',18,GOLD,True)
text(52,3042,'The AI advises. Separate approval and safety checks control actions.',26,INK,True)
text(52,3090,'Exception: an exact approved fact may allow AI review of a rule hit; it cannot dismiss the alert alone.',18,MUTED)
svg.append('</svg>')
OUT.mkdir(parents=True,exist_ok=True)
(OUT/'arbiter-flow.svg').write_text('\n'.join(svg)+'\n',encoding='utf-8')
base.save(OUT/'arbiter-flow.png',optimize=True)
frames=[]
for frame in range(60):
    im=base.copy(); painter=ImageDraw.Draw(im)
    for index,(points,color) in enumerate(paths):
        distance=((frame/60-index*.07)%1)*sum(math.dist(a,b) for a,b in zip(points,points[1:]))
        for a,b in zip(points,points[1:]):
            length=math.dist(a,b)
            if length and distance<=length:
                t=distance/length; x=a[0]+(b[0]-a[0])*t; y=a[1]+(b[1]-a[1])*t
                painter.ellipse((x-6,y-6,x+6,y+6),fill=color)
                break
            distance-=length
    frames.append(im.quantize(colors=128))
frames[0].save(OUT/'arbiter-flow.gif',save_all=True,append_images=frames[1:],duration=100,loop=0,optimize=True,disposal=1)
print('Combined flow rendered:',(OUT/'arbiter-flow.gif').stat().st_size,'bytes')
