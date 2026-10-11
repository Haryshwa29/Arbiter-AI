"""Render the website's illustrative flow locally; no customer telemetry."""
from pathlib import Path
from PIL import Image, ImageColor, ImageDraw, ImageFilter, ImageFont

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'frontend/public'
W, H = 1200, 550
BG, SURFACE, LINE = '#171613', '#22201d', '#4c4840'
INK, MUTED, GOLD, GREEN = '#f0eee5', '#c4b8a5', '#d7b66d', '#ccc1a7'
FONT = Path('C:/Windows/Fonts')
def font(size, bold=False):
    return ImageFont.truetype(str(FONT / ('segoeuib.ttf' if bold else 'segoeui.ttf')), size)
def text(draw, xy, value, size=20, color=INK, bold=False):
    draw.text(xy, value, font=font(size, bold), fill=color)

ACCENTS = ['#d26b51', '#d7b66d', '#83ad87', '#d7b66d', '#83ad87']
def backdrop(width, height):
    base = Image.new('RGBA', (width, height), BG)
    glow = Image.new('RGBA', (120, 100))
    paint = ImageDraw.Draw(glow)
    for cx, cy, color in [(5,20,(190,55,35,48)),(65,25,(210,159,44,40)),(115,70,(43,156,99,48))]:
        paint.ellipse((cx-40,cy-55,cx+40,cy+55),fill=color)
    glow = glow.filter(ImageFilter.GaussianBlur(22)).resize((width,height), Image.Resampling.BICUBIC)
    return Image.alpha_composite(base,glow).convert('RGB')

def card_fill(index, active):
    base, accent = ImageColor.getrgb(SURFACE), ImageColor.getrgb(ACCENTS[index])
    mix = .15 if active else .055
    return tuple(round(a*(1-mix)+b*mix) for a,b in zip(base,accent))
def icon(d, kind, x, y, color):
    if kind == 0:
        d.rounded_rectangle((x-27,y-22,x+27,y+14),5,outline=color,width=3)
        d.line((x,y+15,x,y+28),fill=color,width=3);d.line((x-17,y+28,x+17,y+28),fill=color,width=3)
    elif kind == 1:
        d.rounded_rectangle((x-22,y-26,x+22,y+26),5,outline=color,width=3)
        for yy in [-12,0,12]:d.line((x-11,y+yy,x+11,y+yy),fill=color,width=3)
    elif kind == 2:
        d.polygon([(x,y-29),(x+25,y-18),(x+21,y+15),(x,y+30),(x-21,y+15),(x-25,y-18)],outline=color,width=3)
        d.line((x-10,y,x-2,y+8,x+13,y-10),fill=color,width=3)
    elif kind == 3:
        # Roman-inspired geometry matches public/arbiter-mark.svg.
        def point(px, py): return (round(x+(px-12)*2.3), round(y+(py-14)*2.3))
        outline=[point(px,py) for px,py in [(5,3),(12,1.5),(19,3),(21,6),(21,19),(12,26),(3,19),(3,6)]]
        d.polygon(outline,fill='#201b14')
        d.line(outline+[outline[0]],fill=GOLD,width=3)
        letter=[point(px,py) for px,py in [(12,6.5),(18,20),(15.5,20),(14,16.2),(10,16.2),(8.5,20),(6,20)]]
        d.polygon(letter,fill=GOLD)
        d.polygon([point(px,py) for px,py in [(11,13.8),(13,13.8),(12,11)]],fill='#201b14')
        d.line([point(5.5,5),point(12,3.5),point(18.5,5)],fill=GOLD,width=2)
        d.line([point(12,21.5),point(12,24.5)],fill=GOLD,width=2)
    else:
        d.ellipse((x-12,y-27,x+12,y-3),outline=color,width=3)
        d.arc((x-28,y+2,x+28,y+51),180,360,fill=color,width=3)

names = ['Your device','Activity arrives','Arbiter checks','Decision explained','You stay in control']
subs = ['A login is recorded','Logs become an event','Rules + context','Evidence stays attached','Approve eligible action']
captions = [
 ('01 / OBSERVE', 'Someone repeatedly tries to sign in.', 'The device records activity. Connected sources bring it to Arbiter.'),
 ('02 / COLLECT', 'The event enters the local queue.', 'It keeps an identity, a timestamp and the original evidence.'),
 ('03 / CHECK', 'Is this routine, suspicious, or unclear?', 'Rules and context decide clear cases. Local AI can examine ambiguous ones.'),
 ('04 / EXPLAIN', 'This activity deserves your attention.', 'An alert shows the reason and related evidence. An alert is not a block.'),
 ('05 / REVIEW', 'You decide what happens next.', 'Review the alert. Approve a supported protective action when eligible.'),
]
frames=[]
desktop_background = backdrop(W, H)
for frame in range(100):
    stage=min(4,frame//20)
    im=desktop_background.copy();d=ImageDraw.Draw(im)
    text(d,(35,22),'HOW ARBITER WORKS',14,GOLD,True)
    text(d,(825,22),'ILLUSTRATION / NOT LIVE TELEMETRY',13,MUTED)
    for i in range(5):
        x=35+i*232;active=i==stage;c=GOLD if active else GREEN if i<stage else MUTED
        d.rounded_rectangle((x,83,x+202,272),12,fill=card_fill(i,active),outline=c if active else LINE,width=2)
        icon(d,i,x+101,136,c)
        # Narrow cards use two lines for the longer headings.
        title=names[i];parts={'Decision explained':['Decision','explained'],'You stay in control':['You stay','in control']}.get(title,[title])
        for j,part in enumerate(parts):
            tw=d.textlength(part,font=font(19,True));text(d,(x+101-tw/2,180+j*24),part,19,INK,True)
        tw=d.textlength(subs[i],font=font(13));text(d,(x+101-tw/2,242),subs[i],13,MUTED)
        if i<4:
            d.line((x+208,172,x+226,172),fill=LINE,width=2)
            d.polygon([(x+226,172),(x+220,167),(x+220,177)],fill=LINE)
            if i==stage and stage<4:
                pos=x+208+int((frame%20)/19*18)
                d.ellipse((pos-3,169,pos+3,175),fill=GOLD)
    d.line((35,312,1165,312),fill=LINE,width=1)
    label,title,caption=captions[stage]
    text(d,(35,342),label,14,GOLD,True)
    text(d,(35,375),title,30,INK,True)
    text(d,(35,427),caption,19,MUTED)
    for i in range(5):
        x=35+i*45;d.rounded_rectangle((x,494,x+32,498),2,fill=GOLD if i==stage else LINE)
    frames.append(im)
OUT.mkdir(exist_ok=True)
frames[60].save(OUT/'arbiter-flow-poster.png',optimize=True)
frames[0].save(OUT/'arbiter-flow.gif',save_all=True,append_images=frames[1:],duration=140,loop=0,optimize=True,disposal=2)
print('Rendered product flow GIF and reduced-motion poster.')

# A portrait variant keeps the pictography and labels legible on phones.
mobile=[]
mobile_background = backdrop(600,1060)
for frame in range(50):
    stage=min(4,frame//10)
    im=mobile_background.copy();d=ImageDraw.Draw(im)
    text(d,(30,22),'HOW ARBITER WORKS',16,GOLD,True)
    for i in range(5):
        y=72+i*143;c=GOLD if i==stage else GREEN if i<stage else MUTED
        d.rounded_rectangle((30,y,570,y+118),10,fill=card_fill(i,i==stage),outline=c if i==stage else LINE,width=2)
        icon(d,i,82,y+59,c)
        text(d,(135,y+28),names[i],24,INK,True)
        text(d,(135,y+68),subs[i],19,MUTED)
        if i<4:
            d.line((300,y+121,300,y+141),fill=LINE,width=2)
            d.polygon([(300,y+141),(295,y+135),(305,y+135)],fill=LINE)
            if i==stage:
                yy=y+122+int((frame%10)/9*17);d.ellipse((297,yy-3,303,yy+3),fill=GOLD)
    label,title,caption=captions[stage]
    text(d,(30,825),label,17,GOLD,True)
    import textwrap
    yy=865
    for line in textwrap.wrap(title,33):
        text(d,(30,yy),line,26,INK,True);yy+=35
    text(d,(30,1015),'ILLUSTRATION / NOT LIVE TELEMETRY',15,MUTED)
    mobile.append(im)
mobile[30].save(OUT/'arbiter-flow-mobile-poster.png',optimize=True)
mobile[0].save(OUT/'arbiter-flow-mobile.gif',save_all=True,append_images=mobile[1:],duration=280,loop=0,optimize=True,disposal=2)
print('Rendered portrait flow for mobile.')
