"""Server-rendered HTML for the dashboard.

Self-contained: all CSS/JS inline, no external CDN (ADR-001 hardening and
invariant #3 — nothing loads from off the network). The visual language is
the calm, restrained one from the design direction: neutral surfaces, color
reserved to mean something, gentle motion only.
"""

from __future__ import annotations

import html

BASE_CSS = """
:root{color-scheme:dark;--bg:#0d1117;--s1:#161b22;--s2:#1c222b;--s3:#232b36;
--bd:#21262d;--tx:#c9d1d9;--tx2:#8b949e;--tx3:#6e7681;--acc:#58a6ff;
--danger:#f85149;--dangerbg:#2a1516;--ok:#7ee787;--okbg:#132017;--pro:#d2a8ff}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--tx);font-family:-apple-system,
'Segoe UI',Roboto,sans-serif;line-height:1.5;font-size:14px}
a{color:var(--acc);text-decoration:none}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.btn{background:var(--s2);border:1px solid var(--bd);color:var(--tx);
border-radius:8px;padding:9px 18px;font-size:14px;cursor:pointer}
.btn:hover{background:var(--s3)}
.btn.primary{background:#238636;border-color:#238636;color:#fff}
.btn.primary:hover{background:#2ea043}
input{background:var(--s1);border:1px solid var(--bd);color:var(--tx);
border-radius:8px;padding:9px 12px;font-size:14px;width:100%}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.35}}
@keyframes slidein{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:none}}
"""


def page(title: str, body: str, extra: str = "") -> bytes:
    return (f"<!DOCTYPE html><html lang=en><head><meta charset=utf-8>"
            f"<meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<title>{html.escape(title)}</title><style>{BASE_CSS}{extra}</style>"
            f"</head><body>{body}</body></html>").encode()


def splash(counts: dict) -> bytes:
    body = f"""
<div style="max-width:560px;margin:8vh auto;padding:0 20px;text-align:center">
  <div style="display:inline-flex;align-items:center;gap:9px;margin-bottom:18px">
    <span style="font-size:26px">&#9683;</span>
    <span style="font-size:24px;font-weight:600">Arbiter</span>
  </div>
  <p style="font-size:15px;color:var(--tx2);margin:0 0 4px">
    This network is protected by Arbiter — a self-hosted AI security analyst.</p>
  <p style="font-size:13px;color:var(--tx3);margin:0 0 32px">
    Every alert is triaged locally. Your data never leaves the network.</p>
  <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-bottom:30px">
    <div style="background:var(--s1);border:1px solid var(--bd);border-radius:12px;padding:18px 8px">
      <div style="font-size:26px;font-weight:600">{counts['triaged']:,}</div>
      <div style="font-size:12px;color:var(--tx3);margin-top:5px">events triaged to date</div></div>
    <div style="background:var(--s1);border:1px solid var(--bd);border-radius:12px;padding:18px 8px">
      <div style="font-size:26px;font-weight:600;color:var(--ok)">{counts['suppressed']:,}</div>
      <div style="font-size:12px;color:var(--tx3);margin-top:5px">quietly suppressed</div></div>
    <div style="background:var(--s1);border:1px solid var(--bd);border-radius:12px;padding:18px 8px">
      <div style="font-size:26px;font-weight:600">{counts['escalated']:,}</div>
      <div style="font-size:12px;color:var(--tx3);margin-top:5px">raised to a human</div></div>
  </div>
  <a href="/login"><button class="btn">&#128274; Sign in</button></a>
  <p style="margin-top:26px;font-size:11.5px;color:var(--tx3);line-height:1.6">
    Nothing on this page identifies a host, address, account, or event.
    Operational detail is visible only after sign-in.</p>
</div>"""
    return page("Arbiter", body)


def login(csrf: str, error: str = "") -> bytes:
    err = (f"<p style='color:var(--danger);font-size:13px;margin:0 0 12px'>"
           f"{html.escape(error)}</p>" if error else "")
    body = f"""
<div style="max-width:340px;margin:12vh auto;padding:0 20px">
  <div style="display:flex;align-items:center;gap:8px;justify-content:center;margin-bottom:24px">
    <span style="font-size:22px">&#9683;</span>
    <span style="font-size:20px;font-weight:600">Arbiter</span>
  </div>
  {err}
  <form method=post action=/login>
    <input type=hidden name=csrf value="{html.escape(csrf)}">
    <label style="font-size:12px;color:var(--tx2)">username</label>
    <input name=username autofocus autocomplete=username style="margin:5px 0 14px">
    <label style="font-size:12px;color:var(--tx2)">password</label>
    <input name=password type=password autocomplete=current-password style="margin:5px 0 20px">
    <button class="btn primary" style="width:100%" type=submit>Sign in</button>
  </form>
  <p style="text-align:center;margin-top:18px"><a href="/" style="font-size:12px;color:var(--tx3)">&larr; back</a></p>
</div>"""
    return page("Sign in — Arbiter", body)


NAV = """
<div style="width:210px;flex:0 0 210px;background:var(--s1);min-height:100vh;padding:16px 12px">
  <div style="display:flex;align-items:center;gap:8px;padding:2px 6px 14px;border-bottom:1px solid var(--bd)">
    <span style="font-size:19px">&#9683;</span><span style="font-weight:600">Arbiter</span>
    <span style="margin-left:auto;font-size:11px;color:var(--ok)"><span style="animation:pulse 2.4s infinite">&#9679;</span> live</span>
  </div>
  <div style="font-size:10px;color:var(--tx3);letter-spacing:.06em;margin:14px 6px 6px">MONITOR</div>
  {see}
  {admin}
  <div style="position:relative;margin-top:24px;padding:10px 6px;border-top:1px solid var(--bd);font-size:12px;color:var(--tx2)">
    {user} · <span style="color:var(--acc)">{role}</span>
    <form method=post action=/logout style="margin-top:8px"><button class="btn" style="padding:5px 12px;font-size:12px">Sign out</button></form>
  </div>
</div>"""


def _navitem(label: str, active: bool = False) -> str:
    bg = "background:var(--s3);" if active else ""
    col = "var(--tx)" if active else "var(--tx2)"
    return (f"<div style='padding:7px 10px;border-radius:8px;{bg}font-size:13px;"
            f"color:{col};margin-bottom:2px'>{label}</div>")


def dashboard(user: dict, today: dict, lifetime: dict, verdicts: list) -> bytes:
    see = (_navitem("Overview", True) + _navitem("Live feed")
           + _navitem("Verdicts &amp; audit") + _navitem("Reports")
           + _navitem("Assets &amp; facts"))
    admin = ""
    if user["role"] == "admin":
        admin = ("<div style='font-size:10px;color:var(--tx3);letter-spacing:.06em;"
                 "margin:16px 6px 6px'>ADMINISTER</div>"
                 + _navitem("AI settings") + _navitem("Users &amp; roles")
                 + _navitem("Retention &amp; policy"))
    nav = NAV.format(see=see, admin=admin,
                     user=html.escape(user["username"]), role=user["role"])

    rows = "".join(_verdict_row(v) for v in verdicts)
    supp_today = today["today"] - today["escalated"]
    main = f"""
<div style="flex:1;padding:22px 26px;max-width:920px">
  <div style="display:flex;align-items:center;gap:10px;margin-bottom:4px">
    <div style="font-size:19px;font-weight:600">Good to see you, {html.escape(user['username'])}</div>
    <span style="margin-left:auto;font-size:12px;color:var(--tx2)">agent healthy</span>
  </div>
  <p style="color:var(--tx3);font-size:13px;margin:0 0 18px">
    {today['escalated']} escalations of {today['today']} events today — {supp_today} handled without you.</p>

  <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin-bottom:22px">
    {_metric('events today', f"{today['today']:,}")}
    {_metric('needs a human', str(today['escalated']), 'var(--danger)')}
    {_metric('quietly handled', f"{supp_today:,}", 'var(--ok)')}
    {_metric('prefilter saved', f"{today['prefilter']:,}")}
  </div>

  <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px">
    <span style="font-size:15px;font-weight:600">Live feed</span>
    <span style="font-size:11px;color:var(--tx3)">streaming · newest first</span>
    <label style="margin-left:auto;font-size:12px;color:var(--tx2)">
      <input type=checkbox id=esconly style="width:auto;vertical-align:-1px"> escalations only</label>
  </div>
  <div id=feed style="display:flex;flex-direction:column;gap:6px">{rows}</div>
</div>
<script>
const feed=document.getElementById('feed'),esconly=document.getElementById('esconly');
function rowHtml(v){{
  const esc=v.decision==='escalate';
  const dc=esc?'var(--danger)':'var(--ok)';
  const bg=esc?'background:var(--dangerbg);':'background:var(--s1);';
  const tc=v.tier==='prefilter'?'var(--acc)':'var(--pro)';
  return `<div class="vrow" data-esc="${{esc}}" style="${{bg}}display:flex;align-items:center;gap:9px;padding:9px 13px;border-radius:10px;font-size:12.5px;animation:slidein .5s ease">
    <span style="font-weight:600;color:${{dc}};min-width:64px">${{esc?'ESCALATE':'suppress'}}</span>
    <span class="mono" style="color:${{tc}};font-size:11px">${{v.tier}}</span>
    <span>${{v.host}}</span>
    <span class="mono" style="color:var(--tx3);font-size:11.5px">${{v.signature}}</span>
    <span style="margin-left:auto" class="mono" title="${{(v.rationale||'').replace(/"/g,'&quot;')}}">${{(+v.score).toFixed(1)}}</span></div>`;
}}
function applyFilter(){{document.querySelectorAll('.vrow').forEach(r=>{{
  r.style.display=(esconly.checked&&r.dataset.esc!=='true')?'none':'flex';}});}}
esconly.onchange=applyFilter;
try{{
  const es=new EventSource('/api/stream');
  es.onmessage=e=>{{const v=JSON.parse(e.data);
    feed.insertAdjacentHTML('afterbegin',rowHtml(v));
    while(feed.children.length>60)feed.removeChild(feed.lastChild);
    applyFilter();}};
}}catch(e){{}}
</script>"""
    body = f"<div style='display:flex'>{nav}{main}</div>"
    return page("Dashboard — Arbiter", body)


def _metric(label: str, value: str, color: str = "var(--tx)") -> str:
    return (f"<div style='background:var(--s1);border-radius:12px;padding:13px 16px'>"
            f"<div style='font-size:12px;color:var(--tx3)'>{label}</div>"
            f"<div style='font-size:24px;font-weight:600;color:{color};"
            f"margin-top:4px'>{value}</div></div>")


def _verdict_row(v: dict) -> str:
    esc = v["decision"] == "escalate"
    dc = "var(--danger)" if esc else "var(--ok)"
    bg = "var(--dangerbg)" if esc else "var(--s1)"
    tc = "var(--acc)" if v["tier"] == "prefilter" else "var(--pro)"
    label = "ESCALATE" if esc else "suppress"
    score = f"{float(v['score']):.1f}"
    return (f"<div class=vrow data-esc={'true' if esc else 'false'} "
            f"style='background:{bg};display:flex;align-items:center;gap:9px;"
            f"padding:9px 13px;border-radius:10px;font-size:12.5px'>"
            f"<span style='font-weight:600;color:{dc};min-width:64px'>{label}</span>"
            f"<span class=mono style='color:{tc};font-size:11px'>{html.escape(v['tier'])}</span>"
            f"<span>{html.escape(v.get('host') or '')}</span>"
            f"<span class=mono style='color:var(--tx3);font-size:11.5px'>"
            f"{html.escape(v.get('signature') or '')}</span>"
            f"<span style='margin-left:auto' class=mono "
            f"title='{html.escape(v.get('rationale') or '')}'>{score}</span></div>")
