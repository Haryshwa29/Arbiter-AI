"""Security guardrails — intent-class detectors that wrap the LLM.

The pipeline is a sandwich: Event -> guardrails -> LLM -> guardrails -> Decision.
The model is the *analyst layer* (it explains and ranks); detection lives in
these rules. Red-teaming showed why: a 4B model wrapped in a benign
"maintenance" fact suppresses disguised attacks, and literal-keyword rules
are trivially evaded ("allow all inbound" dodges `0.0.0.0/0`, `wheel` dodges
`sudo`, `certutil` isn't obvious malware). So the guardrails match on
*intent class and structure*, not exact strings, and each carries a
NON_SUPPRESSIBLE_* reason code.

Design stance (from the red-team lesson):
- Detection = rules + normalization + non-suppressible rails. The LLM never
  gets to suppress a recognised dangerous-intent class.
- Match semantics, not literals: normalise the message and check for the
  *behaviour* (exposure to a broad scope, credential material access,
  privilege expansion, download-and-execute, integrity change, egress to an
  external destination, LOLBins, supply-chain install scripts, ransomware
  mass-rename, impossible travel).
- Prefer to over-escalate than to miss (asymmetric costs) — but keep a few
  precision carve-outs where a legit pattern is unambiguous (public web
  server on 80/443, a package-confirmed integrity change).

Every new red-team miss becomes a new detector or a normalised feature here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .schema import Event


@dataclass(frozen=True)
class GuardrailHit:
    code: str      # e.g. NON_SUPPRESSIBLE_PRIVESC
    name: str      # short rule name
    reason: str


def _m(ev: Event) -> str:
    return ev.message.lower()


def _has(s: str, *needles: str) -> bool:
    return any(n in s for n in needles)


# --- intent-class detectors ------------------------------------------------

_SENSITIVE_PORTS = ("22", "23", "3389", "5432", "3306", "1433", "6379",
                    "27017", "9200", "5984")
_SENSITIVE_SVC = ("rdp", "ssh", "postgres", "mysql", "mssql", "redis",
                  "mongo", "database", "db ", "winrm", "smb", "telnet")
_BROAD_SCOPE = ("0.0.0.0/0", "0.0.0.0", "::/0", "allow all", "from any",
                "any source", "all ports", "anywhere", "to the internet",
                "public internet", "0.0.0.0/1", "/1 ", "/0 ")


def _internet_exposure(ev: Event) -> bool:
    if ev.event_type not in {"firewall_change", "security_group_change",
                             "port_open", "acl_change", "network_acl",
                             "ingress_change"}:
        return False
    m = _m(ev)
    broad = _has(m, *_BROAD_SCOPE) or str(ev.fields.get("cidr", "")).strip() \
        in {"0.0.0.0/0", "::/0"}
    if not broad:
        return False
    # Precision carve-out: a public web server exposing ONLY 80/443 is its
    # designed baseline, not an incident.
    web_only = _has(m, "443", "80", "http", "https", "web") and not (
        _has(m, *_SENSITIVE_PORTS) or _has(m, *_SENSITIVE_SVC)
        or _has(m, "all ports"))
    if web_only:
        return False
    return True


def _credential_access(ev: Event) -> bool:
    m = _m(ev)
    if _has(m, "mimikatz", "lsass", "ntds.dit", "ntds", "sam dump",
            "reg save", "secretsdump", "credential dump", "/etc/shadow",
            "shadow.bak", "hashdump", "dcsync"):
        return True
    # /etc/passwd alone is world-readable/benign; only flag with intent.
    if _has(m, "shadow") and _has(m, "read", "copy", "dump", "cat", "exfil",
                                  "/tmp", "crack"):
        return True
    if _has(m, "passwd") and _has(m, "shadow", "crack", "dump", "exfil"):
        return True
    return False


def _privilege_expansion(ev: Event) -> bool:
    if ev.event_type not in {"user_created", "account_created", "iam_change",
                             "role_grant", "group_change", "priv_escalation"}:
        return False
    m = _m(ev)
    if str(ev.fields.get("uid", "")).strip() == "0":
        return True
    return _has(m, "uid 0", "wheel", "sudo group", "sudoers", "admin",
                "administrators", "domain admin", "root group", "root",
                "administratoraccess", "privileged", "elevated")


def _download_execute(ev: Event) -> bool:
    m = _m(ev)
    if re.search(r"(curl|wget|fetch|iwr|invoke-webrequest)\b[^\n]*\|\s*"
                 r"(sh|bash|zsh|python|perl)", m):
        return True
    if _has(m, "reverse shell", "nc -e", "bash -i", "/dev/tcp/",
            "powershell -enc", "| sh -"):
        return True
    # two-step download then execute
    downloaded = _has(m, "download", "curl", "wget", "fetch", "urlcache")
    executed = _has(m, "chmod +x", "then execut", "executed /tmp", "ran /tmp",
                    "&& ./", "; ./", "chmod 755")
    return downloaded and executed


def _integrity_change(ev: Event) -> bool:
    if ev.event_type not in {"file_integrity", "binary_change", "integrity"}:
        return False
    m = _m(ev)
    # A binary/executable/hash change is escalated UNLESS explicitly
    # confirmed by the package manager. "as part of maintenance" is not a
    # confirmation — that framing is exactly the evasion.
    confirmed = _has(m, "package manager confirms", "apt confirms",
                     "confirmed update", "confirms update", "signed by",
                     "verified update", "matches package", "package confirms")
    if confirmed:
        return False
    touches_binary = _has(m, "binary", "sshd", "executable", "hash changed",
                          "checksum", ".so", "/usr/", "/bin/", "/sbin/",
                          "vmlinuz", ".dll")
    return touches_binary


_INTERNAL = ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
             "172.2", "172.30.", "172.31.", "nas-01", "known backup host",
             "internal")
_EXTERNAL_SINKS = ("dropbox", "mega.nz", "pastebin", "anonfiles",
                   "transfer.sh", "s3.amazonaws.com", "blob.core",
                   "storage.googleapis", "wetransfer", "file.io", "0x0.st")


def _data_exfil(ev: Event) -> bool:
    if ev.event_type not in {"data_upload", "data_transfer", "egress",
                             "dns_exfil", "data_exfiltration", "s3_download"}:
        return False
    m = _m(ev)
    if ev.event_type == "dns_exfil" or _has(m, "dns tunnel", "exfil",
                                            "unknown dest", "unknown destination",
                                            "unrecognized", "external"):
        return True
    if _has(m, *_EXTERNAL_SINKS):
        return True
    # a public IP destination that isn't clearly internal
    ip = str(ev.fields.get("src_ip", "") or ev.fields.get("dst", ""))
    dest_in_msg = re.search(r"to (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", m)
    dest = ip or (dest_in_msg.group(1) if dest_in_msg else "")
    if dest and not _has(dest, *_INTERNAL) and not _has(m, "known backup",
                                                        "to nas-01"):
        # looks like egress to an off-network address
        if re.match(r"^(?!10\.|192\.168\.|172\.)", dest):
            return True
    return False


_LOLBINS = ("certutil", "bitsadmin", "mshta", "regsvr32", "rundll32",
            "wmic", "cscript", "wscript", "installutil", "msbuild",
            "powershell", "psexec")
_LOLBIN_CTX = ("urlcache", "-urlcache", "http://", "https://", "download",
               "-enc", "-encodedcommand", "encoded", "downloadstring", "iex",
               "/transfer", "process call create", "javascript:", "scrobj",
               ".hta", "-nop", "-w hidden", "hidden", "bypass", "base64",
               "unusual", "-split -f")


def _lolbin(ev: Event) -> bool:
    m = _m(ev)
    if not _has(m, *_LOLBINS):
        return False
    return _has(m, *_LOLBIN_CTX)


def _supply_chain(ev: Event) -> bool:
    m = _m(ev)
    installer = _has(m, "postinstall", "preinstall", "install script",
                     "npm install", "pip install", "gem install", "setup.py",
                     "package script", "lifecycle script")
    if not installer:
        return False
    return _has(m, "curl", "wget", "download", "fetch", "http://", "https://",
                "registered", "new domain", "pastebin", "raw.github",
                "execute", "network")


def _ransomware(ev: Event) -> bool:
    if ev.event_type not in {"mass_file_rename", "file_encrypt", "mass_delete",
                             "mass_modify"}:
        return False
    m = _m(ev)
    count = ev.fields.get("count")
    if isinstance(count, (int, float)) and count >= 100:
        return True
    # mass renames/encryption are ransomware behaviour regardless of the
    # extension used or how signed the binary looks.
    return _has(m, "renamed", "re-saved", "encrypted", "files") and _has(
        m, "000", "hundred", "thousand", "many", "mass", "1,", "2,", "3,",
        "4,", "5,", "6,", "7,", "8,", "9,")


def _impossible_travel(ev: Event) -> bool:
    if ev.event_type == "geo_impossible_travel":
        return True
    geo = str(ev.fields.get("geo", "")).strip()
    prev = str(ev.fields.get("prev_geo", "")
               or ev.fields.get("usual_geo", "")).strip()
    gap = ev.fields.get("gap_minutes")
    return bool(geo and prev and geo != prev
                and isinstance(gap, (int, float)) and gap < 60)


# (code, name, reason, predicate) — order matters only for which reason is
# reported first; a hit from any means the event is non-suppressible.
RULES = [
    ("NON_SUPPRESSIBLE_EXPOSURE", "internet_exposure",
     "exposing a sensitive service to a broad/public scope is never a benign "
     "maintenance side-effect", _internet_exposure),
    ("NON_SUPPRESSIBLE_CRED_ACCESS", "credential_access",
     "access to credential material (shadow/SAM/ntds/lsass) is always "
     "escalated", _credential_access),
    ("NON_SUPPRESSIBLE_PRIVESC", "privilege_expansion",
     "creation or elevation of a privileged account (uid-0/wheel/sudo/admin) "
     "is always escalated", _privilege_expansion),
    ("NON_SUPPRESSIBLE_DOWNLOAD_EXEC", "download_execute",
     "download-and-execute (pipe-to-shell or fetch-then-run) is never benign",
     _download_execute),
    ("NON_SUPPRESSIBLE_INTEGRITY", "integrity_change",
     "a binary/integrity change not confirmed by the package manager can't be "
     "excused by a maintenance window", _integrity_change),
    ("NON_SUPPRESSIBLE_EXFIL", "data_exfil",
     "data leaving to an external or file-sharing destination is never routine "
     "sync/backup traffic", _data_exfil),
    ("NON_SUPPRESSIBLE_LOLBIN", "lolbin",
     "a living-off-the-land binary (certutil/wmic/rundll32/mshta/powershell) "
     "used to download or run code is escalated", _lolbin),
    ("NON_SUPPRESSIBLE_SUPPLYCHAIN", "supply_chain",
     "a package install/postinstall script that reaches the network is a "
     "supply-chain risk", _supply_chain),
    ("NON_SUPPRESSIBLE_RANSOMWARE", "ransomware",
     "mass file rename/encryption is ransomware behaviour regardless of "
     "extension or how signed the binary looks", _ransomware),
    ("NON_SUPPRESSIBLE_IMPOSSIBLE_TRAVEL", "impossible_travel",
     "one account authenticating from two locations in an impossible "
     "timeframe is account takeover, never routine maintenance",
     _impossible_travel),
]


def guardrail_check(event: Event) -> GuardrailHit | None:
    """Return the first non-suppressible intent class that matches, or None.

    Deterministic: no facts, no score, no model — pure event inspection.
    """
    for code, name, reason, predicate in RULES:
        try:
            if predicate(event):
                return GuardrailHit(code, name, reason)
        except Exception:
            continue
    return None


# --- fact-corroborated downgrade --------------------------------------------
#
# Some rails fire on patterns a few environments legitimately produce as a
# standing baseline (e.g. terraform provisioning a uid-0 monitoring account).
# Log text can't be trusted to say so — the attacker writes the log line.
# Admin-curated environment facts (the memory layer) can.
#
# A corroborating fact DOWNGRADES the rail: instead of auto-escalating, the
# event goes to the LLM tier, which sees the fact and decides. A downgrade is
# never a suppression by itself. Rails whose intent class has no plausible
# legitimate baseline (credential dumping, download-and-execute, ransomware,
# exfil to file-sharing sinks, ...) are never downgradeable.
#
# Corroboration is deliberately strict: the fact must name the event's host
# AND the *specific* dangerous marker the rail fired on. A generic
# "provisioning creates service accounts" fact does not excuse a wheel-group
# add — only a fact that says this host legitimately creates wheel/uid-0
# accounts does.

_PRIV_MARKER_GROUPS: tuple[tuple[str, ...], ...] = (
    ("uid 0", "uid0"),
    ("wheel",),
    ("sudo", "sudoers"),
    ("root",),
    ("admin", "administrators", "administratoraccess", "domain admin"),
    ("privileged", "elevated"),
)


def _norm(s: str) -> str:
    return s.lower().replace("-", " ")


def _corroborates_privesc(ev: Event, fact: str) -> bool:
    f = _norm(fact)
    if _norm(ev.host) not in f:
        return False
    m = _norm(ev.message)
    if str(ev.fields.get("uid", "")).strip() == "0" and _has(f, "uid 0", "uid0"):
        return True
    for group in _PRIV_MARKER_GROUPS:
        if _has(m, *group) and _has(f, *group):
            return True
    return False


# rule name -> corroborator predicate. Additions here are a security
# decision: only rails where a legitimate standing baseline is plausible.
_DOWNGRADE_CORROBORATORS = {
    "privilege_expansion": _corroborates_privesc,
}


def fact_downgrade(hit: GuardrailHit, event: Event,
                   facts: list[str]) -> str | None:
    """Return the admin-curated fact that corroborates this rail hit, or None.

    None means the rail stands: escalate without the model. A returned fact
    means the decision belongs to the LLM tier (with the fact in context) —
    never to the cheap prefilter, and never an automatic suppress.
    """
    check = _DOWNGRADE_CORROBORATORS.get(hit.name)
    if check is None:
        return None
    for fact in facts:
        try:
            if check(event, fact):
                return fact
        except Exception:
            continue
    return None
