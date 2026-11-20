"""Extract bounded observations from native Wazuh evidence, never test labels."""
import ipaddress
import re


def security_details(raw):
    """Keep native rule/CVE and conversation fields; prose is not a CVE finding."""
    data, rule = raw.get('data', {}), raw.get('rule', {})
    if not isinstance(data, dict) or not isinstance(rule, dict):
        return {}
    alert = data.get('alert', {})
    metadata = alert.get('metadata', {}) if isinstance(alert, dict) else {}
    metadata = metadata if isinstance(metadata, dict) else {}
    mitre = rule.get('mitre', {})
    mitre = mitre if isinstance(mitre, dict) else {}
    vulnerability = data.get('vulnerability', {})
    vulnerability = vulnerability if isinstance(vulnerability, dict) else {}
    def identifiers(values, pattern):
        found = set()
        for value in values:
            for entry in (value if isinstance(value, list) else [value])[:16]:
                if isinstance(entry, str) and len(entry)<=32:
                    entry = entry.upper().replace('_','-')
                    if re.fullmatch(pattern, entry):
                        found.add(entry)
        return sorted(found)[:8]
    security = {}
    cves = identifiers([rule.get('cve'),metadata.get('cve'),metadata.get('cve_id'),
        vulnerability.get('cve')], r'CVE-\d{4}-\d{4,12}')
    techniques = identifiers([mitre.get('id'),metadata.get('mitre_technique_id')],
        r'T\d{4}(?:\.\d{3})?')
    if cves: security['reported_cves'] = cves
    if techniques: security['reported_techniques'] = techniques
    package = vulnerability.get('package', {})
    if isinstance(package, dict):
        observed = {}
        direct=identifiers([vulnerability.get('cve')],r'CVE-\d{4}-\d{4,12}')
        if direct: observed['cve']=direct[0]
        for key,value in [('package',package.get('name')),('version',package.get('version')),
                          ('status',vulnerability.get('status'))]:
            if isinstance(value, str) and 0<len(value)<=256:
                observed[key] = value
        if observed: security['vulnerability'] = observed
    network = {}
    for key in ('flow_id','app_proto','direction'):
        value = data.get(key)
        if type(value) is int and 0<=value<2**64 or isinstance(value,str) and 0<len(value)<=128:
            network[key] = value
    selections = {'flow':('pkts_toserver','pkts_toclient','bytes_toserver','bytes_toclient','state'),
        'http':('http_method','hostname','status'), 'tls':('sni','version')}
    for section,keys in selections.items():
        source = data.get(section, {})
        if not isinstance(source, dict): continue
        values = {k:v for k in keys if (v:=source.get(k)) is not None
            and ((type(v) is int and 0<=v<2**63) or (isinstance(v,str) and 0<len(v)<=256))}
        if values: network[section] = values
    if network: security['network'] = network
    return {'security':security} if security else {}


def network_tuple(text):
    """Read the endpoint tuple from an older IDS text record without guessing roles."""
    match=re.search(r'\{(TCP|UDP)\}\s+\[?([\da-fA-F:.]+)\]?:(\d{1,5})\s+->\s+\[?([\da-fA-F:.]+)\]?:(\d{1,5})\s*$',text)
    if not match:
        return {}
    protocol,src,sp,dst,dp=match.groups()
    try:
        if max(int(sp),int(dp))>65535: return {}
        return {'src_ip':str(ipaddress.ip_address(src)),'src_port':int(sp),
                'dst_ip':str(ipaddress.ip_address(dst)),'dst_port':int(dp),'protocol':protocol}
    except ValueError:
        return {}


def observations(raw: dict, groups: list[str]) -> dict:
    data = raw.get("data", {})
    rule = raw.get("rule", {})
    decoder = raw.get("decoder") or {}
    predecoder = raw.get("predecoder") or {}
    if not all(isinstance(x, dict) for x in (data, rule, decoder, predecoder)):
        return {}
    result = security_details(raw)
    group_set = set(groups)
    decoder_name = decoder.get("name", "")
    text = str(raw.get("full_log", ""))
    endpoints=network_tuple(text)
    if endpoints:
        result['network_tuple']=endpoints
    dns=data.get('dns',{})
    if isinstance(dns,dict) and isinstance(dns.get('query'),list):
        queries=dns['query']
        if len(queries)==1 and isinstance(queries[0],dict): dns=queries[0]
        elif len(queries)>1: result['multiple_dns_questions']=True
    if isinstance(dns,dict) and isinstance(dns.get('rrname'),str) and 0<len(dns['rrname'])<=2048:
        result['dns_query']=dns['rrname']
    # These are source-generated attack/recon rule groups, not URI keywords
    # or dataset identities. A 404 alone in an ordinary access log is not an
    # attack verdict. A detector-classified application alert needs review.
    if "web" in group_set and decoder_name == "web-accesslog":
        status = str(data.get("id", ""))
        method, path = str(data.get("protocol", "")), str(data.get("url", ""))
        if status.isdigit() and 400 <= int(status) <= 499 and path.startswith("/"):
            result["web"] = {"status": int(status), "method": method[:16], "path": path[:2048]}
            if group_set.intersection({"attack", "web_scan", "recon", "web_attack", "sql_injection"}):
                result["web_alert_review"] = True
    # Apache's own denied-access records must not become harmless just because
    # the denial worked. Ordinary access-log 403/404 responses remain distinct.
    if ({"apache", "web", "access_denied"}.issubset(group_set)
            and decoder_name == "apache-errorlog"
            and ((data.get("id") == "AH01276" and "Cannot serve directory " in text
                  and "directory index forbidden by Options directive" in text)
                 or (data.get("id") == "AH01630" and "client denied by server configuration:" in text))):
        result["web_alert_review"] = True
    # Preserve underlying Suricata priority even if an older Wazuh wrapper
    # assigns the same low rule level to every embedded alert.
    alert = data.get("alert")
    if ({"ids", "suricata"}.issubset(group_set) and data.get("event_type") == "alert"
            and isinstance(alert, dict) and str(alert.get("severity", "")) in {"1", "2", "3"}
            and str(alert.get("signature_id", "")).isdigit() and isinstance(alert.get("signature"), str)):
        result["suricata"] = {"priority": int(alert["severity"]),
            "signature_id": str(alert["signature_id"]), "signature": alert["signature"][:512],
            "category": str(alert.get("category", ""))[:256]}
    # Authentication success is not a general suppression authority: PAM,
    # sudo, su and externally sourced mail logins remain separate cases.
    if ({"dovecot", "authentication_success"}.issubset(group_set)
            and not group_set.intersection({"authentication_failed", "attack", "sudo", "su", "error"})
            and decoder_name == "dovecot" and predecoder.get("program_name") == "dovecot"):
        match = re.search(r"(?:imap|pop3)-login: Login: user=<([^<>,\r\n]+)>,[^\r\n]*?\brip=([^,\s]+),\s*lip=([^,\s]+),([^\r\n]*)$", text) if len(text.splitlines()) == 1 else None
        if match:
            user, peer, local, transport_tail = match.groups()
            result["mail_auth"] = {"username": user[:256], "src_ip": peer, "dst_ip": local,
                "tls": bool(re.search(r"(?:^|,)\s*TLS(?:,|\s*:\s*)", transport_tail))}
            try:
                address = ipaddress.ip_address(peer)
                # Restrict to RFC1918/loopback, not ipaddress.is_private's
                # wider set of reserved/documentation/non-routable ranges.
                internal = address.is_loopback or (address.version == 4 and any(address in ipaddress.ip_network(n)
                    for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")))
                privileged = user.casefold().split("@", 1)[0] in {"root", "admin", "administrator", "postmaster"}
                consistent = all(not data.get(k) or str(data[k]) == value for k, value in
                    (("dstuser", user), ("srcuser", user), ("srcip", peer), ("dstip", local),
                     ("src_ip", peer), ("dest_ip", local)))
                if peer == local and internal and not privileged and consistent and result["mail_auth"]["tls"]:
                    result["local_tls_mail_login"] = True
            except ValueError:
                result.pop("mail_auth", None)
    if (decoder_name == "freshclam" and {"clamd", "freshclam"}.issubset(group_set)
            and str(rule.get("id")) == "52507" and rule.get("description") == "ClamAV database update"
            and "ClamAV update process started at " in text
            and not re.search(r"\b(?:error|failed|failure|found|disabled|stopped)\b", text, re.I)):
        result["signature_database_update"] = True
    target = str(data.get("dstuser", "")).casefold()
    program = str(predecoder.get("program_name", "")).casefold()
    actor = str(data.get("srcuser", "")).casefold()
    service_actor = actor in {"www-data", "www", "apache", "nginx", "nobody"} or str(data.get("uid", "")) in {"33", "48"}
    if (("sudo" in group_set and target == "root")
            or ("authentication_success" in group_set and program in {"su", "sudo"}
                and (target == "root" or service_actor))):
        result["privileged_session_review"] = True
    return result
