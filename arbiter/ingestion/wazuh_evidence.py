"""Extract bounded observations from native Wazuh evidence, never test labels."""
import ipaddress
import re


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
    result = {}
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
    if {"web", "accesslog"}.issubset(group_set) and decoder_name == "web-accesslog":
        status = str(data.get("id", ""))
        method, path = str(data.get("protocol", "")), str(data.get("url", ""))
        if status.isdigit() and 400 <= int(status) <= 499 and path.startswith("/"):
            result["web"] = {"status": int(status), "method": method[:16], "path": path[:2048]}
            if group_set.intersection({"attack", "web_scan", "recon", "web_attack", "sql_injection"}):
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
