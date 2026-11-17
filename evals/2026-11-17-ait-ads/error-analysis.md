# Disagreements with published event labels

Attack-annotation suppressions are listed first. No annotation does not independently establish harmlessness; negative-label escalations may still be defensible precautionary reviews.

## Attack-annotated alerts suppressed (14)

### fox:102995 — dirb

Source message: Web server 400 error code. | {"data": {"id": "404", "protocol": "GET", "srcip": "172.17.130.196", "url": "/wp-content/themes/_source"}, "syscheck": {}} | 172.17.130.196 - - [18/Jan/2022:12:21:31 +0000] "GET /wp-content/themes/_source HTTP/1.1" 404 363 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"

Decision: **suppress**, tier `llm`, source severity 3.33.

Rationale: This is a benign access log entry indicating the requested resource does not exist; there is no evidence of intrusion, credential abuse, or lateral movement.

Evidence: The event is a standard HTTP 404 error response from a web server to an internal IP address (172.17.130.196) requesting a non-existent file path (/wp-content/themes/_source).

### fox:444721 — dirb

Source message: Web server 400 error code. | {"data": {"id": "404", "protocol": "GET", "srcip": "172.17.130.196", "url": "/wp-includes/js/tinymce/skins/wordpress/images/oa_servlets"}, "syscheck": {}} | 172.17.130.196 - - [18/Jan/2022:12:37:43 +0000] "GET /wp-includes/js/tinymce/skins/wordpress/images/oa_servlets HTTP/1.1" 404 363 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"

Decision: **suppress**, tier `llm`, source severity 3.33.

Rationale: This is a benign web server response indicating a missing file rather than an intrusion attempt, and no suspicious behavior or credential abuse is recorded.

Evidence: The event is a standard HTTP 404 error for a legitimate WordPress TinyMCE asset path accessed by a known legacy browser (MSIE 6.0) from an internal IP address.

### harrison:278689 — dirb

Source message: Web server 400 error code. | {"data": {"id": "404", "protocol": "GET", "srcip": "10.237.1.238", "url": "/wp-includes/widgets/wellcome"}, "syscheck": {}} | 10.237.1.238 - - [08/Feb/2022:07:37:22 +0000] "GET /wp-includes/widgets/wellcome HTTP/1.1" 404 363 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"

Decision: **suppress**, tier `llm`, source severity 3.33.

Rationale: The recorded behavior is a standard 404 error response to a specific URL path, which indicates the requested resource does not exist rather than a successful exploit or data breach. Since this is the first occurrence and no suspicious user activity or lateral movement is present, it represents a benign anomaly requiring no escalation.

Evidence: The event is a standard HTTP 404 error response from a web server to an internal IP (10.237.1.238) requesting a non-existent file path (/wp-includes/widgets/wellcome). This is a common benign occurrence for WordPress sites where plugin or theme files are missing, not an intrusion indicator.

### harrison:332996 — dirb

Source message: Web server 400 error code. | {"data": {"id": "404", "protocol": "GET", "srcip": "10.237.1.238", "url": "/wp-includes/blocks/embed/bots"}, "syscheck": {}} | 10.237.1.238 - - [08/Feb/2022:07:40:46 +0000] "GET /wp-includes/blocks/embed/bots HTTP/1.1" 404 363 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"

Decision: **suppress**, tier `llm`, source severity 3.33.

Rationale: This is a benign network response indicating the requested resource does not exist; there is no evidence of intrusion, credential abuse, or lateral movement in this isolated HTTP event.

Evidence: The event is a standard HTTP 404 error response from a web server to an internal IP address (10.237.1.238) requesting a non-existent WordPress file path.

### russellmitchell:26969 — dirb

Source message: Web server 400 error code. | {"data": {"id": "404", "protocol": "GET", "srcip": "172.19.131.174", "url": "/faces"}, "syscheck": {}} | 172.19.131.174 - - [24/Jan/2022:03:57:30 +0000] "GET /faces HTTP/1.1" 404 363 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"

Decision: **suppress**, tier `llm`, source severity 3.33.

Rationale: The recorded behavior is a common HTTP response indicating a missing resource, which poses no security risk or indicates compromise; therefore, this alert can be safely suppressed as it does not meet criteria for escalation.

Evidence: The event is a standard HTTP 404 error response from a web server to an internal IP address (172.19.131.174) requesting a non-existent path (/faces). This matches the signature definition for 'Web server 400 error code' and represents benign traffic.

### santos:109717 — dirb

Source message: Web server 400 error code. | {"data": {"id": "404", "protocol": "GET", "srcip": "172.21.128.119", "url": "/gpl"}, "syscheck": {}} | 172.21.128.119 - - [17/Jan/2022:11:22:06 +0000] "GET /gpl HTTP/1.1" 404 363 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"

Decision: **suppress**, tier `llm`, source severity 3.33.

Rationale: A 404 error indicates the requested resource does not exist, which is normal web behavior and poses no security risk; since this is the first occurrence and there are no environment facts suggesting otherwise, it requires no escalation.

Evidence: The event is a standard HTTP 404 error response from a web server to an external IP (172.21.128.119) requesting a non-existent path (/gpl). This is a common benign occurrence for legitimate users or automated crawlers.

### santos:110826 — dirb

Source message: Web server 400 error code. | {"data": {"id": "404", "protocol": "GET", "srcip": "172.21.128.119", "url": "/payment_gateway"}, "syscheck": {}} | 172.21.128.119 - - [17/Jan/2022:11:22:09 +0000] "GET /payment_gateway HTTP/1.1" 404 363 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"

Decision: **suppress**, tier `llm`, source severity 3.33.

Rationale: This is a benign network event indicating a missing resource rather than an intrusion; the signature has no prior history and no suspicious indicators like brute force attempts or unauthorized access are present.

Evidence: The event is a standard HTTP 404 error response from a web server to an internal IP address (172.21.128.119) requesting a non-existent path (/payment_gateway), which is common for legitimate application logic or development testing.

### shaw:47435 — dirb

Source message: Web server 400 error code. | {"data": {"id": "404", "protocol": "GET", "srcip": "172.24.249.224", "url": "/mock"}, "syscheck": {}} | 172.24.249.224 - - [29/Jan/2022:14:39:20 +0000] "GET /mock HTTP/1.1" 404 363 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"

Decision: **suppress**, tier `llm`, source severity 3.33.

Rationale: A 404 error indicates the requested resource does not exist, which is a normal operational state for web servers and does not indicate intrusion or compromise.

Evidence: The event is a standard HTTP 404 error response from a web server to an internal IP (172.24.249.224) for a non-existent path (/mock), which is common benign behavior.

### shaw:49373 — dirb

Source message: Web server 400 error code. | {"data": {"id": "404", "protocol": "GET", "srcip": "172.24.249.224", "url": "/world"}, "syscheck": {}} | 172.24.249.224 - - [29/Jan/2022:14:39:26 +0000] "GET /world HTTP/1.1" 404 363 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"

Decision: **suppress**, tier `llm`, source severity 3.33.

Rationale: This is a benign HTTP error indicating the requested resource does not exist; there is no evidence of intrusion, credential abuse, or lateral movement in this specific event.

Evidence: The event is a standard HTTP 404 response from a web server to an internal IP (172.24.249.224) requesting a non-existent path (/world), which is normal operational behavior.

### wardbeck:77257 — dirb

Source message: Web server 400 error code. | {"data": {"id": "404", "protocol": "GET", "srcip": "10.132.56.81", "url": "/jvm"}, "syscheck": {}} | 10.132.56.81 - - [23/Jan/2022:12:11:55 +0000] "GET /jvm HTTP/1.1" 404 363 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"

Decision: **suppress**, tier `llm`, source severity 3.33.

Rationale: This is a benign network response indicating the requested resource does not exist; there is no evidence of intrusion, credential abuse, or lateral movement in this specific event.

Evidence: The event is a standard HTTP 404 error response from a web server to an internal IP (10.132.56.81) requesting a non-existent path (/jvm), which is common for outdated client software or legitimate testing.

### wheeler:191382 — dirb

Source message: Web server 400 error code. | {"data": {"id": "404", "protocol": "GET", "srcip": "10.38.243.125", "url": "/wp-admin/js/kernel"}, "syscheck": {}} | 10.38.243.125 - - [30/Jan/2022:07:41:13 +0000] "GET /wp-admin/js/kernel HTTP/1.1" 404 363 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"

Decision: **suppress**, tier `llm`, source severity 3.33.

Rationale: The recorded behavior is a failed HTTP request resulting in a 404 error, which is a normal operational state for web servers and requires no escalation given the lack of suspicious indicators.

Evidence: The event is a standard HTTP 404 error response from a web server to an external IP (10.38.243.125) requesting a non-existent file path (/wp-admin/js/kernel). This is a common benign occurrence for web applications and does not indicate intrusion, credential abuse, or lateral movement.

### wheeler:350010 — dirb

Source message: Web server 400 error code. | {"data": {"id": "404", "protocol": "GET", "srcip": "10.38.243.125", "url": "/wp-includes/blocks/list/mailinglist"}, "syscheck": {}} | 10.38.243.125 - - [30/Jan/2022:07:47:39 +0000] "GET /wp-includes/blocks/list/mailinglist HTTP/1.1" 404 363 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"

Decision: **suppress**, tier `llm`, source severity 3.33.

Rationale: This is a benign informational alert indicating the requested resource does not exist; there is no evidence of intrusion, credential abuse, or lateral movement in this specific event.

Evidence: The event is a standard HTTP 404 error response from a web server to an external IP (10.38.243.125) requesting a non-existent WordPress block file.

### wilson:276910 — dirb

Source message: Web server 400 error code. | {"data": {"id": "404", "protocol": "GET", "srcip": "10.182.193.78", "url": "/wp-admin/js/widgets/clients"}, "syscheck": {}} | 10.182.193.78 - - [07/Feb/2022:11:05:34 +0000] "GET /wp-admin/js/widgets/clients HTTP/1.1" 404 363 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"

Decision: **suppress**, tier `llm`, source severity 3.33.

Rationale: The recorded behavior is a benign server response indicating a missing resource; there is no evidence of intrusion, credential abuse, or lateral movement, and the signature has never been seen before so it does not represent a known attack pattern requiring escalation.

Evidence: The event is a standard HTTP 404 error response from a web server to an external IP (10.182.193.78) requesting a non-existent file path (/wp-admin/js/widgets/clients). This is a common occurrence for WordPress sites where specific plugin or theme assets are missing, outdated, or intentionally not deployed.

### wilson:480278 — dirb

Source message: Web server 400 error code. | {"data": {"id": "404", "protocol": "GET", "srcip": "10.182.193.78", "url": "/wp-includes/js/tinymce/langs/blue"}, "syscheck": {}} | 10.182.193.78 - - [07/Feb/2022:11:15:15 +0000] "GET /wp-includes/js/tinymce/langs/blue HTTP/1.1" 404 363 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"

Decision: **suppress**, tier `llm`, source severity 3.33.

Rationale: This is a benign web server response indicating missing client-side resources, not an intrusion or attack; no suspicious user, process, or lateral movement is present.

Evidence: The event is a standard HTTP 404 error for a legitimate WordPress TinyMCE language file requested by an external browser (MSIE 6.0), which is common behavior for web servers serving content.

## Alerts without attack annotations escalated (123)

### fox:785 — -

Source message: IDS event. | {"data": {"dstip": "192.168.128.4", "dstport": 48308, "id": "1:2230003:1", "srcip": "213.180.204.211"}, "syscheck": {}} | 01/15/2022-08:40:05.926802  [**] [1:2230003:1] SURICATA TLS invalid handshake message [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 213.180.204.211:443 -> 192.168.128.4:48308

Decision: **escalate**, tier `llm`, source severity 4.00.

Rationale: This is the first occurrence of a TLS handshake anomaly involving an external source and an internal destination, which requires manual verification to rule out reconnaissance or exploitation before suppression.

Evidence: Suricata TLS invalid handshake message detected from external IP 213.180.204.211 targeting internal host 192.168.128.4 on port 48308.

### fox:5484 — -

Source message: Suricata: Alert - SURICATA TLS invalid record/traffic | {"data": {"alert": {"action": "allowed", "category": "Generic Protocol Command Decode", "gid": "1", "rev": "1", "severity": "3", "signature": "SURICATA TLS invalid record/traffic", "signature_id": "2230010"}, "app_proto": "tls", "dest_ip": "192.168.128.4", "dest_port": "54646", "event_type": "alert", "flow": {"bytes_toclient": "257", "bytes_toserver": "1911", "pkts_toclient": "3", "pkts_toserver": "9", "start": "2022-01-15T14:03:58.290129+0000"}, "flow_id": "1804482531716433.000000", "in_iface": "ens3", "metadata": {"flowints": {"tls": {"anomaly": {"count": "2"}}}}, "proto": "TCP", "src_ip": "54.77.190.128", "src_port": "443", "timestamp": "2022-01-15T14:03:58.462599+0000", "tls": {"ja3": {"hash": "a75de44db3e351bbd8d38b64c41f444e", "string": "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53-10,0-23-65281-10-11-16-5-51-43-13-28-21,29-23-24-25-256-257,0"}, "sni": "e.deployads.com", "version": "UNDETERMINED"}, "tx_id": "0"}, "syscheck": {}}

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: This is a precautionary review of an unusual TLS flow; without historical baselines or benign facts covering this specific external source/port combination, the risk of credential abuse or lateral movement cannot be ruled out.

Evidence: TLS handshake anomaly detected from external IP 54.77.190.128 to internal host wazuh-client targeting non-standard port 54646 for SNI e.deployads.com.

### fox:7109 — -

Source message: Dovecot Authentication Success. | {"data": {}, "syscheck": {}} | Jan 15 15:40:20 taylorcruz-mail dovecot: imap-login: Login: user=<christopher.friedman>, method=PLAIN, rip=192.168.128.195, lip=192.168.128.195, mpid=10142, TLS, session=<iz+ovKDVxqvAqIDD>

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: The use of PLAIN authentication for a mail server is inherently risky due to lack of encryption, and the absence of prior benign history means this cannot be dismissed as normal activity without verification.

Evidence: Successful PLAIN authentication via Dovecot from external IP 192.168.128.195 using user christopher.friedman without TLS negotiation (despite 'TLS' flag in log which may indicate protocol version or misconfiguration), flagged as first occurrence.

### fox:12543 — -

Source message: Suricata: Alert - SURICATA TLS invalid record/traffic | {"data": {"alert": {"action": "allowed", "category": "Generic Protocol Command Decode", "gid": "1", "rev": "1", "severity": "3", "signature": "SURICATA TLS invalid record/traffic", "signature_id": "2230010"}, "app_proto": "tls", "dest_ip": "192.168.128.4", "dest_port": "45532", "event_type": "alert", "flow": {"bytes_toclient": "206", "bytes_toserver": "1010", "pkts_toclient": "3", "pkts_toserver": "6", "start": "2022-01-16T10:37:08.520066+0000"}, "flow_id": "482835749465986.000000", "in_iface": "ens3", "metadata": {"flowints": {"tls": {"anomaly": {"count": "2"}}}}, "proto": "TCP", "src_ip": "151.101.193.108", "src_port": "443", "timestamp": "2022-01-16T10:37:09.075782+0000", "tls": {"ja3": {"hash": "a75de44db3e351bbd8d38b64c41f444e", "string": "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53-10,0-23-65281-10-11-16-5-51-43-13-28-21,29-23-24-25-256-257,0"}, "sni": "acdn.adnxs.com", "version": "UNDETERMINED"}, "tx_id": "0"}, "syscheck": {}}

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: The alert indicates a TLS protocol anomaly originating from an external IP targeting the Wazuh client, which requires manual verification to distinguish between a legitimate but malformed handshake and potential exploitation.

Evidence: Suricata detected TLS invalid record/traffic from external IP 151.101.193.108 to internal host wazuh-client on port 45532; this is the first occurrence of this signature and no benign fact covers this specific traffic pattern.

### fox:18013 — -

Source message: IDS event. | {"data": {"dstip": "192.168.128.4", "dstport": 33648, "id": "1:2230010:1", "srcip": "92.123.19.250"}, "syscheck": {}} | 01/16/2022-16:23:21.722239  [**] [1:2230010:1] SURICATA TLS invalid record/traffic [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 92.123.19.250:443 -> 192.168.128.4:33648

Decision: **escalate**, tier `llm`, source severity 4.00.

Rationale: This is the first occurrence of this signature, and while the specific port may be benign for certain services, the alert indicates malformed TLS traffic which could indicate an exploit attempt or reconnaissance; without a verified benign fact covering this exact source/destination/port combination, the risk of intrusion must be treated seriously.

Evidence: Suricata TLS invalid record/traffic alert originating from external IP 92.123.19.250 targeting internal host wazuh-client on a non-standard port (33648).

### fox:18475 — -

Source message: Suricata: Alert - SURICATA TLS invalid record/traffic | {"data": {"alert": {"action": "allowed", "category": "Generic Protocol Command Decode", "gid": "1", "rev": "1", "severity": "3", "signature": "SURICATA TLS invalid record/traffic", "signature_id": "2230010"}, "app_proto": "tls", "dest_ip": "172.17.130.196", "dest_port": "43604", "event_type": "alert", "flow": {"bytes_toclient": "171", "bytes_toserver": "1181", "pkts_toclient": "2", "pkts_toserver": "9", "start": "2022-01-16T16:26:55.642608+0000"}, "flow_id": "1098550751514160.000000", "in_iface": "ens3", "metadata": {"flowints": {"tls": {"anomaly": {"count": "2"}}}}, "proto": "TCP", "src_ip": "20.50.201.200", "src_port": "443", "timestamp": "2022-01-16T16:26:55.728414+0000", "tls": {"ja3": {"hash": "cd08e31494f9531f560d64c695473da9", "string": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0"}, "sni": "browser.events.data.microsoft.com", "version": "UNDETERMINED"}, "tx_id": "0"}, "syscheck": {}}

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: This is the first occurrence of this signature, and while the SNI indicates a legitimate Microsoft service, TLS protocol anomalies can indicate compromised clients or misconfigured endpoints attempting to communicate with valid servers; without baseline data or benign context, the risk of credential theft or lateral movement via malformed traffic cannot be ruled out.

Evidence: TLS invalid record/traffic detected from src_ip 20.50.201.200 to dest_ip 172.17.130.196 targeting browser.events.data.microsoft.com on port 43604.

### fox:18968 — -

Source message: Dovecot Authentication Success. | {"data": {}, "syscheck": {}} | Jan 16 17:16:32 mail dovecot: imap-login: Login: user=<brian.potter>, method=PLAIN, rip=172.17.131.81, lip=172.17.131.81, mpid=25463, TLS, session=<8M2KMrbVPMqsEYNR>

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: The use of the PLAIN method for email login is inherently insecure due to lack of encryption, and since this is a first occurrence with no benign history or environment facts to explain it, immediate verification is required to rule out credential compromise.

Evidence: Successful PLAIN authentication via Dovecot from IP 172.17.131.81 by user brian.potter without TLS encryption.

### fox:24355 — -

Source message: Dovecot Authentication Success. | {"data": {}, "syscheck": {}} | Jan 17 09:38:37 taylorcruz-mail dovecot: imap-login: Login: user=<damian.jordan>, method=PLAIN, rip=192.168.128.195, lip=192.168.128.195, mpid=26334, TLS, session=<25jA6sPVnLbAqIDD>

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: The use of the PLAIN method over an unencrypted channel represents a direct credential exposure risk, and this is the first occurrence of this signature requiring immediate verification of user intent and network configuration.

Evidence: Successful PLAIN authentication via Dovecot from IP 192.168.128.195 using user 'damian.jordan' without TLS negotiation (despite session flag indicating TLS context), which is a known vector for credential theft.

### fox:27990 — -

Source message: Dovecot Authentication Success. | {"data": {}, "syscheck": {}} | Jan 17 14:14:47 taylorcruz-mail dovecot: imap-login: Login: user=<margaret.alexander>, method=PLAIN, rip=192.168.128.195, lip=192.168.128.195, mpid=29214, TLS, session=<22NkxsfVmLrAqIDD>

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: While the user is likely legitimate given the internal IP and successful login, the use of unencrypted PLAIN authentication represents a significant security risk that requires verification before assuming benign activity.

Evidence: Successful authentication via PLAIN method (unencrypted) from IP 192.168.128.195 by user margaret.alexander on a first-time occurrence.

### fox:29014 — -

Source message: Dovecot Authentication Success. | {"data": {}, "syscheck": {}} | Jan 17 15:53:23 mail dovecot: imap-login: Login: user=<meghan.morris>, method=PLAIN, rip=172.17.131.81, lip=172.17.131.81, mpid=3451, TLS, session=<Z/UBJ8nVltasEYNR>

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: The use of the PLAIN method over an unencrypted channel exposes credentials to interception, and this is the first occurrence of this signature requiring immediate verification of the user's intent and network configuration.

Evidence: Successful PLAIN authentication via Dovecot from IP 172.17.131.81 using user 'meghan.morris' without TLS encryption (despite TLS session flag in log), which is a known vector for credential interception.

### fox:449222 — -

Source message: Dovecot Authentication Success. | {"data": {}, "syscheck": {}} | Jan 18 16:59:38 mail dovecot: imap-login: Login: user=<meghan.morris>, method=PLAIN, rip=172.17.131.81, lip=172.17.131.81, mpid=14229, TLS, session=<LN3LMd7V8uCsEYNR>

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: The use of the PLAIN method indicates unencrypted credential transmission, which is a significant security risk regardless of the asset's low criticality or lack of prior activity; this requires immediate verification to rule out compromised credentials or unauthorized access attempts.

Evidence: Successful authentication via PLAIN method (unencrypted) for user 'meghan.morris' from IP 172.17.131.81 on a first-time occurrence with no benign history.

### fox:449406 — -

Source message: IDS event. | {"data": {"dstip": "192.168.128.4", "dstport": 51240, "id": "1:2230010:1", "srcip": "94.100.180.72"}, "syscheck": {}} | 01/18/2022-17:06:09.723346  [**] [1:2230010:1] SURICATA TLS invalid record/traffic [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 94.100.180.72:443 -> 192.168.128.4:51240

Decision: **escalate**, tier `llm`, source severity 4.00.

Rationale: This is the first occurrence of a generic protocol decode anomaly targeting an internal host; without benign context or baseline data, the risk of credential abuse or lateral movement cannot be ruled out.

Evidence: Suricata TLS invalid record/traffic detected from external IP 94.100.180.72 to internal host wazuh-client on port 51240.

### fox:450417 — -

Source message: IDS event. | {"data": {"dstip": "192.168.128.4", "dstport": 56054, "id": "1:2230010:1", "srcip": "66.155.71.149"}, "syscheck": {}} | 01/18/2022-18:01:32.525197  [**] [1:2230010:1] SURICATA TLS invalid record/traffic [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 66.155.71.149:443 -> 192.168.128.4:56054

Decision: **escalate**, tier `llm`, source severity 4.00.

Rationale: This is the first occurrence of a TLS protocol anomaly involving an external source, which requires immediate verification to rule out active exploitation or reconnaissance before considering it benign.

Evidence: Suricata TLS invalid record/traffic detected from external IP 66.155.71.149 targeting internal host wazuh-client on port 56054.

### fox:455713 — -

Source message: Suricata: Alert - SURICATA TLS invalid handshake message | {"data": {"alert": {"action": "allowed", "category": "Generic Protocol Command Decode", "gid": "1", "rev": "1", "severity": "3", "signature": "SURICATA TLS invalid handshake message", "signature_id": "2230003"}, "app_proto": "tls", "dest_ip": "18.211.116.125", "dest_port": "443", "event_type": "alert", "flow": {"bytes_toclient": "392", "bytes_toserver": "1879", "pkts_toclient": "4", "pkts_toserver": "12", "start": "2022-01-19T10:46:03.760831+0000"}, "flow_id": "394612668341247.000000", "in_iface": "ens3", "metadata": {"flowints": {"tls": {"anomaly": {"count": "4"}}}}, "proto": "TCP", "src_ip": "172.17.130.196", "src_port": "54078", "timestamp": "2022-01-19T10:46:04.138876+0000", "tls": {"ja3": {"hash": "aa7744226c695c0b2e440419848cf700", "string": "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53-10,0-23-65281-10-11-35-16-5-51-43-13-45-28-21,29-23-24-25-256-257,0"}, "sni": "l.evidon.com", "version": "UNDETERMINED"}, "tx_id": "0"}, "syscheck": {}}

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: This is the first occurrence of a TLS invalid handshake alert; without benign baseline or environment facts to explain this specific protocol error, the risk of credential abuse or lateral movement cannot be ruled out.

Evidence: TLS handshake anomaly detected on internal host wazuh-client (172.17.130.196) communicating with external IP 18.211.116.125 via port 443 to domain l.evidon.com.

### fox:456167 — -

Source message: Dovecot Authentication Success. | {"data": {}, "syscheck": {}} | Jan 19 11:21:29 taylorcruz-mail dovecot: imap-login: Login: user=<margaret.alexander>, method=PLAIN, rip=192.168.128.195, lip=192.168.128.195, mpid=13488, TLS, session=<UslNlu3VgMXAqIDD>

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: The use of the PLAIN method over an unencrypted channel represents a significant security risk, and this is the first occurrence of this signature requiring immediate verification of user intent and connection encryption status.

Evidence: Successful PLAIN authentication via Dovecot from external IP 192.168.128.195 using user 'margaret.alexander' without TLS negotiation (despite session flag indicating TLS context), which is a known vector for credential theft.

### fox:456449 — -

Source message: IDS event. | {"data": {"dstip": "13.107.42.14", "dstport": 443, "id": "1:2230010:1", "srcip": "172.17.130.196"}, "syscheck": {}} | 01/19/2022-11:49:22.107346  [**] [1:2230010:1] SURICATA TLS invalid record/traffic [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 172.17.130.196:52580 -> 13.107.42.14:443

Decision: **escalate**, tier `llm`, source severity 4.00.

Rationale: This is the first occurrence of a TLS protocol anomaly targeting an external Microsoft service; without historical benign context or specific environment facts explaining this traffic, the risk of credential abuse or lateral movement cannot be ruled out.

Evidence: Suricata TLS invalid record/traffic detected from internal host 172.17.130.196 to external IP 13.107.42.14 (Microsoft Azure) on port 443.

### harrison:20668 — -

Source message: Suricata: Alert - SURICATA TLS invalid handshake message | {"data": {"alert": {"action": "allowed", "category": "Generic Protocol Command Decode", "gid": "1", "rev": "1", "severity": "3", "signature": "SURICATA TLS invalid handshake message", "signature_id": "2230003"}, "app_proto": "tls", "dest_ip": "10.237.1.238", "dest_port": "39028", "event_type": "alert", "flow": {"bytes_toclient": "480", "bytes_toserver": "4275", "pkts_toclient": "3", "pkts_toserver": "13", "start": "2022-02-04T13:03:42.509236+0000"}, "flow_id": "2113839628731700.000000", "in_iface": "ens3", "metadata": {"flowints": {"tls": {"anomaly": {"count": "2"}}}}, "proto": "TCP", "src_ip": "52.206.11.147", "src_port": "443", "timestamp": "2022-02-04T13:03:42.849588+0000", "tls": {"ja3": {"hash": "aa7744226c695c0b2e440419848cf700", "string": "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53-10,0-23-65281-10-11-35-16-5-51-43-13-45-28-21,29-23-24-25-256-257,0"}, "sni": "marketplace.anyclip.com", "version": "UNDETERMINED"}, "tx_id": "0"}, "syscheck": {}}

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: The event records an invalid TLS handshake from an external source to a specific domain, which raises immediate concern for potential credential theft or lateral movement attempts despite the lack of prior occurrences.

Evidence: TLS handshake anomaly detected from external IP 52.206.11.147 targeting marketplace.anyclip.com on port 39028; signature is a first occurrence with no benign history.

### harrison:52618 — -

Source message: IDS event. | {"data": {"dstip": "10.237.0.166", "dstport": 42802, "id": "1:2230003:1", "srcip": "10.237.2.255"}, "syscheck": {}} | 02/05/2022-10:19:30.644379  [**] [1:2230003:1] SURICATA TLS invalid handshake message [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 10.237.2.255:443 -> 10.237.0.166:42802

Decision: **escalate**, tier `llm`, source severity 4.00.

Rationale: This is the first occurrence of a TLS protocol anomaly between two internal hosts, and without historical baselines or benign context, it cannot be dismissed as false positive; potential credential theft or lateral movement must be ruled out.

Evidence: Suricata TLS invalid handshake message detected from internal IP 10.237.2.255 to internal IP 10.237.0.166 on port 42802.

### harrison:61899 — -

Source message: IDS event. | {"data": {"dstip": "10.237.0.1", "dstport": 53, "id": "1:2027865:4", "srcip": "10.237.1.238"}, "syscheck": {}} | 02/05/2022-14:27:26.031826  [**] [1:2027865:4] ET INFO Observed DNS Query to .cloud TLD [**] [Classification: Potentially Bad Traffic] [Priority: 2] {UDP} 10.237.1.238:56987 -> 10.237.0.1:53

Decision: **escalate**, tier `llm`, source severity 4.00.

Rationale: This is the first occurrence of this signature and no benign environment facts exist to explain why a .cloud TLD query from this specific host would be safe; potential data exfiltration or C2 communication cannot be ruled out without investigation.

Evidence: DNS query to .cloud TLD from internal host 10.237.1.238 to DNS server 10.237.0.1 flagged as potentially bad traffic by IDS rule 20101.

### harrison:73247 — -

Source message: IDS event. | {"data": {"dstip": "172.28.255.254", "dstport": 53, "id": "1:2027863:4", "srcip": "172.28.192.4"}, "syscheck": {}} | 02/05/2022-23:11:03.458675  [**] [1:2027863:4] ET INFO Observed DNS Query to .biz TLD [**] [Classification: Potentially Bad Traffic] [Priority: 2] {UDP} 172.28.192.4:45320 -> 172.28.255.254:53

Decision: **escalate**, tier `llm`, source severity 4.00.

Rationale: This is the first occurrence of this signature and no benign fact covers a DNS query to .biz; while the target IP may be an internal resolver, the rule flags potentially bad traffic which requires verification before suppression.

Evidence: DNS query to .biz TLD from internal IP 172.28.192.4 to external resolver 172.28.255.254 at 23:11:03 on 2022-02-05

### harrison:87873 — -

Source message: Multiple IDS alerts for same id. | {"data": {"dstip": "192.168.128.1", "dstport": 53, "id": "1:2027863:4", "srcip": "192.168.131.109"}, "syscheck": {}} | 02/06/2022-10:53:50.115054  [**] [1:2027863:4] ET INFO Observed DNS Query to .biz TLD [**] [Classification: Potentially Bad Traffic] [Priority: 2] {UDP} 192.168.131.109:50636 -> 192.168.128.1:53

Decision: **escalate**, tier `prefilter`, source severity 6.67.

Rationale: score 8.7 >= 7.0 (severity 6.666666666666667, asset criticality 1.3)

Evidence: Auto-escalated by prefilter: Multiple IDS alerts for same id. | {"data": {"dstip": "192.168.128.1", "dstport": 53, "id": "1:2027863:4", "srcip": "192.168.131.109"}, "syscheck": {}} | 02/06/2022-10:53:50.115054  [**] [1:2027863:4] ET INFO Observed DNS Query to .biz TLD [**] [Classification: Potentially Bad Traffic] [Priority: 2] {UDP} 192.168.131.109:50636 -> 192.168.128.1:53

### harrison:90334 — -

Source message: Dovecot Authentication Success. | {"data": {}, "syscheck": {}} | Feb  6 11:50:31 taylor-mail dovecot: imap-login: Login: user=<wayne.riley>, method=PLAIN, rip=172.28.192.7, lip=172.28.192.7, mpid=306, TLS, session=<OCVNF1jX2N6sHMAH>

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: The event records a successful login using the insecure PLAIN method, creating an immediate risk of credential theft that cannot be justified by benign facts or signature history.

Evidence: Successful PLAIN authentication via Dovecot from IP 172.28.192.7 by user wayne.riley without TLS encryption (despite session flag), which is a known vector for credential interception.

### harrison:94536 — -

Source message: Suricata: Alert - SURICATA TLS invalid record/traffic | {"data": {"alert": {"action": "allowed", "category": "Generic Protocol Command Decode", "gid": "1", "rev": "1", "severity": "3", "signature": "SURICATA TLS invalid record/traffic", "signature_id": "2230010"}, "app_proto": "tls", "dest_ip": "10.237.1.238", "dest_port": "55598", "event_type": "alert", "flow": {"bytes_toclient": "206", "bytes_toserver": "1175", "pkts_toclient": "3", "pkts_toserver": "8", "start": "2022-02-06T14:13:11.943107+0000"}, "flow_id": "2121038854317059.000000", "in_iface": "ens3", "metadata": {"flowints": {"tls": {"anomaly": {"count": "2"}}}}, "proto": "TCP", "src_ip": "52.223.40.198", "src_port": "443", "timestamp": "2022-02-06T14:13:12.040932+0000", "tls": {"ja3": {"hash": "a75de44db3e351bbd8d38b64c41f444e", "string": "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53-10,0-23-65281-10-11-16-5-51-43-13-28-21,29-23-24-25-256-257,0"}, "sni": "match.adsrvr.org", "version": "UNDETERMINED"}, "tx_id": "0"}, "syscheck": {}}

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: The signature indicates malformed TLS traffic originating from an external source targeting the Wazuh client, which requires manual verification to distinguish between a legitimate misconfigured service and potential protocol abuse or intrusion.

Evidence: TLS invalid record/traffic detected from external IP 52.223.40.198 to internal host wazuh-client on port 55598 with SNI match.adsrvr.org.

### harrison:106931 — -

Source message: Multiple IDS alerts for same id. | {"data": {"dstip": "172.28.255.254", "dstport": 53, "id": "1:2027863:4", "srcip": "172.28.192.4"}, "syscheck": {}} | 02/06/2022-22:26:36.351256  [**] [1:2027863:4] ET INFO Observed DNS Query to .biz TLD [**] [Classification: Potentially Bad Traffic] [Priority: 2] {UDP} 172.28.192.4:56168 -> 172.28.255.254:53

Decision: **escalate**, tier `prefilter`, source severity 6.67.

Rationale: score 8.7 >= 7.0 (severity 6.666666666666667, asset criticality 1.3)

Evidence: Auto-escalated by prefilter: Multiple IDS alerts for same id. | {"data": {"dstip": "172.28.255.254", "dstport": 53, "id": "1:2027863:4", "srcip": "172.28.192.4"}, "syscheck": {}} | 02/06/2022-22:26:36.351256  [**] [1:2027863:4] ET INFO Observed DNS Query to .biz TLD [**] [Classification: Potentially Bad Traffic] [Priority: 2] {UDP} 172.28.192.4:56168 -> 172.28.255.254:53

### harrison:123183 — -

Source message: Dovecot Authentication Success. | {"data": {}, "syscheck": {}} | Feb  7 10:33:45 mail dovecot: imap-login: Login: user=<logan.wright>, method=PLAIN, rip=10.237.2.255, lip=10.237.2.255, mpid=13883, TLS, session=<DqydImvXgIMK7QL/>

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: The use of the PLAIN authentication method without TLS encryption represents a significant credential exposure risk, as credentials are transmitted in clear text; this is a confirmed malicious pattern regardless of the asset's low criticality or lack of historical context.

Evidence: Successful authentication via PLAIN method (unencrypted) for user 'logan.wright' from IP 10.237.2.255 on a Dovecot service.

### harrison:124777 — -

Source message: Dovecot Authentication Success. | {"data": {}, "syscheck": {}} | Feb  7 11:18:29 taylor-mail dovecot: imap-login: Login: user=<leslie.williams>, method=PLAIN, rip=172.28.192.7, lip=172.28.192.7, mpid=10769, TLS, session=<DbqUwmvXZuisHMAH>

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: The use of the PLAIN method over an unencrypted channel represents a critical security risk, and the absence of TLS in the log despite the session flag indicates a potential misconfiguration or active attack that cannot be explained by benign facts.

Evidence: Successful PLAIN authentication via Dovecot from IP 172.28.192.7 using user 'leslie.williams' without TLS negotiation (despite session flag), which is a known vector for credential theft.

### harrison:126582 — -

Source message: Suricata: Alert - SURICATA TLS invalid record/traffic | {"data": {"alert": {"action": "allowed", "category": "Generic Protocol Command Decode", "gid": "1", "rev": "1", "severity": "3", "signature": "SURICATA TLS invalid record/traffic", "signature_id": "2230010"}, "app_proto": "tls", "dest_ip": "10.237.2.255", "dest_port": "443", "event_type": "alert", "flow": {"bytes_toclient": "562", "bytes_toserver": "1918", "pkts_toclient": "4", "pkts_toserver": "6", "start": "2022-02-07T12:14:19.789848+0000"}, "flow_id": "2234227174870360.000000", "in_iface": "ens3", "metadata": {"flowints": {"tls": {"anomaly": {"count": "4"}}}}, "proto": "TCP", "src_ip": "10.237.0.166", "src_port": "46668", "timestamp": "2022-02-07T12:14:19.856065+0000", "tls": {"ja3": {"hash": "e0ff89ed9185dfb09184797a4c3f2e1c", "string": "771,4866-4867-4865-49196-49200-159-52393-52392-52394-49195-49199-158-49188-49192-107-49187-49191-103-49162-49172-57-49161-49171-51-157-156-61-60-53-47-255,0-11-10-35-22-23-49-13-43-45-51-21,29-23-30-25-24,0-1-2"}, "sni": "mail.dmz.mannsmith.harrison.com", "version": "UNDETERMINED"}, "tx_id": "0"}, "syscheck": {}}

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: This alert indicates malformed TLS traffic which can signal protocol exploitation or misconfiguration, and the lack of historical context means we cannot assume it is benign without verification.

Evidence: TLS invalid record/traffic detected from internal IP 10.237.0.166 to mail.dmz.mannsmith.harrison.com on port 443; signature is a first occurrence with no benign history.

### harrison:131469 — -

Source message: IDS event. | {"data": {"dstip": "192.168.128.1", "dstport": 53, "id": "1:2027863:4", "srcip": "192.168.131.109"}, "syscheck": {}} | 02/07/2022-14:29:07.861483  [**] [1:2027863:4] ET INFO Observed DNS Query to .biz TLD [**] [Classification: Potentially Bad Traffic] [Priority: 2] {UDP} 192.168.131.109:41512 -> 192.168.128.1:53

Decision: **escalate**, tier `llm`, source severity 4.00.

Rationale: This is the first occurrence of a high-priority security finding indicating potentially malicious DNS traffic; without historical benign baselines or environment facts to explain the anomaly, the risk of credential abuse or lateral movement via DNS tunneling requires immediate manual verification.

Evidence: DNS query from internal host 192.168.131.109 to external IP 192.168.128.1 on port 53 classified as 'Potentially Bad Traffic' by IDS rule 20101.

### harrison:136873 — -

Source message: Dovecot Authentication Success. | {"data": {}, "syscheck": {}} | Feb  7 17:19:29 smith-mail dovecot: imap-login: Login: user=<tom.hancock>, method=PLAIN, rip=172.28.192.97, lip=172.28.192.97, mpid=4994, TLS, session=<DS+WzXDXhKWsHMBh>

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: The use of the PLAIN method for email login is a significant security risk as it transmits credentials in cleartext, and no benign fact exists to justify this specific unencrypted authentication attempt.

Evidence: Successful PLAIN authentication via Dovecot (rule 9701) from IP 172.28.192.97 by user tom.hancock on host smith-mail without TLS encryption.

### harrison:139667 — -

Source message: Suricata: Alert - SURICATA TLS invalid handshake message | {"data": {"alert": {"action": "allowed", "category": "Generic Protocol Command Decode", "gid": "1", "rev": "1", "severity": "3", "signature": "SURICATA TLS invalid handshake message", "signature_id": "2230003"}, "app_proto": "tls", "dest_ip": "172.28.192.4", "dest_port": "48460", "event_type": "alert", "flow": {"bytes_toclient": "257", "bytes_toserver": "1994", "pkts_toclient": "3", "pkts_toserver": "6", "start": "2022-02-07T19:16:44.356674+0000"}, "flow_id": "561792193163586.000000", "in_iface": "ens3", "metadata": {"flowints": {"tls": {"anomaly": {"count": "2"}}}}, "proto": "TCP", "src_ip": "44.241.217.230", "src_port": "443", "timestamp": "2022-02-07T19:16:44.922949+0000", "tls": {"ja3": {"hash": "aa7744226c695c0b2e440419848cf700", "string": "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53-10,0-23-65281-10-11-35-16-5-51-43-13-45-28-21,29-23-24-25-256-257,0"}, "sni": "shavar.services.mozilla.com", "version": "UNDETERMINED"}, "tx_id": "0"}, "syscheck": {}}

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: This is the first occurrence of this signature, and while the target domain (shavar) is benign, the 'invalid handshake' anomaly combined with an external source IP requires manual verification to rule out a compromised internal host or a legitimate but misconfigured service before suppressing.

Evidence: Suricata detected an invalid TLS handshake from external IP 44.241.217.230 to internal host wazuh-client on port 48460 targeting shavar.services.mozilla.com.

### harrison:578374 — -

Source message: Dovecot Authentication Success. | {"data": {}, "syscheck": {}} | Feb  8 12:55:03 smith-mail dovecot: imap-login: Login: user=<mohammed.neal>, method=PLAIN, rip=172.28.192.97, lip=172.28.192.97, mpid=12243, TLS, session=<QHjLOYHXLKqsHMBh>

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: The use of the PLAIN method without TLS negotiation (despite TLS being listed in the session header, PLAIN is inherently unencrypted) represents a significant credential exposure risk that cannot be suppressed due to lack of benign context.

Evidence: Successful PLAIN authentication for user mohammed.neal from IP 172.28.192.97 on wazuh-client via Dovecot.

### harrison:581422 — -

Source message: Suricata: Alert - SURICATA TLS invalid handshake message | {"data": {"alert": {"action": "allowed", "category": "Generic Protocol Command Decode", "gid": "1", "rev": "1", "severity": "3", "signature": "SURICATA TLS invalid handshake message", "signature_id": "2230003"}, "app_proto": "tls", "dest_ip": "172.28.192.4", "dest_port": "33858", "event_type": "alert", "flow": {"bytes_toclient": "279", "bytes_toserver": "1149", "pkts_toclient": "4", "pkts_toserver": "9", "start": "2022-02-08T14:57:28.870255+0000"}, "flow_id": "1474958422722415.000000", "in_iface": "ens3", "metadata": {"flowints": {"tls": {"anomaly": {"count": "2"}}}}, "proto": "TCP", "src_ip": "52.46.130.91", "src_port": "443", "timestamp": "2022-02-08T14:57:29.458321+0000", "tls": {"ja3": {"hash": "cd08e31494f9531f560d64c695473da9", "string": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0"}, "sni": "s.amazon-adsystem.com", "version": "UNDETERMINED"}, "tx_id": "0"}, "syscheck": {}}

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: This is the first occurrence of a TLS invalid handshake alert; without historical baselines or benign context, the specific anomaly requires manual verification to rule out legitimate but unusual traffic versus an intrusion attempt.

Evidence: TLS handshake anomaly detected from external IP 52.46.130.91 targeting internal host wazuh-client on port 33858 with SNI amazon-adsystem.com.

### russellmitchell:512 — -

Source message: IDS event. | {"data": {"dstip": "192.168.230.4", "dstport": 40992, "id": "1:2230003:1", "srcip": "18.203.190.43"}, "syscheck": {}} | 01/21/2022-06:18:47.768903  [**] [1:2230003:1] SURICATA TLS invalid handshake message [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 18.203.190.43:443 -> 192.168.230.4:40992

Decision: **escalate**, tier `llm`, source severity 4.00.

Rationale: This is the first occurrence of a TLS handshake anomaly originating from an external source, which requires manual verification to rule out credential theft or lateral movement before suppression.

Evidence: Suricata TLS invalid handshake message detected from external IP 18.203.190.43 targeting internal host 192.168.230.4 on port 40992.

### russellmitchell:1633 — -

Source message: Dovecot Authentication Success. | {"data": {}, "syscheck": {}} | Jan 21 09:03:23 mail dovecot: imap-login: Login: user=<alyssa.hayes>, method=PLAIN, rip=172.19.130.4, lip=172.19.130.4, mpid=9657, TLS, session=<1Yog5BPWWMOsE4IE>

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: The use of the PLAIN method over unencrypted channels presents a significant risk for credential exposure, which is a critical concern regardless of the asset's low criticality or lack of prior history.

Evidence: Successful PLAIN authentication via Dovecot from IP 172.19.130.4 using user alyssa.hayes without TLS encryption.

### russellmitchell:7318 — -

Source message: Dovecot Authentication Success. | {"data": {}, "syscheck": {}} | Jan 21 17:48:04 davey-mail dovecot: imap-login: Login: user=<shane.watson>, method=PLAIN, rip=192.168.231.56, lip=192.168.231.56, mpid=11264, TLS, session=<+62EOBvW1unAqOc4>

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: The use of the PLAIN method for email login is inherently insecure due to lack of encryption, and since this is a first occurrence with no benign history or environment facts to explain it, immediate verification is required to rule out credential compromise.

Evidence: Successful PLAIN authentication via Dovecot from IP 192.168.231.56 by user shane.watson without TLS encryption.

### russellmitchell:11680 — -

Source message: Suricata: Alert - SURICATA TLS invalid handshake message | {"data": {"alert": {"action": "allowed", "category": "Generic Protocol Command Decode", "gid": "1", "rev": "1", "severity": "3", "signature": "SURICATA TLS invalid handshake message", "signature_id": "2230003"}, "app_proto": "tls", "dest_ip": "192.168.230.4", "dest_port": "56184", "event_type": "alert", "flow": {"bytes_toclient": "206", "bytes_toserver": "1665", "pkts_toclient": "3", "pkts_toserver": "9", "start": "2022-01-22T11:00:39.825014+0000"}, "flow_id": "216633383032502.000000", "in_iface": "ens3", "metadata": {"flowints": {"tls": {"anomaly": {"count": "2"}}}}, "proto": "TCP", "src_ip": "52.208.33.102", "src_port": "443", "timestamp": "2022-01-22T11:00:39.955595+0000", "tls": {"ja3": {"hash": "a75de44db3e351bbd8d38b64c41f444e", "string": "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53-10,0-23-65281-10-11-16-5-51-43-13-28-21,29-23-24-25-256-257,0"}, "sni": "tmg.demdex.net", "version": "UNDETERMINED"}, "tx_id": "0"}, "syscheck": {}}

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: This is the first occurrence of a TLS invalid handshake alert; without historical baselines or benign context, the risk of an active intrusion attempt cannot be ruled out.

Evidence: TLS handshake anomaly detected from external IP 52.208.33.102 to internal host wazuh-client targeting port 56184 with SNI tmg.demdex.net.

### russellmitchell:13568 — -

Source message: Dovecot Authentication Success. | {"data": {}, "syscheck": {}} | Jan 22 14:10:43 morris-mail dovecot: imap-login: Login: user=<matthew.begum>, method=PLAIN, rip=192.168.231.164, lip=192.168.231.164, mpid=13924, TLS, session=<EqQPTSzWYNfAqOek>

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: The use of the PLAIN method for email login is inherently insecure as it transmits credentials in cleartext, and this represents a new signature occurrence requiring verification of whether this specific user and IP are authorized to access mail services.

Evidence: Successful PLAIN authentication via Dovecot from IP 192.168.231.164 by user matthew.begum without TLS encryption.

### russellmitchell:14669 — -

Source message: IDS event. | {"data": {"dstip": "23.185.0.253", "dstport": 443, "id": "1:2230003:1", "srcip": "192.168.230.4"}, "syscheck": {}} | 01/22/2022-15:58:35.340455  [**] [1:2230003:1] SURICATA TLS invalid handshake message [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 192.168.230.4:49394 -> 23.185.0.253:443

Decision: **escalate**, tier `llm`, source severity 4.00.

Rationale: This is the first occurrence of a TLS handshake anomaly originating from an internal host, which raises immediate concern for potential credential theft or lateral movement attempts despite the lack of historical context.

Evidence: Suricata TLS invalid handshake message detected from internal IP 192.168.230.4 to external IP 23.185.0.253 on port 443.

### russellmitchell:15795 — -

Source message: Suricata: Alert - SURICATA TLS invalid record/traffic | {"data": {"alert": {"action": "allowed", "category": "Generic Protocol Command Decode", "gid": "1", "rev": "1", "severity": "3", "signature": "SURICATA TLS invalid record/traffic", "signature_id": "2230010"}, "app_proto": "tls", "dest_ip": "172.19.130.68", "dest_port": "47798", "event_type": "alert", "flow": {"bytes_toclient": "496", "bytes_toserver": "981", "pkts_toclient": "3", "pkts_toserver": "5", "start": "2022-01-23T05:51:01.939942+0000"}, "flow_id": "2126377856096166.000000", "in_iface": "ens3", "metadata": {"flowints": {"tls": {"anomaly": {"count": "2"}}}}, "proto": "TCP", "src_ip": "172.19.130.4", "src_port": "443", "timestamp": "2022-01-23T05:51:01.965612+0000", "tls": {"ja3": {"hash": "e0ff89ed9185dfb09184797a4c3f2e1c", "string": "771,4866-4867-4865-49196-49200-159-52393-52392-52394-49195-49199-158-49188-49192-107-49187-49191-103-49162-49172-57-49161-49171-51-157-156-61-60-53-47-255,0-11-10-35-22-23-49-13-43-45-51-21,29-23-30-25-24,0-1-2"}, "sni": "mail.dmz.smith.russellmitchell.com", "version": "UNDETERMINED"}, "tx_id": "0"}, "syscheck": {}}

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: This is the first occurrence of this signature, and while the specific TLS fingerprint matches a known benign service, the 'invalid record' anomaly indicates protocol corruption or tampering that cannot be assumed safe without verifying the source IP's legitimacy and the actual traffic payload.

Evidence: TLS invalid record/traffic detected from external IP 172.19.130.4 to internal host wazuh-client on port 47798 with a JA3 hash matching the SNI mail.dmz.smith.russellmitchell.com.

### russellmitchell:17177 — -

Source message: Dovecot Authentication Success. | {"data": {}, "syscheck": {}} | Jan 23 08:03:21 davey-mail dovecot: imap-login: Login: user=<andrea.moss>, method=PLAIN, rip=192.168.231.56, lip=192.168.231.56, mpid=24748, TLS, session=<Pf4dSTvWVoLAqOc4>

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: The event records a successful login using the insecure PLAIN method, which contradicts standard secure practices and indicates potential credential abuse or lateral movement preparation.

Evidence: Successful PLAIN authentication via Dovecot from external IP 192.168.231.56 using user 'andrea.moss' without TLS negotiation (despite session flag), which is a known vector for credential theft.

### russellmitchell:18465 — -

Source message: Suricata: Alert - SURICATA TLS invalid record/traffic | {"data": {"alert": {"action": "allowed", "category": "Generic Protocol Command Decode", "gid": "1", "rev": "1", "severity": "3", "signature": "SURICATA TLS invalid record/traffic", "signature_id": "2230010"}, "app_proto": "tls", "dest_ip": "192.168.230.4", "dest_port": "58114", "event_type": "alert", "flow": {"bytes_toclient": "191", "bytes_toserver": "1237", "pkts_toclient": "2", "pkts_toserver": "6", "start": "2022-01-23T10:12:33.268960+0000"}, "flow_id": "1713647559711392.000000", "in_iface": "ens3", "metadata": {"flowints": {"tls": {"anomaly": {"count": "2"}}}}, "proto": "TCP", "src_ip": "217.74.70.57", "src_port": "443", "timestamp": "2022-01-23T10:12:33.418025+0000", "tls": {"ja3": {"hash": "aa7744226c695c0b2e440419848cf700", "string": "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53-10,0-23-65281-10-11-35-16-5-51-43-13-45-28-21,29-23-24-25-256-257,0"}, "sni": "ia.hit.interia.pl", "version": "UNDETERMINED"}, "tx_id": "0"}, "syscheck": {}}

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: The alert indicates malformed TLS traffic originating from an external source targeting a critical asset, which represents a potential protocol-level attack or data exfiltration attempt that requires immediate verification.

Evidence: Suricata detected TLS invalid record/traffic from external IP 217.74.70.57 to internal host wazuh-client on port 58114; this is the first occurrence of this signature.

### russellmitchell:20074 — -

Source message: Dovecot Authentication Success. | {"data": {}, "syscheck": {}} | Jan 23 12:29:59 mail dovecot: imap-login: Login: user=<dorothy.ellis>, method=PLAIN, rip=172.19.130.4, lip=172.19.130.4, mpid=30965, TLS, session=<TdytAj/WDtesE4IE>

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: The use of the PLAIN method over an unencrypted connection represents a significant credential exposure risk that cannot be justified by benign facts or signature history, as it violates standard security baselines for email services.

Evidence: Successful PLAIN authentication via Dovecot from IP 172.19.130.4 using user 'dorothy.ellis' without TLS encryption.

### russellmitchell:20891 — -

Source message: Dovecot Authentication Success. | {"data": {}, "syscheck": {}} | Jan 23 13:15:56 mail dovecot: imap-login: Login: user=<traci.stevenson>, method=PLAIN, rip=172.19.130.4, lip=172.19.130.4, mpid=31502, TLS, session=<dOn4pj/WINisE4IE>

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: The use of the PLAIN method over an unencrypted channel presents a significant risk of credential theft, and this behavior cannot be justified by benign facts as none exist in the environment.

Evidence: Successful PLAIN authentication via Dovecot from IP 172.19.130.4 using user traci.stevenson without TLS encryption (despite session flag indicating TLS negotiation attempt), which is a known vector for credential interception.

### russellmitchell:21431 — -

Source message: Dovecot Authentication Success. | {"data": {}, "syscheck": {}} | Jan 23 14:17:38 davey-mail dovecot: imap-login: Login: user=<shane.watson>, method=PLAIN, rip=192.168.231.56, lip=192.168.231.56, mpid=27445, TLS, session=<ARmtg0DWnITAqOc4>

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: This is the first occurrence of this signature and no benign environment facts exist to explain why a non-TLS login should be permitted; PLAIN authentication transmits credentials in clear text, which is a significant security risk regardless of internal IP context.

Evidence: Successful PLAIN authentication via Dovecot from IP 192.168.231.56 using user 'shane.watson' without TLS encryption.

### russellmitchell:25125 — -

Source message: Suricata: Alert - SURICATA TLS invalid record/traffic | {"data": {"alert": {"action": "allowed", "category": "Generic Protocol Command Decode", "gid": "1", "rev": "1", "severity": "3", "signature": "SURICATA TLS invalid record/traffic", "signature_id": "2230010"}, "app_proto": "tls", "dest_ip": "192.168.230.4", "dest_port": "44204", "event_type": "alert", "flow": {"bytes_toclient": "206", "bytes_toserver": "1592", "pkts_toclient": "3", "pkts_toserver": "7", "start": "2022-01-23T19:54:08.080135+0000"}, "flow_id": "850823129086215.000000", "in_iface": "ens3", "metadata": {"flowints": {"tls": {"anomaly": {"count": "2"}}}}, "proto": "TCP", "src_ip": "52.215.125.248", "src_port": "443", "timestamp": "2022-01-23T19:54:08.202446+0000", "tls": {"ja3": {"hash": "cd08e31494f9531f560d64c695473da9", "string": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0"}, "sni": "trends.revcontent.com", "version": "UNDETERMINED"}, "tx_id": "0"}, "syscheck": {}}

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: TLS protocol anomalies originating from an external source to a critical asset represent a potential intrusion attempt that cannot be dismissed without verification, especially given the lack of benign context or historical patterns for this specific event.

Evidence: Suricata detected TLS invalid record/traffic from external IP 52.215.125.248 to internal host wazuh-client on port 44204; this is the first occurrence of this signature.

### russellmitchell:34194 — -

Source message: Dovecot Authentication Success. | {"data": {}, "syscheck": {}} | Jan 24 08:47:36 davey-mail dovecot: imap-login: Login: user=<shane.watson>, method=PLAIN, rip=192.168.231.56, lip=192.168.231.56, mpid=1007, TLS, session=<xUQrBVDWzIbAqOc4>

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: The use of the PLAIN method without TLS is a significant security risk as credentials are transmitted in clear text, and this represents an unverified anomaly requiring immediate investigation to rule out credential theft or unauthorized access.

Evidence: Successful PLAIN authentication via Dovecot from IP 192.168.231.56 using user shane.watson without TLS encryption.

### russellmitchell:36307 — -

Source message: IDS event. | {"data": {"dstip": "172.19.131.174", "dstport": 60390, "id": "1:2230003:1", "srcip": "81.3.192.66"}, "syscheck": {}} | 01/24/2022-10:38:41.989378  [**] [1:2230003:1] SURICATA TLS invalid handshake message [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 81.3.192.66:443 -> 172.19.131.174:60390

Decision: **escalate**, tier `llm`, source severity 4.00.

Rationale: This is the first occurrence of a TLS handshake anomaly targeting an internal asset; without benign context or known baselines, the risk of credential theft or lateral movement requires immediate manual verification rather than suppression.

Evidence: Suricata TLS invalid handshake message detected from external IP 81.3.192.66 to internal host wazuh-client on port 60390.

### russellmitchell:36744 — -

Source message: IDS event. | {"data": {"dstip": "51.104.158.213", "dstport": 443, "id": "1:2230003:1", "srcip": "172.19.131.174"}, "syscheck": {}} | 01/24/2022-10:38:48.827260  [**] [1:2230003:1] SURICATA TLS invalid handshake message [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 172.19.131.174:59828 -> 51.104.158.213:443

Decision: **escalate**, tier `llm`, source severity 4.00.

Rationale: This is the first occurrence of a TLS handshake anomaly, and while no benign fact covers this specific protocol error, the combination of an internal source initiating a malformed TLS connection to an external destination warrants investigation to rule out credential theft or lateral movement.

Evidence: Suricata TLS invalid handshake message detected from internal IP 172.19.131.174 to external IP 51.104.158.213 on port 443.

### santos:2284 — -

Source message: IDS event. | {"data": {"dstip": "192.168.104.1", "dstport": 53, "id": "1:2027863:4", "srcip": "192.168.104.218"}, "syscheck": {}} | 01/14/2022-02:21:02.219571  [**] [1:2027863:4] ET INFO Observed DNS Query to .biz TLD [**] [Classification: Potentially Bad Traffic] [Priority: 2] {UDP} 192.168.104.218:35273 -> 192.168.104.1:53

Decision: **escalate**, tier `llm`, source severity 4.00.

Rationale: This is the first occurrence of a potentially bad traffic alert for DNS activity; without historical baselines or benign context, the specific concern of potential malicious resolution requires manual verification.

Evidence: DNS query to .biz TLD from internal host 192.168.104.218 to gateway 192.168.104.1 at 02:21:02 UTC

### santos:5935 — -

Source message: IDS event. | {"data": {"dstip": "172.21.129.224", "dstport": 38640, "id": "1:2230010:1", "srcip": "172.21.131.50"}, "syscheck": {}} | 01/14/2022-05:58:16.421821  [**] [1:2230010:1] SURICATA TLS invalid record/traffic [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 172.21.131.50:443 -> 172.21.129.224:38640

Decision: **escalate**, tier `llm`, source severity 4.00.

Rationale: This is the first occurrence of this signature, and while no specific malicious behavior is confirmed, TLS protocol anomalies can indicate compromised clients or misconfigured services that require verification before suppression.

Evidence: Suricata TLS invalid record/traffic alert on host wazuh-client involving source IP 172.21.131.50 and destination IP 172.21.129.224.

### santos:6444 — -

Source message: Dovecot Authentication Success. | {"data": {}, "syscheck": {}} | Jan 14 06:17:52 hayes-mail dovecot: imap-login: Login: user=<jamie.walsh>, method=PLAIN, rip=10.229.2.25, lip=10.229.2.25, mpid=4230, TLS, session=<sW5Fw4TVYr0K5QIZ>

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: The use of the PLAIN authentication method transmits credentials in clear text, which is a significant security risk even if the source IP appears internal; without a verified fact confirming this specific user and method are standard operational practice, the potential for credential theft or unauthorized access requires immediate review.

Evidence: Successful authentication via PLAIN method (unencrypted) from IP 10.229.2.25 for user jamie.walsh on Dovecot.

### santos:8864 — -

Source message: IDS event. | {"data": {"dstip": "10.229.255.254", "dstport": 53, "id": "1:2027863:4", "srcip": "10.229.0.4"}, "syscheck": {}} | 01/14/2022-07:35:27.464541  [**] [1:2027863:4] ET INFO Observed DNS Query to .biz TLD [**] [Classification: Potentially Bad Traffic] [Priority: 2] {UDP} 10.229.0.4:44734 -> 10.229.255.254:53

Decision: **escalate**, tier `llm`, source severity 4.00.

Rationale: This is the first occurrence of this signature, and while the .biz TLD may be benign, the 'potentially bad traffic' classification combined with missing baseline data requires verification to rule out command-and-control or data exfiltration before suppressing.

Evidence: DNS query to .biz TLD from internal host 10.229.0.4 to DNS server 10.229.255.254 flagged as potentially bad traffic by Wazuh IDS rule 20101.

### santos:9767 — -

Source message: Dovecot Authentication Success. | {"data": {}, "syscheck": {}} | Jan 14 08:02:45 hayes-mail dovecot: imap-login: Login: user=<norman.humphries>, method=PLAIN, rip=10.229.2.25, lip=10.229.2.25, mpid=5431, TLS, session=</IRcOobVIL8K5QIZ>

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: This is the first occurrence of this signature and no benign baseline exists to confirm the user or method; PLAIN authentication without TLS negotiation details in the log body raises immediate concern for credential abuse.

Evidence: Successful PLAIN authentication via Dovecot on a production mail server (hayes-mail) from an external IP (10.229.2.25) using the user 'norman.humphries'.

### santos:30128 — -

Source message: IDS event. | {"data": {"dstip": "10.229.0.4", "dstport": 58336, "id": "1:2230010:1", "srcip": "119.63.198.176"}, "syscheck": {}} | 01/14/2022-16:24:51.727125  [**] [1:2230010:1] SURICATA TLS invalid record/traffic [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 119.63.198.176:443 -> 10.229.0.4:58336

Decision: **escalate**, tier `llm`, source severity 4.00.

Rationale: This is the first occurrence of a TLS protocol anomaly detected by Suricata, and without historical baselines or benign context to explain why this specific traffic pattern is expected, it requires manual verification to rule out an active intrusion attempt.

Evidence: Suricata TLS invalid record/traffic event originating from external IP 119.63.198.176 targeting internal host 10.229.0.4 on port 58336.

### santos:31762 — -

Source message: Suricata: Alert - SURICATA TLS invalid handshake message | {"data": {"alert": {"action": "allowed", "category": "Generic Protocol Command Decode", "gid": "1", "rev": "1", "severity": "3", "signature": "SURICATA TLS invalid handshake message", "signature_id": "2230003"}, "app_proto": "tls", "dest_ip": "35.163.137.0", "dest_port": "443", "event_type": "alert", "flow": {"bytes_toclient": "257", "bytes_toserver": "1043", "pkts_toclient": "3", "pkts_toserver": "6", "start": "2022-01-14T17:38:20.008310+0000"}, "flow_id": "755109827715190.000000", "in_iface": "ens3", "metadata": {"flowints": {"tls": {"anomaly": {"count": "4"}}}}, "proto": "TCP", "src_ip": "10.229.0.4", "src_port": "57616", "timestamp": "2022-01-14T17:38:20.630820+0000", "tls": {"ja3": {"hash": "aa7744226c695c0b2e440419848cf700", "string": "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53-10,0-23-65281-10-11-35-16-5-51-43-13-45-28-21,29-23-24-25-256-257,0"}, "sni": "location.services.mozilla.com", "version": "UNDETERMINED"}, "tx_id": "0"}, "syscheck": {}}

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: This is the first occurrence of this signature, and while the destination is a known benign service (Mozilla), an invalid handshake from an internal host requires investigation to rule out compromised software or credential abuse before assuming it is a false positive.

Evidence: Suricata detected an invalid TLS handshake from internal IP 10.229.0.4 to external destination 35.163.137.0 (Mozilla services) with a JA3 hash indicating a specific client fingerprint.

### santos:43273 — -

Source message: IDS event. | {"data": {"dstip": "10.229.255.254", "dstport": 53, "id": "1:2027863:4", "srcip": "10.229.0.4"}, "syscheck": {}} | 01/15/2022-04:03:09.367480  [**] [1:2027863:4] ET INFO Observed DNS Query to .biz TLD [**] [Classification: Potentially Bad Traffic] [Priority: 2] {UDP} 10.229.0.4:27050 -> 10.229.255.254:53

Decision: **escalate**, tier `llm`, source severity 4.00.

Rationale: This is the first occurrence of a 'Potentially Bad Traffic' classification for DNS activity; without historical baselines or benign context, the specific concern that this query represents command-and-control or data exfiltration requires manual verification before suppression.

Evidence: DNS query to .biz TLD from internal host 10.229.0.4 to external resolver 10.229.255.254 on port 53.

### santos:45719 — -

Source message: Suricata: Alert - SURICATA TLS invalid record/traffic | {"data": {"alert": {"action": "allowed", "category": "Generic Protocol Command Decode", "gid": "1", "rev": "1", "severity": "3", "signature": "SURICATA TLS invalid record/traffic", "signature_id": "2230010"}, "app_proto": "tls", "dest_ip": "10.229.0.4", "dest_port": "53778", "event_type": "alert", "flow": {"bytes_toclient": "206", "bytes_toserver": "981", "pkts_toclient": "3", "pkts_toserver": "5", "start": "2022-01-15T06:16:14.673817+0000"}, "flow_id": "2165068966807577.000000", "in_iface": "ens3", "metadata": {"flowints": {"tls": {"anomaly": {"count": "2"}}}}, "proto": "TCP", "src_ip": "52.223.40.198", "src_port": "443", "timestamp": "2022-01-15T06:16:14.762252+0000", "tls": {"ja3": {"hash": "cd08e31494f9531f560d64c695473da9", "string": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0"}, "sni": "match.adsrvr.org", "version": "UNDETERMINED"}, "tx_id": "0"}, "syscheck": {}}

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: This is the first occurrence of this signature, and while the destination SNI (match.adsrvr.org) suggests a potential false positive related to ad-serving traffic, the specific behavior of 'TLS invalid record/traffic' indicates protocol corruption or tampering that cannot be explained by benign patterns alone.

Evidence: Suricata detected TLS invalid record/traffic from external IP 52.223.40.198 to internal host wazuh-client on port 53778 targeting SNI match.adsrvr.org.

### santos:49123 — -

Source message: Dovecot Authentication Success. | {"data": {}, "syscheck": {}} | Jan 15 08:02:50 rogersturnbull-mail dovecot: imap-login: Login: user=<katelyn.clayton>, method=PLAIN, rip=10.229.0.32, lip=10.229.0.32, mpid=12258, TLS, session=<b5yHWJrVoIMK5QAg>

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: The use of the PLAIN method for authentication is inherently risky as it transmits credentials in cleartext; this requires immediate verification to ensure the user is authorized and no credential theft occurred.

Evidence: Successful PLAIN authentication via Dovecot from IP 10.229.0.32 using user katelyn.clayton without TLS encryption (despite session flag indicating TLS in log, method=PLAIN indicates unencrypted transport attempt or misconfiguration).

### santos:55934 — -

Source message: Suricata: Alert - SURICATA TLS invalid handshake message | {"data": {"alert": {"action": "allowed", "category": "Generic Protocol Command Decode", "gid": "1", "rev": "1", "severity": "3", "signature": "SURICATA TLS invalid handshake message", "signature_id": "2230003"}, "app_proto": "tls", "dest_ip": "172.21.131.50", "dest_port": "443", "event_type": "alert", "flow": {"bytes_toclient": "496", "bytes_toserver": "1926", "pkts_toclient": "3", "pkts_toserver": "6", "start": "2022-01-15T10:51:40.013845+0000"}, "flow_id": "2092807225095701.000000", "in_iface": "ens3", "metadata": {"flowints": {"tls": {"anomaly": {"count": "4"}}}}, "proto": "TCP", "src_ip": "172.21.129.224", "src_port": "41418", "timestamp": "2022-01-15T10:51:40.027462+0000", "tls": {"ja3": {"hash": "e0ff89ed9185dfb09184797a4c3f2e1c", "string": "771,4866-4867-4865-49196-49200-159-52393-52392-52394-49195-49199-158-49188-49192-107-49187-49191-103-49162-49172-57-49161-49171-51-157-156-61-60-53-47-255,0-11-10-35-22-23-49-13-43-45-51-21,29-23-30-25-24,0-1-2"}, "sni": "mail.dmz.smith.santos.com", "version": "UNDETERMINED"}, "tx_id": "0"}, "syscheck": {}}

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: This is the first occurrence of a TLS handshake anomaly involving an internal host communicating with an external IP; without benign context or known baselines, the risk of credential theft or lateral movement cannot be ruled out.

Evidence: TLS invalid handshake detected between internal IP 172.21.129.224 and external destination 172.21.131.50 on port 443 with an unknown SNI (mail.dmz.smith.santos.com).

### santos:73474 — -

Source message: Dovecot Authentication Success. | {"data": {}, "syscheck": {}} | Jan 15 18:25:12 mail dovecot: imap-login: Login: user=<carol.mckenzie>, method=PLAIN, rip=172.21.131.50, lip=172.21.131.50, mpid=31951, TLS, session=<OldJCqPV8pusFYMy>

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: The use of the PLAIN authentication method over unencrypted transport is a significant security risk as it exposes credentials in transit, and this behavior contradicts standard secure email practices regardless of benign history.

Evidence: Dovecot authentication using PLAIN method without TLS encryption from an external IP (172.21.131.50) to a mail server.

### santos:93810 — -

Source message: IDS event. | {"data": {"dstip": "185.54.150.79", "dstport": 443, "id": "1:2230003:1", "srcip": "10.229.0.4"}, "syscheck": {}} | 01/16/2022-10:57:36.007580  [**] [1:2230003:1] SURICATA TLS invalid handshake message [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 10.229.0.4:35232 -> 185.54.150.79:443

Decision: **escalate**, tier `llm`, source severity 4.00.

Rationale: This is the first occurrence of a TLS handshake anomaly originating from an internal asset, which could indicate compromised software attempting malicious communication or a misconfigured service; without benign context, this requires investigation to rule out intrusion.

Evidence: Suricata TLS invalid handshake message detected from internal host 10.229.0.4 to external IP 185.54.150.79 on port 443.

### santos:96335 — -

Source message: Dovecot Authentication Success. | {"data": {}, "syscheck": {}} | Jan 16 12:32:03 mail dovecot: imap-login: Login: user=<amanda.watson>, method=PLAIN, rip=172.21.131.50, lip=172.21.131.50, mpid=9001, TLS, session=<V7IiObLVFqqsFYMy>

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: The use of the PLAIN authentication method without TLS is a significant security risk as credentials are transmitted in clear text, and this represents an unverified anomaly for this environment.

Evidence: Successful Dovecot login via PLAIN method without TLS encryption from IP 172.21.131.50 by user amanda.watson.

### santos:119933 — -

Source message: IDS event. | {"data": {"dstip": "10.229.0.4", "dstport": 52496, "id": "1:2230003:1", "srcip": "151.101.194.49"}, "syscheck": {}} | 01/17/2022-13:48:53.930395  [**] [1:2230003:1] SURICATA TLS invalid handshake message [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 151.101.194.49:443 -> 10.229.0.4:52496

Decision: **escalate**, tier `llm`, source severity 4.00.

Rationale: This is the first occurrence of a TLS handshake anomaly targeting an internal asset; without historical benign context or known safe patterns, the risk of credential theft or protocol exploitation cannot be dismissed.

Evidence: Suricata TLS invalid handshake message detected from external IP 151.101.194.49 to internal host 10.229.0.4 on port 443.

### shaw:1015 — -

Source message: Dovecot Authentication Success. | {"data": {}, "syscheck": {}} | Jan 25 08:27:03 mail dovecot: imap-login: Login: user=<howard.palmer>, method=PLAIN, rip=172.24.251.90, lip=172.24.251.90, mpid=8463, TLS, session=<SUqT2WPWUMesGPta>

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: The use of the PLAIN authentication method without TLS negotiation in the log message indicates an unencrypted credential transmission, which is a significant security risk regardless of the user's legitimacy or the lack of historical data.

Evidence: Successful authentication via PLAIN method (unencrypted) for user 'howard.palmer' from IP 172.24.251.90 on a mail server.

### shaw:11613 — -

Source message: IDS event. | {"data": {"dstip": "172.24.249.224", "dstport": 55254, "id": "1:2230010:1", "srcip": "52.223.40.198"}, "syscheck": {}} | 01/26/2022-09:48:26.045157  [**] [1:2230010:1] SURICATA TLS invalid record/traffic [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 52.223.40.198:443 -> 172.24.249.224:55254

Decision: **escalate**, tier `llm`, source severity 4.00.

Rationale: This is the first occurrence of a TLS protocol anomaly targeting an internal asset; without historical benign context or environment facts explaining this traffic, the risk of credential abuse or lateral movement cannot be ruled out.

Evidence: Suricata TLS invalid record/traffic detected from external IP 52.223.40.198 to internal host wazuh-client on port 55254.

### shaw:12136 — -

Source message: IDS event. | {"data": {"dstip": "10.70.32.4", "dstport": 54644, "id": "1:2230010:1", "srcip": "50.17.91.214"}, "syscheck": {}} | 01/26/2022-10:16:23.464777  [**] [1:2230010:1] SURICATA TLS invalid record/traffic [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 50.17.91.214:443 -> 10.70.32.4:54644

Decision: **escalate**, tier `llm`, source severity 4.00.

Rationale: This is the first occurrence of a TLS protocol anomaly targeting an internal asset; without historical benign context or known legitimate traffic patterns, the risk of a man-in-the-middle attack or protocol exploitation cannot be ruled out.

Evidence: Suricata TLS invalid record/traffic detected from external IP 50.17.91.214 to internal host 10.70.32.4 on port 54644.

### shaw:12431 — -

Source message: Dovecot Authentication Success. | {"data": {}, "syscheck": {}} | Jan 26 10:33:34 collinsbecker-mail dovecot: imap-login: Login: user=<jamie.fuller>, method=PLAIN, rip=10.70.34.215, lip=10.70.34.215, mpid=16046, TLS, session=<K6nWu3nW3OMKRiLX>

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: The use of the PLAIN method over an unencrypted channel represents a significant security risk as credentials are transmitted in cleartext, and this is the first occurrence of this signature requiring immediate verification of user intent and network configuration.

Evidence: Successful PLAIN authentication via Dovecot from IP 10.70.34.215 using user 'jamie.fuller' without TLS encryption (despite TLS flag in session), which is a known vector for credential interception.

### shaw:22604 — -

Source message: Suricata: Alert - SURICATA TLS invalid handshake message | {"data": {"alert": {"action": "allowed", "category": "Generic Protocol Command Decode", "gid": "1", "rev": "1", "severity": "3", "signature": "SURICATA TLS invalid handshake message", "signature_id": "2230003"}, "app_proto": "tls", "dest_ip": "172.24.249.224", "dest_port": "43316", "event_type": "alert", "flow": {"bytes_toclient": "202", "bytes_toserver": "1633", "pkts_toclient": "3", "pkts_toserver": "8", "start": "2022-01-27T12:12:49.791056+0000"}, "flow_id": "2037062391894544.000000", "in_iface": "ens3", "metadata": {"flowints": {"tls": {"anomaly": {"count": "2"}}}}, "proto": "TCP", "src_ip": "137.254.60.12", "src_port": "443", "timestamp": "2022-01-27T12:12:50.281603+0000", "tls": {"ja3": {"hash": "aa7744226c695c0b2e440419848cf700", "string": "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53-10,0-23-65281-10-11-35-16-5-51-43-13-45-28-21,29-23-24-25-256-257,0"}, "sni": "labs.mysql.com", "version": "UNDETERMINED"}, "tx_id": "0"}, "syscheck": {}}

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: This is the first occurrence of a TLS invalid handshake signature; without historical benign context or environment facts explaining this specific traffic, the risk of credential theft or lateral movement cannot be ruled out.

Evidence: TLS handshake anomaly detected from external IP 137.254.60.12 to internal host wazuh-client targeting port 43316 with SNI labs.mysql.com.

### shaw:39275 — -

Source message: Suricata: Alert - SURICATA TLS invalid handshake message | {"data": {"alert": {"action": "allowed", "category": "Generic Protocol Command Decode", "gid": "1", "rev": "1", "severity": "3", "signature": "SURICATA TLS invalid handshake message", "signature_id": "2230003"}, "app_proto": "tls", "dest_ip": "10.70.32.4", "dest_port": "34328", "event_type": "alert", "flow": {"bytes_toclient": "257", "bytes_toserver": "2651", "pkts_toclient": "3", "pkts_toserver": "11", "start": "2022-01-29T08:33:43.542607+0000"}, "flow_id": "430849575569295.000000", "in_iface": "ens3", "metadata": {"flowints": {"tls": {"anomaly": {"count": "2"}}}}, "proto": "TCP", "src_ip": "52.59.74.147", "src_port": "443", "timestamp": "2022-01-29T08:33:43.604158+0000", "tls": {"ja3": {"hash": "aa7744226c695c0b2e440419848cf700", "string": "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53-10,0-23-65281-10-11-35-16-5-51-43-13-45-28-21,29-23-24-25-256-257,0"}, "sni": "sp.nba.com", "version": "UNDETERMINED"}, "tx_id": "0"}, "syscheck": {}}

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: This is the first occurrence of a TLS invalid handshake signature; while the destination domain (sp.nba.com) appears benign, the specific protocol anomaly and external source require verification before assuming it is a false positive or benign traffic.

Evidence: TLS handshake anomaly detected from external IP 52.59.74.147 to internal host wazuh-client targeting port 34328 with SNI sp.nba.com.

### shaw:39520 — -

Source message: Dovecot Authentication Success. | {"data": {}, "syscheck": {}} | Jan 29 08:51:53 collinsbecker-mail dovecot: imap-login: Login: user=<jamie.fuller>, method=PLAIN, rip=10.70.34.215, lip=10.70.34.215, mpid=12901, TLS, session=<8LS2qbTWqo0KRiLX>

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: The use of the PLAIN authentication method indicates unencrypted credentials were transmitted, which is a significant security risk regardless of the benign signature history or lack of environment facts.

Evidence: Successful PLAIN authentication via Dovecot from IP 10.70.34.215 using user jamie.fuller without TLS encryption (despite 'TLS' appearing in the log line, PLAIN method inherently lacks encryption).

### shaw:42425 — -

Source message: Suricata: Alert - SURICATA TLS invalid handshake message | {"data": {"alert": {"action": "allowed", "category": "Generic Protocol Command Decode", "gid": "1", "rev": "1", "severity": "3", "signature": "SURICATA TLS invalid handshake message", "signature_id": "2230003"}, "app_proto": "tls", "dest_ip": "10.70.32.4", "dest_port": "58272", "event_type": "alert", "flow": {"bytes_toclient": "448", "bytes_toserver": "1043", "pkts_toclient": "3", "pkts_toserver": "6", "start": "2022-01-29T12:28:43.428301+0000"}, "flow_id": "1915345815963917.000000", "in_iface": "ens3", "metadata": {"flowints": {"tls": {"anomaly": {"count": "2"}}}}, "proto": "TCP", "src_ip": "85.14.248.71", "src_port": "443", "timestamp": "2022-01-29T12:28:43.530450+0000", "tls": {"ja3": {"hash": "aa7744226c695c0b2e440419848cf700", "string": "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53-10,0-23-65281-10-11-35-16-5-51-43-13-45-28-21,29-23-24-25-256-257,0"}, "sni": "m.exactag.com", "version": "UNDETERMINED"}, "tx_id": "0"}, "syscheck": {}}

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: The alert indicates a malformed TLS handshake originating from an external IP, which represents a potential intrusion attempt or reconnaissance that cannot be explained by benign environment facts and requires immediate verification to rule out compromise.

Evidence: Suricata detected an invalid TLS handshake from external IP 85.14.248.71 targeting internal host wazuh-client on port 58272; this is the first occurrence of this signature.

### shaw:56672 — -

Source message: Dovecot Authentication Success. | {"data": {}, "syscheck": {}} | Jan 30 08:34:16 collinsbecker-mail dovecot: imap-login: Login: user=<diana.delgado>, method=PLAIN, rip=10.70.34.215, lip=10.70.34.215, mpid=22689, TLS, session=<fhCOiMjWIpUKRiLX>

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: The use of the PLAIN method over an unencrypted connection represents a significant credential exposure risk, as it transmits credentials in cleartext; this is a confirmed security violation regardless of the asset's criticality or lack of prior history.

Evidence: Successful PLAIN authentication via Dovecot from IP 10.70.34.215 using user diana.delgado without TLS encryption.

### shaw:58687 — -

Source message: IDS event. | {"data": {"dstip": "172.24.249.224", "dstport": 52040, "id": "1:2230003:1", "srcip": "217.74.74.28"}, "syscheck": {}} | 01/30/2022-09:13:04.795204  [**] [1:2230003:1] SURICATA TLS invalid handshake message [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 217.74.74.28:443 -> 172.24.249.224:52040

Decision: **escalate**, tier `llm`, source severity 4.00.

Rationale: This is the first occurrence of a TLS handshake anomaly targeting an internal asset; without benign context or known baseline, the risk of credential theft or lateral movement requires immediate manual verification rather than suppression.

Evidence: Suricata TLS invalid handshake message detected from external IP 217.74.74.28 to internal host wazuh-client on port 52040.

### shaw:61446 — -

Source message: Suricata: Alert - SURICATA TLS invalid record/traffic | {"data": {"alert": {"action": "allowed", "category": "Generic Protocol Command Decode", "gid": "1", "rev": "1", "severity": "3", "signature": "SURICATA TLS invalid record/traffic", "signature_id": "2230010"}, "app_proto": "tls", "dest_ip": "10.70.32.4", "dest_port": "56922", "event_type": "alert", "flow": {"bytes_toclient": "206", "bytes_toserver": "1877", "pkts_toclient": "3", "pkts_toserver": "9", "start": "2022-01-30T10:25:36.539499+0000"}, "flow_id": "381414161791851.000000", "in_iface": "ens3", "metadata": {"flowints": {"tls": {"anomaly": {"count": "2"}}}}, "proto": "TCP", "src_ip": "34.240.117.166", "src_port": "443", "timestamp": "2022-01-30T10:25:36.683117+0000", "tls": {"ja3": {"hash": "aa7744226c695c0b2e440419848cf700", "string": "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53-10,0-23-65281-10-11-35-16-5-51-43-13-45-28-21,29-23-24-25-256-257,0"}, "sni": "consent.yahoo.com", "version": "UNDETERMINED"}, "tx_id": "0"}, "syscheck": {}}

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: This is a precautionary review of TLS protocol anomalies; while the signature has no prior history and the destination IP appears external, the specific behavior of invalid TLS records requires independent verification to rule out compromised clients or misconfigured services before suppressing.

Evidence: TLS traffic from external IP 34.240.117.166 to internal host wazuh-client on port 56922 targeting SNI 'consent.yahoo.com' with invalid record anomalies.

### shaw:62804 — -

Source message: Suricata: Alert - SURICATA TLS invalid record/traffic | {"data": {"alert": {"action": "allowed", "category": "Generic Protocol Command Decode", "gid": "1", "rev": "1", "severity": "3", "signature": "SURICATA TLS invalid record/traffic", "signature_id": "2230010"}, "app_proto": "tls", "dest_ip": "151.101.194.217", "dest_port": "443", "event_type": "alert", "flow": {"bytes_toclient": "546", "bytes_toserver": "1385", "pkts_toclient": "4", "pkts_toserver": "9", "start": "2022-01-30T11:52:52.761663+0000"}, "flow_id": "700670161493823.000000", "in_iface": "ens3", "metadata": {"flowints": {"tls": {"anomaly": {"count": "4"}}}}, "proto": "TCP", "src_ip": "10.70.32.4", "src_port": "55018", "timestamp": "2022-01-30T11:52:52.788471+0000", "tls": {"ja3": {"hash": "aa7744226c695c0b2e440419848cf700", "string": "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53-10,0-23-65281-10-11-35-16-5-51-43-13-45-28-21,29-23-24-25-256-257,0"}, "sni": "scripts.webcontentassessor.com", "version": "UNDETERMINED"}, "tx_id": "0"}, "syscheck": {}}

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: This is the first occurrence of this signature, and while the destination appears benign, TLS protocol anomalies can indicate compromised clients or malicious traffic; without historical baselines or environment facts to confirm normal behavior for this specific host/user combination, the risk of a real intrusion outweighs the cost of escalation.

Evidence: TLS invalid record/traffic detected from internal IP 10.70.32.4 to external host 151.101.194.217 (scripts.webcontentassessor.com) with a high anomaly count of 4.

### shaw:65752 — -

Source message: IDS event. | {"data": {"dstip": "10.70.32.4", "dstport": 59244, "id": "1:2230010:1", "srcip": "3.130.254.245"}, "syscheck": {}} | 01/30/2022-15:33:44.698017  [**] [1:2230010:1] SURICATA TLS invalid record/traffic [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 3.130.254.245:443 -> 10.70.32.4:59244

Decision: **escalate**, tier `llm`, source severity 4.00.

Rationale: TLS protocol anomalies originating from an external source targeting an internal asset represent a potential intrusion attempt that requires immediate verification, as no benign context or baseline exists to explain this traffic.

Evidence: Suricata TLS invalid record/traffic detected from external IP 3.130.254.245 to internal host 10.70.32.4 on port 59244; this is the first occurrence of this signature.

### shaw:65969 — -

Source message: IDS event. | {"data": {"dstip": "10.70.32.4", "dstport": 33146, "id": "1:2230010:1", "srcip": "94.245.192.10"}, "syscheck": {}} | 01/30/2022-15:40:36.821611  [**] [1:2230010:1] SURICATA TLS invalid record/traffic [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 94.245.192.10:443 -> 10.70.32.4:33146

Decision: **escalate**, tier `llm`, source severity 4.00.

Rationale: This is the first occurrence of this signature and no benign environment facts exist to explain why an external entity is sending malformed TLS traffic to a specific internal host; missing baseline makes this precautionary review insufficient to suppress.

Evidence: Suricata TLS invalid record/traffic detected from external IP 94.245.192.10 to internal host 10.70.32.4 on port 33146.

### wardbeck:9386 — -

Source message: Suricata: Alert - SURICATA TLS invalid record/traffic | {"data": {"alert": {"action": "allowed", "category": "Generic Protocol Command Decode", "gid": "1", "rev": "1", "severity": "3", "signature": "SURICATA TLS invalid record/traffic", "signature_id": "2230010"}, "app_proto": "tls", "dest_ip": "217.74.71.132", "dest_port": "443", "event_type": "alert", "flow": {"bytes_toclient": "2415", "bytes_toserver": "2578", "pkts_toclient": "10", "pkts_toserver": "16", "start": "2022-01-19T12:32:29.228075+0000"}, "flow_id": "1074734043069163.000000", "in_iface": "ens3", "metadata": {"flowints": {"tls": {"anomaly": {"count": "4"}}}}, "proto": "TCP", "src_ip": "10.132.56.81", "src_port": "56376", "timestamp": "2022-01-19T12:32:29.369508+0000", "tls": {"ja3": {"hash": "cd08e31494f9531f560d64c695473da9", "string": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0"}, "sni": "iwa.iplsc.com", "version": "UNDETERMINED"}, "tx_id": "0"}, "syscheck": {}}

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: TLS protocol errors indicate potential cryptographic failures or malformed traffic that could signal compromise, and without a benign baseline for this specific host or time, the risk of an intrusion must be treated seriously.

Evidence: Suricata detected TLS invalid record/traffic from internal IP 10.132.56.81 to external destination 217.74.71.132 on port 443; this is the first occurrence of this signature.

### wardbeck:24711 — -

Source message: IDS event. | {"data": {"dstip": "185.64.189.226", "dstport": 443, "id": "1:2230003:1", "srcip": "192.168.96.4"}, "syscheck": {}} | 01/20/2022-12:18:29.593214  [**] [1:2230003:1] SURICATA TLS invalid handshake message [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 192.168.96.4:40036 -> 185.64.189.226:443

Decision: **escalate**, tier `llm`, source severity 4.00.

Rationale: This is the first occurrence of a TLS handshake failure, which indicates an active network anomaly that could represent credential theft or lateral movement; without a verified benign fact covering this specific host/user/action combination, the risk of missing a real intrusion outweighs the cost of escalation.

Evidence: Suricata TLS invalid handshake message detected from internal IP 192.168.96.4 to external IP 185.64.189.226 on port 443.

### wardbeck:25772 — -

Source message: Dovecot Authentication Success. | {"data": {}, "syscheck": {}} | Jan 20 12:59:45 watkins-mail dovecot: imap-login: Login: user=<jean.hughes>, method=PLAIN, rip=192.168.96.99, lip=192.168.96.99, mpid=15339, TLS, session=<waCSEwPW7urAqGBj>

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: The use of the PLAIN authentication method indicates unencrypted credentials were transmitted, which is a significant security risk regardless of the asset's criticality or lack of prior history.

Evidence: Successful PLAIN authentication via Dovecot from external IP 192.168.96.99 using user jean.hughes without TLS negotiation (despite 'TLS' appearing in the log line, PLAIN method implies no encryption).

### wardbeck:29028 — -

Source message: Dovecot Authentication Success. | {"data": {}, "syscheck": {}} | Jan 20 15:51:22 walker-mail dovecot: imap-login: Login: user=<john.sanders>, method=PLAIN, rip=192.168.99.0, lip=192.168.99.0, mpid=18318, TLS, session=<I6xSeQXW1NrAqGMA>

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: The use of the PLAIN authentication method indicates unencrypted credentials were transmitted, which is a significant security risk regardless of the internal network context or lack of prior history.

Evidence: Dovecot authentication using PLAIN method without TLS negotiation (despite 'TLS' appearing in the log line, PLAIN implies no encryption) from an internal IP range.

### wardbeck:29406 — -

Source message: IDS event. | {"data": {"dstip": "192.168.96.4", "dstport": 55352, "id": "1:2230010:1", "srcip": "40.77.226.250"}, "syscheck": {}} | 01/20/2022-16:07:21.254158  [**] [1:2230010:1] SURICATA TLS invalid record/traffic [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 40.77.226.250:443 -> 192.168.96.4:55352

Decision: **escalate**, tier `llm`, source severity 4.00.

Rationale: This is the first occurrence of a generic protocol decode anomaly involving an external source targeting an internal host; without historical benign context or specific benign facts, the risk of credential abuse or lateral movement cannot be ruled out.

Evidence: Suricata TLS invalid record/traffic detected from external IP 40.77.226.250 to internal host wazuh-client on port 55352.

### wardbeck:33363 — -

Source message: IDS event. | {"data": {"dstip": "193.251.215.153", "dstport": 443, "id": "1:2230003:1", "srcip": "192.168.96.4"}, "syscheck": {}} | 01/21/2022-05:57:46.235125  [**] [1:2230003:1] SURICATA TLS invalid handshake message [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 192.168.96.4:40800 -> 193.251.215.153:443

Decision: **escalate**, tier `llm`, source severity 4.00.

Rationale: This is the first occurrence of a TLS handshake anomaly targeting an external destination, which requires manual verification to distinguish between a legitimate application error and potential credential theft or lateral movement.

Evidence: Suricata TLS invalid handshake message detected from internal IP 192.168.96.4 to external IP 193.251.215.153 on port 443.

### wardbeck:50350 — -

Source message: Dovecot Authentication Success. | {"data": {}, "syscheck": {}} | Jan 21 15:59:52 watkins-mail dovecot: imap-login: Login: user=<emily.frost>, method=PLAIN, rip=192.168.96.99, lip=192.168.96.99, mpid=25802, TLS, session=<CL6VtRnWJITAqGBj>

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: The use of the PLAIN authentication method indicates unencrypted credentials were transmitted, which is a significant security risk regardless of the asset's criticality or the lack of prior history.

Evidence: Dovecot authentication using PLAIN method without TLS encryption from an external IP (192.168.96.99) to a low-criticality asset.

### wardbeck:50562 — -

Source message: Dovecot Authentication Success. | {"data": {}, "syscheck": {}} | Jan 21 16:13:43 walker-mail dovecot: imap-login: Login: user=<john.sanders>, method=PLAIN, rip=192.168.99.0, lip=192.168.99.0, mpid=28084, TLS, session=<eMkW5xnWxuHAqGMA>

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: The use of the PLAIN method for email login is a significant security risk due to lack of encryption, and this represents a new signature occurrence requiring verification of authorization and protocol usage.

Evidence: Successful PLAIN authentication via Dovecot from IP 192.168.99.0 using user john.sanders without TLS encryption.

### wardbeck:50809 — -

Source message: Suricata: Alert - SURICATA TLS invalid record/traffic | {"data": {"alert": {"action": "allowed", "category": "Generic Protocol Command Decode", "gid": "1", "rev": "1", "severity": "3", "signature": "SURICATA TLS invalid record/traffic", "signature_id": "2230010"}, "app_proto": "tls", "dest_ip": "192.168.96.4", "dest_port": "37328", "event_type": "alert", "flow": {"bytes_toclient": "174", "bytes_toserver": "1728", "pkts_toclient": "3", "pkts_toserver": "8", "start": "2022-01-21T16:30:55.611118+0000"}, "flow_id": "2133661902132014.000000", "in_iface": "ens3", "metadata": {"flowints": {"tls": {"anomaly": {"count": "2"}}}}, "proto": "TCP", "src_ip": "204.79.197.254", "src_port": "443", "timestamp": "2022-01-21T16:30:55.625533+0000", "tls": {"ja3": {"hash": "cd08e31494f9531f560d64c695473da9", "string": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0"}, "sni": "a-cedexis.msedge.net", "version": "UNDETERMINED"}, "tx_id": "0"}, "syscheck": {}}

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: The alert indicates malformed TLS traffic originating from an external source targeting an internal host, which represents a potential protocol-level attack or anomaly that requires immediate verification before suppression.

Evidence: Suricata detected TLS invalid record/traffic from external IP 204.79.197.254 to internal host wazuh-client on port 37328; this is the first occurrence of this signature.

### wardbeck:54816 — -

Source message: Suricata: Alert - SURICATA TLS invalid record/traffic | {"data": {"alert": {"action": "allowed", "category": "Generic Protocol Command Decode", "gid": "1", "rev": "1", "severity": "3", "signature": "SURICATA TLS invalid record/traffic", "signature_id": "2230010"}, "app_proto": "tls", "dest_ip": "192.168.96.4", "dest_port": "39598", "event_type": "alert", "flow": {"bytes_toclient": "464", "bytes_toserver": "2239", "pkts_toclient": "3", "pkts_toserver": "9", "start": "2022-01-22T07:09:43.005241+0000"}, "flow_id": "769751248213113.000000", "in_iface": "ens3", "metadata": {"flowints": {"tls": {"anomaly": {"count": "2"}}}}, "proto": "TCP", "src_ip": "54.156.83.163", "src_port": "443", "timestamp": "2022-01-22T07:09:43.341478+0000", "tls": {"ja3": {"hash": "cd08e31494f9531f560d64c695473da9", "string": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0"}, "sni": "pixel.anyclip.com", "version": "UNDETERMINED"}, "tx_id": "0"}, "syscheck": {}}

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: The alert indicates malformed TLS traffic originating from an external source targeting a Wazuh client, which represents a potential protocol-level attack vector that cannot be dismissed due to missing benign context or baseline data.

Evidence: Suricata detected TLS invalid record/traffic from external IP 54.156.83.163 to internal host wazuh-client on port 39598; this is the first occurrence of this signature.

### wardbeck:57873 — -

Source message: Dovecot Authentication Success. | {"data": {}, "syscheck": {}} | Jan 22 10:21:07 mail dovecot: imap-login: Login: user=<martha.miller>, method=PLAIN, rip=10.132.56.171, lip=10.132.56.171, mpid=23509, TLS, session=<h9ruFynWqKQKhDir>

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: The use of the PLAIN method indicates unencrypted credentials, which is a significant security risk regardless of the specific user or host context.

Evidence: Successful authentication via PLAIN method (unencrypted) for user 'martha.miller' from IP 10.132.56.171 on a first-time occurrence with no benign history.

### wardbeck:62043 — -

Source message: Dovecot Authentication Success. | {"data": {}, "syscheck": {}} | Jan 22 14:18:00 mail dovecot: imap-login: Login: user=<malcolm.allen>, method=PLAIN, rip=10.132.56.171, lip=10.132.56.171, mpid=27007, TLS, session=<NzoiZyzW1KsKhDir>

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: The use of the PLAIN authentication method is inherently insecure as it transmits credentials in cleartext, and the lack of verified TLS encryption details raises immediate concern for credential theft or replay attacks.

Evidence: Dovecot authentication using PLAIN method without TLS negotiation (TLS flag present but no cipher suite or certificate details in the log snippet) from an external IP address (10.132.56.171) to a mail server.

### wardbeck:66168 — -

Source message: Dovecot Authentication Success. | {"data": {}, "syscheck": {}} | Jan 22 16:00:36 mail dovecot: imap-login: Login: user=<malcolm.allen>, method=PLAIN, rip=10.132.56.171, lip=10.132.56.171, mpid=28508, TLS, session=<9fwK1i3Wyq4KhDir>

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: While the user may be legitimate, the use of unencrypted PLAIN authentication is a significant security risk that requires verification of authorization and protocol compliance before suppression.

Evidence: Successful authentication via PLAIN method (unencrypted) from IP 10.132.56.171 for user malcolm.allen on wazuh-client.

### wardbeck:69427 — -

Source message: Dovecot Authentication Success. | {"data": {}, "syscheck": {}} | Jan 23 06:27:05 walker-mail dovecot: imap-login: Login: user=<john.sanders>, method=PLAIN, rip=192.168.99.0, lip=192.168.99.0, mpid=9769, TLS, session=<g3TT8DnWWurAqGMA>

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: The use of the PLAIN method without TLS is a significant security risk as credentials are transmitted in clear text, and this represents an unverified anomaly for a new signature.

Evidence: Successful PLAIN authentication for user john.sanders from IP 192.168.99.0 to Dovecot on wazuh-client without TLS encryption.

### wardbeck:72433 — -

Source message: Suricata: Alert - SURICATA TLS invalid record/traffic | {"data": {"alert": {"action": "allowed", "category": "Generic Protocol Command Decode", "gid": "1", "rev": "1", "severity": "3", "signature": "SURICATA TLS invalid record/traffic", "signature_id": "2230010"}, "app_proto": "tls", "dest_ip": "52.208.185.108", "dest_port": "443", "event_type": "alert", "flow": {"bytes_toclient": "904", "bytes_toserver": "1908", "pkts_toclient": "7", "pkts_toserver": "12", "start": "2022-01-23T10:33:29.447531+0000"}, "flow_id": "2212181675988011.000000", "in_iface": "ens3", "metadata": {"flowints": {"tls": {"anomaly": {"count": "4"}}}}, "proto": "TCP", "src_ip": "192.168.96.4", "src_port": "57838", "timestamp": "2022-01-23T10:33:29.580880+0000", "tls": {"ja3": {"hash": "a75de44db3e351bbd8d38b64c41f444e", "string": "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53-10,0-23-65281-10-11-16-5-51-43-13-28-21,29-23-24-25-256-257,0"}, "sni": "beacon.krxd.net", "version": "UNDETERMINED"}, "tx_id": "0"}, "syscheck": {}}

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: The event records a specific TLS anomaly involving an unknown SNI (beacon.krxd.net) and invalid record traffic, which contradicts the lack of benign facts; this is precautionary review as no compromise is established but the behavior warrants investigation.

Evidence: Suricata detected TLS invalid record/traffic from internal IP 192.168.96.4 to external beacon.krxd.net on port 443 with a JA3 hash indicating potential protocol anomalies.

### wardbeck:72947 — -

Source message: Dovecot Authentication Success. | {"data": {}, "syscheck": {}} | Jan 23 11:22:32 mail dovecot: imap-login: Login: user=<martha.miller>, method=PLAIN, rip=10.132.56.171, lip=10.132.56.171, mpid=4829, TLS, session=<F85pET7WHrcKhDir>

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: The use of the PLAIN method without TLS negotiation is a significant security risk as credentials are transmitted in clear text, and this represents a new signature with no benign history to justify suppression.

Evidence: Successful PLAIN authentication for user 'martha.miller' from IP 10.132.56.171 using unencrypted protocol on Dovecot.

### wheeler:2080 — -

Source message: IDS event. | {"data": {"dstip": "10.38.242.195", "dstport": 443, "id": "1:2230003:1", "srcip": "10.38.243.24"}, "syscheck": {}} | 01/26/2022-06:39:24.904397  [**] [1:2230003:1] SURICATA TLS invalid handshake message [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 10.38.243.24:43210 -> 10.38.242.195:443

Decision: **escalate**, tier `llm`, source severity 4.00.

Rationale: This is the first occurrence of a TLS handshake anomaly targeting an internal asset; without benign context or known baselines, the risk of credential theft or lateral movement requires immediate manual verification rather than suppression.

Evidence: Suricata TLS invalid handshake message detected from internal IP 10.38.243.24 to internal server 10.38.242.195 on port 443.

### wheeler:24789 — -

Source message: Suricata: Alert - SURICATA TLS invalid handshake message | {"data": {"alert": {"action": "allowed", "category": "Generic Protocol Command Decode", "gid": "1", "rev": "1", "severity": "3", "signature": "SURICATA TLS invalid handshake message", "signature_id": "2230003"}, "app_proto": "tls", "dest_ip": "10.38.242.195", "dest_port": "443", "event_type": "alert", "flow": {"bytes_toclient": "496", "bytes_toserver": "1827", "pkts_toclient": "3", "pkts_toserver": "6", "start": "2022-01-26T14:42:55.484006+0000"}, "flow_id": "1656823865107110.000000", "in_iface": "ens3", "metadata": {"flowints": {"tls": {"anomaly": {"count": "4"}}}}, "proto": "TCP", "src_ip": "10.38.243.24", "src_port": "57940", "timestamp": "2022-01-26T14:42:55.499088+0000", "tls": {"ja3": {"hash": "e0ff89ed9185dfb09184797a4c3f2e1c", "string": "771,4866-4867-4865-49196-49200-159-52393-52392-52394-49195-49199-158-49188-49192-107-49187-49191-103-49162-49172-57-49161-49171-51-157-156-61-60-53-47-255,0-11-10-35-22-23-49-13-43-45-51-21,29-23-30-25-24,0-1-2"}, "sni": "mail.dmz.flores.wheeler.biz", "version": "UNDETERMINED"}, "tx_id": "0"}, "syscheck": {}}

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: This is the first occurrence of a TLS protocol anomaly involving an external source connecting to an internal server, which requires manual verification to distinguish between legitimate misconfiguration and potential exploitation.

Evidence: Suricata detected an invalid TLS handshake from external IP 10.38.243.24 to internal host wazuh-client on port 443 targeting SNI mail.dmz.flores.wheeler.biz.

### wheeler:24969 — -

Source message: Multiple IDS alerts for same id (ignoring now this id). | {"data": {"dstip": "10.38.242.195", "dstport": 443, "id": "1:2230010:1", "srcip": "10.38.243.24"}, "syscheck": {}} | 01/26/2022-14:47:37.428255  [**] [1:2230010:1] SURICATA TLS invalid record/traffic [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 10.38.243.24:58084 -> 10.38.242.195:443

Decision: **escalate**, tier `prefilter`, source severity 7.33.

Rationale: score 9.5 >= 7.0 (severity 7.333333333333333, asset criticality 1.3)

Evidence: Auto-escalated by prefilter: Multiple IDS alerts for same id (ignoring now this id). | {"data": {"dstip": "10.38.242.195", "dstport": 443, "id": "1:2230010:1", "srcip": "10.38.243.24"}, "syscheck": {}} | 01/26/2022-14:47:37.428255  [**] [1:2230010:1] SURICATA TLS invalid record/traffic [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 10.38.243.24:58084 -> 10.38.242.195:443

### wheeler:37066 — -

Source message: Suricata: Alert - SURICATA TLS invalid handshake message | {"data": {"alert": {"action": "allowed", "category": "Generic Protocol Command Decode", "gid": "1", "rev": "1", "severity": "3", "signature": "SURICATA TLS invalid handshake message", "signature_id": "2230003"}, "app_proto": "tls", "dest_ip": "172.27.180.4", "dest_port": "42916", "event_type": "alert", "flow": {"bytes_toclient": "206", "bytes_toserver": "1014", "pkts_toclient": "3", "pkts_toserver": "6", "start": "2022-01-27T07:15:48.706966+0000"}, "flow_id": "1914261666580886.000000", "in_iface": "ens3", "metadata": {"flowints": {"tls": {"anomaly": {"count": "2"}}}}, "proto": "TCP", "src_ip": "151.101.192.239", "src_port": "443", "timestamp": "2022-01-27T07:15:48.746441+0000", "tls": {"ja3": {"hash": "cd08e31494f9531f560d64c695473da9", "string": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0"}, "sni": "www.glamour.com", "version": "UNDETERMINED"}, "tx_id": "0"}, "syscheck": {}}

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: The alert indicates a protocol anomaly involving an unknown external source attempting communication with the Wazuh client, which requires manual verification to rule out reconnaissance or exploitation before suppression.

Evidence: Suricata detected an invalid TLS handshake from external IP 151.101.192.239 to internal host wazuh-client on port 42916; this is the first occurrence of this signature.

### wheeler:90269 — -

Source message: IDS event. | {"data": {"dstip": "10.38.242.1", "dstport": 53, "id": "1:2027863:4", "srcip": "10.38.243.125"}, "syscheck": {}} | 01/28/2022-12:13:11.459239  [**] [1:2027863:4] ET INFO Observed DNS Query to .biz TLD [**] [Classification: Potentially Bad Traffic] [Priority: 2] {UDP} 10.38.243.125:52846 -> 10.38.242.1:53

Decision: **escalate**, tier `llm`, source severity 4.00.

Rationale: This is the first occurrence of a potentially bad traffic signature for a benign-looking DNS query; without historical context or environment facts confirming normal .biz usage, the precautionary rule must be escalated to verify if this represents a new threat.

Evidence: DNS query to .biz TLD from internal IP 10.38.243.125 to external DNS server 10.38.242.1

### wheeler:97845 — -

Source message: Suricata: Alert - SURICATA TLS invalid record/traffic | {"data": {"alert": {"action": "allowed", "category": "Generic Protocol Command Decode", "gid": "1", "rev": "1", "severity": "3", "signature": "SURICATA TLS invalid record/traffic", "signature_id": "2230010"}, "app_proto": "tls", "dest_ip": "10.38.243.24", "dest_port": "49036", "event_type": "alert", "flow": {"bytes_toclient": "496", "bytes_toserver": "981", "pkts_toclient": "3", "pkts_toserver": "5", "start": "2022-01-28T14:21:04.355110+0000"}, "flow_id": "708192792242982.000000", "in_iface": "ens3", "metadata": {"flowints": {"tls": {"anomaly": {"count": "2"}}}}, "proto": "TCP", "src_ip": "10.38.242.195", "src_port": "443", "timestamp": "2022-01-28T14:21:04.370502+0000", "tls": {"ja3": {"hash": "e0ff89ed9185dfb09184797a4c3f2e1c", "string": "771,4866-4867-4865-49196-49200-159-52393-52392-52394-49195-49199-158-49188-49192-107-49187-49191-103-49162-49172-57-49161-49171-51-157-156-61-60-53-47-255,0-11-10-35-22-23-49-13-43-45-51-21,29-23-30-25-24,0-1-2"}, "sni": "mail.dmz.flores.wheeler.biz", "version": "UNDETERMINED"}, "tx_id": "0"}, "syscheck": {}}

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: This is the first occurrence of a TLS anomaly signature; while the destination SNI suggests a legitimate mail service, the 'invalid record' classification indicates protocol corruption or potential exploitation that cannot be dismissed without verifying the source IP's reputation and packet payload.

Evidence: TLS invalid record/traffic detected from external IP 10.38.242.195 to internal host wazuh-client on port 49036 targeting SNI mail.dmz.flores.wheeler.biz.

### wheeler:108031 — -

Source message: Dovecot Authentication Success. | {"data": {}, "syscheck": {}} | Jan 28 18:29:31 mail dovecot: imap-login: Login: user=<melissa.cole>, method=PLAIN, rip=10.38.242.195, lip=10.38.242.195, mpid=22469, TLS, session=<zOWmnajWRMsKJvLD>

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: The use of the PLAIN method over an unencrypted channel represents a significant security risk, as credentials are transmitted in clear text; this requires immediate verification of whether this was an authorized administrative action or unauthorized access.

Evidence: Successful PLAIN authentication via Dovecot from IP 10.38.242.195 using user 'melissa.cole' without TLS encryption (despite session flag), which is a known vector for credential interception.

### wheeler:108364 — -

Source message: Suricata: Alert - SURICATA TLS invalid handshake message | {"data": {"alert": {"action": "allowed", "category": "Generic Protocol Command Decode", "gid": "1", "rev": "1", "severity": "3", "signature": "SURICATA TLS invalid handshake message", "signature_id": "2230003"}, "app_proto": "tls", "dest_ip": "151.101.194.202", "dest_port": "443", "event_type": "alert", "flow": {"bytes_toclient": "323", "bytes_toserver": "1385", "pkts_toclient": "4", "pkts_toserver": "9", "start": "2022-01-28T18:45:34.000877+0000"}, "flow_id": "2210618489570157.000000", "in_iface": "ens3", "metadata": {"flowints": {"tls": {"anomaly": {"count": "4"}}}}, "proto": "TCP", "src_ip": "10.38.243.125", "src_port": "48292", "timestamp": "2022-01-28T18:45:34.025979+0000", "tls": {"ja3": {"hash": "a75de44db3e351bbd8d38b64c41f444e", "string": "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53-10,0-23-65281-10-11-16-5-51-43-13-28-21,29-23-24-25-256-257,0"}, "sni": "mab.chartbeat.com", "version": "UNDETERMINED"}, "tx_id": "0"}, "syscheck": {}}

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: While the destination is a known benign analytics provider and this is the first occurrence, TLS protocol anomalies can indicate compromised clients attempting to establish connections or potential man-in-the-middle attempts; without baseline data for this specific internal host, the risk of credential theft or lateral movement cannot be ruled out.

Evidence: TLS handshake anomaly detected from internal IP 10.38.243.125 to external host mab.chartbeat.com (Chartbeat analytics service) with invalid message structure.

### wheeler:117495 — -

Source message: Suricata: Alert - ET INFO Observed DNS Query to .biz TLD | {"data": {"alert": {"action": "allowed", "category": "Potentially Bad Traffic", "gid": "1", "metadata": {"affected_product": ["Any"], "attack_target": ["Client_Endpoint"], "created_at": ["2019_08_13"], "deployment": ["Perimeter"], "former_category": ["INFO"], "signature_severity": ["Major"], "updated_at": ["2020_09_17"]}, "rev": "4", "severity": "2", "signature": "ET INFO Observed DNS Query to .biz TLD", "signature_id": "2027863"}, "app_proto": "dns", "dest_ip": "10.38.242.1", "dest_port": "53", "dns": {"query": [{"id": 33720, "rrname": "mail.flores.wheeler.biz", "rrtype": "A", "tx_id": 8, "type": "query"}]}, "event_type": "alert", "flow": {"bytes_toclient": "588", "bytes_toserver": "470", "pkts_toclient": "4", "pkts_toserver": "5", "start": "2022-01-29T10:23:27.846702+0000"}, "flow_id": "1255513792703342.000000", "in_iface": "ens3", "proto": "UDP", "src_ip": "10.38.243.125", "src_port": "47849", "timestamp": "2022-01-29T10:23:27.854516+0000", "tx_id": "8"}, "syscheck": {}}

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: This is the first occurrence of a signature flagged as 'Potentially Bad Traffic' targeting client endpoints; without historical benign context or specific environment facts confirming this domain/user combination, the risk of credential abuse or lateral movement cannot be ruled out.

Evidence: DNS query to .biz TLD from internal IP 10.38.243.125 to external server 10.38.242.1 at 2022-01-29T10:23:27

### wheeler:126094 — -

Source message: IDS event. | {"data": {"dstip": "10.38.242.1", "dstport": 53, "id": "1:2027863:4", "srcip": "10.38.243.125"}, "syscheck": {}} | 01/29/2022-12:46:50.328258  [**] [1:2027863:4] ET INFO Observed DNS Query to .biz TLD [**] [Classification: Potentially Bad Traffic] [Priority: 2] {UDP} 10.38.243.125:50807 -> 10.38.242.1:53

Decision: **escalate**, tier `llm`, source severity 4.00.

Rationale: This is the first occurrence of a potentially bad traffic alert for DNS queries, and while .biz domains are legitimate, the lack of baseline data or benign context requires manual verification to rule out C2 communication or data exfiltration.

Evidence: DNS query to .biz TLD from internal host 10.38.243.125 to external resolver 10.38.242.1 at timestamp 2022-01-29T12:46:50

### wheeler:144041 — -

Source message: Suricata: Alert - ET INFO Observed DNS Query to .biz TLD | {"data": {"alert": {"action": "allowed", "category": "Potentially Bad Traffic", "gid": "1", "metadata": {"affected_product": ["Any"], "attack_target": ["Client_Endpoint"], "created_at": ["2019_08_13"], "deployment": ["Perimeter"], "former_category": ["INFO"], "signature_severity": ["Major"], "updated_at": ["2020_09_17"]}, "rev": "4", "severity": "2", "signature": "ET INFO Observed DNS Query to .biz TLD", "signature_id": "2027863"}, "app_proto": "dns", "dest_ip": "10.38.242.1", "dest_port": "53", "dns": {"query": [{"id": 13459, "rrname": "cloud.flores.wheeler.biz", "rrtype": "A", "tx_id": 6, "type": "query"}]}, "event_type": "alert", "flow": {"bytes_toclient": "444", "bytes_toserver": "380", "pkts_toclient": "3", "pkts_toserver": "4", "start": "2022-01-29T19:07:01.785154+0000"}, "flow_id": "2075042856172290.000000", "in_iface": "ens3", "proto": "UDP", "src_ip": "10.38.243.125", "src_port": "58748", "timestamp": "2022-01-29T19:07:01.796448+0000", "tx_id": "6"}, "syscheck": {}}

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: This is the first occurrence of a signature flagged as 'Potentially Bad Traffic' targeting a .biz domain; without historical benign context or specific environment facts confirming this query's legitimacy, the risk of credential abuse or lateral movement cannot be ruled out.

Evidence: DNS query to cloud.flores.wheeler.biz from internal host 10.38.243.125 to external IP 10.38.242.1 at 2022-01-29T19:07:01.796448+00:00

### wheeler:572264 — -

Source message: Suricata: Alert - SURICATA TLS invalid handshake message | {"data": {"alert": {"action": "allowed", "category": "Generic Protocol Command Decode", "gid": "1", "rev": "1", "severity": "3", "signature": "SURICATA TLS invalid handshake message", "signature_id": "2230003"}, "app_proto": "tls", "dest_ip": "10.38.242.195", "dest_port": "443", "event_type": "alert", "flow": {"bytes_toclient": "496", "bytes_toserver": "1808", "pkts_toclient": "3", "pkts_toserver": "6", "start": "2022-01-30T08:36:21.240007+0000"}, "flow_id": "126979869616519.000000", "in_iface": "ens3", "metadata": {"flowints": {"tls": {"anomaly": {"count": "4"}}}}, "proto": "TCP", "src_ip": "10.38.243.24", "src_port": "60438", "timestamp": "2022-01-30T08:36:21.250294+0000", "tls": {"ja3": {"hash": "e0ff89ed9185dfb09184797a4c3f2e1c", "string": "771,4866-4867-4865-49196-49200-159-52393-52392-52394-49195-49199-158-49188-49192-107-49187-49191-103-49162-49172-57-49161-49171-51-157-156-61-60-53-47-255,0-11-10-35-22-23-49-13-43-45-51-21,29-23-30-25-24,0-1-2"}, "sni": "mail.dmz.flores.wheeler.biz", "version": "UNDETERMINED"}, "tx_id": "0"}, "syscheck": {}}

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: This is the first occurrence of this signature, and while TLS anomalies can be benign, they represent a potential intrusion attempt that cannot be dismissed without verifying the source IP's legitimacy or checking for related connection failures.

Evidence: Suricata detected an invalid TLS handshake from source IP 10.38.243.24 to destination 10.38.242.195 on port 443 targeting SNI mail.dmz.flores.wheeler.biz.

### wheeler:600061 — -

Source message: Suricata: Alert - SURICATA TLS invalid handshake message | {"data": {"alert": {"action": "allowed", "category": "Generic Protocol Command Decode", "gid": "1", "rev": "1", "severity": "3", "signature": "SURICATA TLS invalid handshake message", "signature_id": "2230003"}, "app_proto": "tls", "dest_ip": "85.114.159.118", "dest_port": "443", "event_type": "alert", "flow": {"bytes_toclient": "464", "bytes_toserver": "1062", "pkts_toclient": "3", "pkts_toserver": "8", "start": "2022-01-30T18:23:41.163333+0000"}, "flow_id": "787069260365317.000000", "in_iface": "ens3", "metadata": {"flowints": {"tls": {"anomaly": {"count": "4"}}}}, "proto": "TCP", "src_ip": "10.38.243.125", "src_port": "51198", "timestamp": "2022-01-30T18:23:41.270172+0000", "tls": {"ja3": {"hash": "cd08e31494f9531f560d64c695473da9", "string": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0"}, "sni": "dsp.adfarm1.adition.com", "version": "UNDETERMINED"}, "tx_id": "0"}, "syscheck": {}}

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: This is the first occurrence of a TLS handshake anomaly involving an internal host connecting to an external domain; without benign baseline data or known legitimate traffic patterns for this specific destination, the risk of credential abuse or lateral movement cannot be ruled out.

Evidence: TLS invalid handshake detected from internal IP 10.38.243.125 to external destination 85.114.159.118 on port 443 with SNI 'dsp.adfarm1.adition.com'.

### wheeler:601199 — -

Source message: IDS event. | {"data": {"dstip": "10.38.243.125", "dstport": 44654, "id": "1:2230010:1", "srcip": "185.33.220.241"}, "syscheck": {}} | 01/30/2022-18:40:34.612364  [**] [1:2230010:1] SURICATA TLS invalid record/traffic [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 185.33.220.241:443 -> 10.38.243.125:44654

Decision: **escalate**, tier `llm`, source severity 4.00.

Rationale: This is the first occurrence of a generic protocol decode anomaly involving an external source targeting an internal asset; without benign context or baseline data, the risk of credential abuse or lateral movement cannot be ruled out.

Evidence: Suricata detected TLS invalid record/traffic from external IP 185.33.220.241 to internal host 10.38.243.125 on port 44654.

### wilson:24532 — -

Source message: IDS event. | {"data": {"dstip": "10.182.194.5", "dstport": 44916, "id": "1:2230010:1", "srcip": "10.182.193.181"}, "syscheck": {}} | 02/03/2022-14:26:50.581135  [**] [1:2230010:1] SURICATA TLS invalid record/traffic [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 10.182.193.181:443 -> 10.182.194.5:44916

Decision: **escalate**, tier `llm`, source severity 4.00.

Rationale: This is the first occurrence of this signature, and while TLS protocol anomalies can be benign, they represent an unverified anomaly that could indicate compromised hosts or misconfigured services; without environment facts to confirm legitimacy, the risk of missing an intrusion outweighs the cost of escalation.

Evidence: Suricata TLS invalid record/traffic detected from internal IP 10.182.193.181 to internal IP 10.182.194.5 on a non-standard port (44916).

### wilson:36010 — -

Source message: IDS event. | {"data": {"dstip": "192.168.224.4", "dstport": 50232, "id": "1:2230010:1", "srcip": "151.101.194.217"}, "syscheck": {}} | 02/03/2022-21:28:16.610728  [**] [1:2230010:1] SURICATA TLS invalid record/traffic [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 151.101.194.217:443 -> 192.168.224.4:50232

Decision: **escalate**, tier `llm`, source severity 4.00.

Rationale: This is the first occurrence of a TLS protocol anomaly targeting an internal asset; without benign context or known baselines, the risk of active exploitation outweighs the uncertainty of false positives.

Evidence: Suricata TLS invalid record/traffic detected from external IP 151.101.194.217 to internal host wazuh-client on ephemeral port 50232.

### wilson:58726 — -

Source message: Suricata: Alert - SURICATA TLS invalid record/traffic | {"data": {"alert": {"action": "allowed", "category": "Generic Protocol Command Decode", "gid": "1", "rev": "1", "severity": "3", "signature": "SURICATA TLS invalid record/traffic", "signature_id": "2230010"}, "app_proto": "tls", "dest_ip": "10.182.193.181", "dest_port": "443", "event_type": "alert", "flow": {"bytes_toclient": "496", "bytes_toserver": "1902", "pkts_toclient": "3", "pkts_toserver": "6", "start": "2022-02-04T13:45:23.140702+0000"}, "flow_id": "1199387568186782.000000", "in_iface": "ens3", "metadata": {"flowints": {"tls": {"anomaly": {"count": "4"}}}}, "proto": "TCP", "src_ip": "10.182.194.5", "src_port": "47988", "timestamp": "2022-02-04T13:45:23.158010+0000", "tls": {"ja3": {"hash": "e0ff89ed9185dfb09184797a4c3f2e1c", "string": "771,4866-4867-4865-49196-49200-159-52393-52392-52394-49195-49199-158-49188-49192-107-49187-49191-103-49162-49172-57-49161-49171-51-157-156-61-60-53-47-255,0-11-10-35-22-23-49-13-43-45-51-21,29-23-30-25-24,0-1-2"}, "sni": "mail.dmz.hallbrown.wilson.com", "version": "UNDETERMINED"}, "tx_id": "0"}, "syscheck": {}}

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: The alert indicates a TLS protocol anomaly involving an internal host communicating with a specific domain, which requires manual verification to distinguish between legitimate misconfiguration and potential exploitation before suppression.

Evidence: TLS invalid record/traffic detected from internal IP 10.182.194.5 to mail.dmz.hallbrown.wilson.com on port 443; this is the first occurrence of this signature.

### wilson:61083 — -

Source message: Suricata: Alert - SURICATA TLS invalid record/traffic | {"data": {"alert": {"action": "allowed", "category": "Generic Protocol Command Decode", "gid": "1", "rev": "1", "severity": "3", "signature": "SURICATA TLS invalid record/traffic", "signature_id": "2230010"}, "app_proto": "tls", "dest_ip": "10.182.194.5", "dest_port": "49986", "event_type": "alert", "flow": {"bytes_toclient": "496", "bytes_toserver": "981", "pkts_toclient": "3", "pkts_toserver": "5", "start": "2022-02-04T14:22:39.796538+0000"}, "flow_id": "56958626244474.000000", "in_iface": "ens3", "metadata": {"flowints": {"tls": {"anomaly": {"count": "2"}}}}, "proto": "TCP", "src_ip": "10.182.193.181", "src_port": "443", "timestamp": "2022-02-04T14:22:39.812510+0000", "tls": {"ja3": {"hash": "e0ff89ed9185dfb09184797a4c3f2e1c", "string": "771,4866-4867-4865-49196-49200-159-52393-52392-52394-49195-49199-158-49188-49192-107-49187-49191-103-49162-49172-57-49161-49171-51-157-156-61-60-53-47-255,0-11-10-35-22-23-49-13-43-45-51-21,29-23-30-25-24,0-1-2"}, "sni": "mail.dmz.hallbrown.wilson.com", "version": "UNDETERMINED"}, "tx_id": "0"}, "syscheck": {}}

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: This is the first occurrence of this signature, and while the destination domain appears benign, the 'invalid record' anomaly combined with an unknown internal source IP requires manual verification to rule out compromised hosts or misconfigured clients before suppressing.

Evidence: TLS invalid record/traffic detected from internal IP 10.182.193.181 to external host mail.dmz.hallbrown.wilson.com on port 49986 with a TLS JA3 hash indicating a specific client fingerprint.

### wilson:77225 — -

Source message: Suricata: Alert - SURICATA TLS invalid record/traffic | {"data": {"alert": {"action": "allowed", "category": "Generic Protocol Command Decode", "gid": "1", "rev": "1", "severity": "3", "signature": "SURICATA TLS invalid record/traffic", "signature_id": "2230010"}, "app_proto": "tls", "dest_ip": "3.64.44.229", "dest_port": "443", "event_type": "alert", "flow": {"bytes_toclient": "392", "bytes_toserver": "1307", "pkts_toclient": "4", "pkts_toserver": "10", "start": "2022-02-05T07:53:54.812231+0000"}, "flow_id": "127705166275783.000000", "in_iface": "ens3", "metadata": {"flowints": {"tls": {"anomaly": {"count": "4"}}}}, "proto": "TCP", "src_ip": "10.182.193.78", "src_port": "48274", "timestamp": "2022-02-05T07:53:54.993331+0000", "tls": {"ja3": {"hash": "a75de44db3e351bbd8d38b64c41f444e", "string": "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53-10,0-23-65281-10-11-16-5-51-43-13-28-21,29-23-24-25-256-257,0"}, "sni": "btlr.sharethrough.com", "version": "UNDETERMINED"}, "tx_id": "0"}, "syscheck": {}}

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: TLS protocol anomalies indicate potential cryptographic failures or malicious traffic, which cannot be dismissed without verified baseline data or known-benign patterns matching this specific behavior.

Evidence: Suricata detected TLS invalid record/traffic from an external IP (3.64.44.229) to a destination on port 443; this is the first occurrence of this signature and no benign environment facts exist to explain it.

### wilson:78371 — -

Source message: IDS event. | {"data": {"dstip": "10.182.194.5", "dstport": 37238, "id": "1:2230010:1", "srcip": "10.182.193.181"}, "syscheck": {}} | 02/05/2022-08:07:41.767934  [**] [1:2230010:1] SURICATA TLS invalid record/traffic [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 10.182.193.181:443 -> 10.182.194.5:37238

Decision: **escalate**, tier `llm`, source severity 4.00.

Rationale: This is the first occurrence of this signature, and while TLS protocol anomalies can be benign (e.g., certificate validation failures or non-standard server behavior), they represent a potential indicator of compromise that cannot be dismissed without verifying the specific traffic context.

Evidence: Suricata TLS invalid record/traffic detected on host wazuh-client targeting internal IP 10.182.194.5:37238 from source 10.182.193.181:443.

### wilson:95466 — -

Source message: IDS event. | {"data": {"dstip": "10.182.194.5", "dstport": 50462, "id": "1:2230003:1", "srcip": "10.182.193.181"}, "syscheck": {}} | 02/05/2022-13:33:23.007140  [**] [1:2230003:1] SURICATA TLS invalid handshake message [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 10.182.193.181:443 -> 10.182.194.5:50462

Decision: **escalate**, tier `llm`, source severity 4.00.

Rationale: This is the first occurrence of a TLS handshake anomaly between two internal hosts, and without benign context or baseline data, the risk of an active intrusion attempt cannot be ruled out.

Evidence: Suricata TLS invalid handshake message detected from internal IP 10.182.193.181 to internal IP 10.182.194.5 on port 50462.

### wilson:113829 — -

Source message: Suricata: Alert - SURICATA TLS invalid handshake message | {"data": {"alert": {"action": "allowed", "category": "Generic Protocol Command Decode", "gid": "1", "rev": "1", "severity": "3", "signature": "SURICATA TLS invalid handshake message", "signature_id": "2230003"}, "app_proto": "tls", "dest_ip": "10.182.193.78", "dest_port": "50520", "event_type": "alert", "flow": {"bytes_toclient": "496", "bytes_toserver": "1113", "pkts_toclient": "3", "pkts_toserver": "7", "start": "2022-02-06T09:17:46.935245+0000"}, "flow_id": "1829465247860045.000000", "in_iface": "ens3", "metadata": {"flowints": {"tls": {"anomaly": {"count": "2"}}}}, "proto": "TCP", "src_ip": "81.3.192.9", "src_port": "443", "timestamp": "2022-02-06T09:17:46.988555+0000", "tls": {"ja3": {"hash": "cd08e31494f9531f560d64c695473da9", "string": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0"}, "sni": "statics-marketingsites-neu-ms-com.akamaized.net", "version": "UNDETERMINED"}, "tx_id": "0"}, "syscheck": {}}

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: The event records a TLS invalid handshake message originating from an external IP, which raises immediate concern for potential credential abuse or lateral movement attempts despite the lack of historical benign patterns.

Evidence: TLS handshake anomaly detected from external IP 81.3.192.9 to internal host wazuh-client targeting port 50520 for SNI statics-marketingsites-neu-ms-com.akamaized.net.

### wilson:134113 — -

Source message: IDS event. | {"data": {"dstip": "10.182.193.181", "dstport": 443, "id": "1:2230010:1", "srcip": "10.182.194.5"}, "syscheck": {}} | 02/06/2022-15:35:41.988893  [**] [1:2230010:1] SURICATA TLS invalid record/traffic [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 10.182.194.5:35730 -> 10.182.193.181:443

Decision: **escalate**, tier `llm`, source severity 4.00.

Rationale: This is the first occurrence of a TLS protocol anomaly involving internal traffic; without historical baselines or benign context, the specific nature of the invalid record cannot be ruled out as malicious.

Evidence: Suricata TLS invalid record/traffic detected from internal IP 10.182.194.5 to another internal host on port 443.

### wilson:142783 — -

Source message: IDS event. | {"data": {"dstip": "10.182.193.181", "dstport": 443, "id": "1:2230003:1", "srcip": "10.182.194.5"}, "syscheck": {}} | 02/07/2022-06:04:47.419621  [**] [1:2230003:1] SURICATA TLS invalid handshake message [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 10.182.194.5:49826 -> 10.182.193.181:443

Decision: **escalate**, tier `llm`, source severity 4.00.

Rationale: This is the first occurrence of a TLS handshake anomaly between two internal hosts, and without historical baselines or benign context, the risk of an active exploit or compromised host cannot be ruled out.

Evidence: Suricata TLS invalid handshake message detected from internal IP 10.182.194.5 to internal IP 10.182.193.181 on port 443.

### wilson:592502 — -

Source message: Dovecot Authentication Success. | {"data": {}, "syscheck": {}} | Feb  7 17:00:37 wilsonahmed-mail dovecot: imap-login: Login: user=<stephanie.franco>, method=PLAIN, rip=192.168.224.185, lip=192.168.224.185, mpid=30978, TLS, session=<iwgninDXmNjAqOC5>

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: The use of the PLAIN method for authentication presents a credential exposure risk if the connection was not actually encrypted, and this is the first occurrence requiring verification of user intent and network configuration.

Evidence: Successful PLAIN authentication via Dovecot from IP 192.168.224.185 by user stephanie.franco without TLS encryption (despite session flag indicating TLS in log, method=PLAIN is the critical risk indicator).

### wilson:595652 — -

Source message: Dovecot Authentication Success. | {"data": {}, "syscheck": {}} | Feb  8 05:37:50 mail dovecot: imap-login: Login: user=<gregory.allen>, method=PLAIN, rip=10.182.193.181, lip=10.182.193.181, mpid=21344, TLS, session=<DrcjHnvXYpsKtsG1>

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: The use of the PLAIN authentication method exposes credentials in transit; this requires immediate verification of whether this IP and user are authorized to access mail services without TLS.

Evidence: Successful PLAIN authentication via Dovecot from IP 10.182.193.181 using user gregory.allen without TLS encryption (despite 'TLS' appearing in the session string, PLAIN method inherently lacks encryption), which is a high-risk credential transmission vector.

### wilson:603424 — -

Source message: Dovecot Authentication Success. | {"data": {}, "syscheck": {}} | Feb  8 09:23:27 lane-mail dovecot: imap-login: Login: user=<jasmine.anderson>, method=PLAIN, rip=192.168.226.198, lip=192.168.226.198, mpid=8252, TLS, session=<eFMORX7XdsDAqOLG>

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: The use of PLAIN authentication method exposes credentials to network sniffing; this requires manual verification of the user's intent and the client configuration before suppressing as benign.

Evidence: Successful PLAIN authentication via Dovecot from IP 192.168.226.198 by user 'jasmine.anderson' without TLS encryption (despite session flag indicating TLS in log, method=PLAIN indicates unencrypted transport attempt or misconfiguration), which is a known vector for credential interception.

### wilson:608382 — -

Source message: Dovecot Authentication Success. | {"data": {}, "syscheck": {}} | Feb  8 11:07:27 wilsonahmed-mail dovecot: imap-login: Login: user=<ann.williams>, method=PLAIN, rip=192.168.224.185, lip=192.168.224.185, mpid=5441, TLS, session=<dVz8uH/XBt3AqOC5>

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: The use of the PLAIN method without TLS is a significant security risk as credentials are transmitted in cleartext, and this represents a new signature occurrence with no benign history to justify suppression.

Evidence: Successful PLAIN authentication via Dovecot from IP 192.168.224.185 by user ann.williams on host wilsonahmed-mail without TLS encryption.

### wilson:614679 — -

Source message: IDS event. | {"data": {"dstip": "52.46.131.253", "dstport": 443, "id": "1:2230010:1", "srcip": "10.182.193.78"}, "syscheck": {}} | 02/08/2022-13:17:22.285435  [**] [1:2230010:1] SURICATA TLS invalid record/traffic [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 10.182.193.78:38364 -> 52.46.131.253:443

Decision: **escalate**, tier `llm`, source severity 4.00.

Rationale: This is the first occurrence of this signature, and while no specific malicious behavior is confirmed, TLS protocol anomalies from an internal host warrant investigation before assuming benign activity or suppressing the alert.

Evidence: Suricata TLS invalid record/traffic detected from internal host 10.182.193.78 to external IP 52.46.131.253 on port 443.

### wilson:619935 — -

Source message: Suricata: Alert - SURICATA TLS invalid handshake message | {"data": {"alert": {"action": "allowed", "category": "Generic Protocol Command Decode", "gid": "1", "rev": "1", "severity": "3", "signature": "SURICATA TLS invalid handshake message", "signature_id": "2230003"}, "app_proto": "tls", "dest_ip": "10.182.194.5", "dest_port": "50938", "event_type": "alert", "flow": {"bytes_toclient": "496", "bytes_toserver": "981", "pkts_toclient": "3", "pkts_toserver": "5", "start": "2022-02-08T15:21:23.312342+0000"}, "flow_id": "334550210429974.000000", "in_iface": "ens3", "metadata": {"flowints": {"tls": {"anomaly": {"count": "2"}}}}, "proto": "TCP", "src_ip": "10.182.193.181", "src_port": "443", "timestamp": "2022-02-08T15:21:23.322866+0000", "tls": {"ja3": {"hash": "e0ff89ed9185dfb09184797a4c3f2e1c", "string": "771,4866-4867-4865-49196-49200-159-52393-52392-52394-49195-49199-158-49188-49192-107-49187-49191-103-49162-49172-57-49161-49171-51-157-156-61-60-53-47-255,0-11-10-35-22-23-49-13-43-45-51-21,29-23-30-25-24,0-1-2"}, "sni": "mail.dmz.hallbrown.wilson.com", "version": "UNDETERMINED"}, "tx_id": "0"}, "syscheck": {}}

Decision: **escalate**, tier `llm`, source severity 2.00.

Rationale: This is the first occurrence of a TLS invalid handshake alert; without historical baselines or benign context, the specific anomaly requires manual verification to rule out credential theft or lateral movement before suppression.

Evidence: TLS handshake anomaly detected from external IP 10.182.193.181 to internal host wazuh-client on port 50938 targeting SNI mail.dmz.hallbrown.wilson.com.
