import config from './demoPolicyConfig.js';
const C = config.constants;
const has = (text, words) => words.some(word => text.includes(word));
const number = x => typeof x === 'number' && Number.isFinite(x);
export const signature = ev => `${ev.source}:${ev.type}:${ev.host}`;
export function scopedContext(ev) {
  return {criticality: Object.hasOwn(config.assets, ev.host) ? config.assets[ev.host] : 1.3, facts: config.facts.filter(f => f.host === ev.host).map(f => f.event_types.includes(ev.type)
    ? `${f.text} [scope verified: this event matches the fact's scope]`
    : `${f.text} [SCOPE MISMATCH — this fact does NOT cover this event: event type '${ev.type}' is not covered (fact covers: ${f.event_types.join(', ')}). It must not be used to justify suppression.]`)};
}
export function guardrail(ev) {
  const m = ev.message.toLowerCase(), f = ev.fields || {}, type = ev.type;
  const predicates = {
    high_priority_tool_finding: () => f._tool_finding && f._telemetry && ['defender','wazuh','suricata','guardduty','windows_security','osquery'].includes(ev.source)
      && f._tool_finding.source === ev.source && f._telemetry.source === ev.source && f._tool_finding.type === type && f._tool_finding.high_priority === true,
    internet_exposure: () => ['firewall_change','security_group_change','port_open','acl_change','network_acl','ingress_change'].includes(type)
      && (has(m,C._BROAD_SCOPE) || ['0.0.0.0/0','::/0'].includes(String(f.cidr || '').trim()))
      && !(has(m,['443','80','http','https','web']) && !has(m,[...C._SENSITIVE_PORTS,...C._SENSITIVE_SVC,'all ports'])),
    credential_access: () => has(m,['mimikatz','lsass','ntds.dit','ntds','sam dump','reg save','secretsdump','credential dump','/etc/shadow','shadow.bak','hashdump','dcsync'])
      || (m.includes('shadow') && has(m,['read','copy','dump','cat','exfil','/tmp','crack'])) || (m.includes('passwd') && has(m,['shadow','crack','dump','exfil'])),
    privilege_expansion: () => ['user_created','account_created','iam_change','role_grant','group_change','priv_escalation'].includes(type)
      && (String(f.uid ?? '').trim() === '0' || has(m,['uid 0','wheel','sudo group','sudoers','admin','administrators','domain admin','root group','root','administratoraccess','privileged','elevated'])),
    download_execute: () => /(curl|wget|fetch|iwr|invoke-webrequest)\b[^\n]*\|\s*(sh|bash|zsh|python|perl)/.test(m)
      || has(m,['reverse shell','nc -e','bash -i','/dev/tcp/','powershell -enc','| sh -'])
      || (has(m,['download','curl','wget','fetch','urlcache']) && has(m,['chmod +x','then execut','executed /tmp','ran /tmp','&& ./','; ./','chmod 755'])),
    integrity_change: () => ['file_integrity','binary_change','integrity'].includes(type)
      && !has(m,['package manager confirms','apt confirms','confirmed update','confirms update','signed by','verified update','matches package','package confirms'])
      && has(m,['binary','sshd','executable','hash changed','checksum','.so','/usr/','/bin/','/sbin/','vmlinuz','.dll']),
    data_exfil: () => {
      if (!['data_upload','data_transfer','egress','dns_exfil','data_exfiltration','s3_download'].includes(type)) return false;
      if (type === 'dns_exfil' || has(m,['dns tunnel','exfil','unknown dest','unknown destination','unrecognized','external',...C._EXTERNAL_SINKS])) return true;
      const dest = String(f.src_ip || f.dst || m.match(/to (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/)?.[1] || '');
      return Boolean(dest && !has(dest,C._INTERNAL) && !has(m,['known backup','to nas-01']) && !/^(10\.|192\.168\.|172\.)/.test(dest));
    },
    lolbin: () => has(m,C._LOLBINS) && has(m,C._LOLBIN_CTX),
    supply_chain: () => has(m,['postinstall','preinstall','install script','npm install','pip install','gem install','setup.py','package script','lifecycle script'])
      && has(m,['curl','wget','download','fetch','http://','https://','registered','new domain','pastebin','raw.github','execute','network']),
    ransomware: () => ['mass_file_rename','file_encrypt','mass_delete','mass_modify'].includes(type)
      && ((number(f.count) && f.count >= 100) || (has(m,['renamed','re-saved','encrypted','files']) && has(m,['000','hundred','thousand','many','mass','1,','2,','3,','4,','5,','6,','7,','8,','9,']))),
    impossible_travel: () => type === 'geo_impossible_travel' || Boolean(String(f.geo || '').trim() && String(f.prev_geo || f.usual_geo || '').trim()
      && String(f.geo).trim() !== String(f.prev_geo || f.usual_geo).trim() && number(f.gap_minutes) && f.gap_minutes < 60),
  };
  return config.rules.find(rule => predicates[rule.name]?.()) || null;
}
export function downgrade(hit, ev) {
  if (hit?.name !== 'privilege_expansion') return null;
  const norm = s => s.toLowerCase().replaceAll('-',' '), m = norm(ev.message);
  return config.facts.filter(f => f.host === ev.host).map(f => f.text).find(text => {
    const f = norm(text);
    return f.includes(norm(ev.host)) && ((String(ev.fields.uid ?? '').trim() === '0' && has(f,['uid 0','uid0'])) || C._PRIV_MARKER_GROUPS.some(group => has(m,group) && has(f,group)));
  }) || null;
}
function routine(ev) {
  const f=ev.fields, p=f._telemetry, kind=ev.type;
  if (!p || f.correlation || ev.severity > 2) return false;
  if (p.source==='sysmon' && kind==='process_exec' && f._collector_activity===true) return true;
  if (p.source==='windows_security' && kind==='security_posture' && ev.severity===0) return true;
  if (p.source==='osquery' && kind==='asset_snapshot') return true;
  if (p.source==='cloudtrail' && kind==='cloud_read') return true;
  if (p.source==='suricata' && ['dns','http','tls','flow','fileinfo'].includes(kind)) return true;
  if (p.source==='syslog' && kind==='syslog_message' && ev.severity<=1) return true;
  if (['windows','sysmon'].includes(p.source) && ['auth_success','auth_failure','logout','dns_query','network_connection','file_create','image_load','system_log'].includes(kind)) return true;
  if (['windows','sysmon'].includes(p.source) && kind==='process_exec') {
    const process=String(f.process_name||'').toLowerCase().replaceAll('/','\\'), cmd=String(f.command_line||'').trim().replace(/^"+|"+$/g,'').toLowerCase();
    return ['c:\\windows\\system32\\cmd.exe','c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe'].includes(process) && ['',process,'cmd.exe','powershell.exe'].includes(cmd);
  }
  return false;
}
export function screening(ev, history={total:0,suppressed:0,escalated:0}) {
  const {criticality}=scopedContext(ev);
  const modifier=history.total>=5 && !ev.fields._telemetry ? 1-.5*history.suppressed/history.total : 1;
  const score=Math.min(10,Math.max(0,ev.severity*criticality*modifier));
  if (routine(ev)) return {decision:'suppress',score,rationale:'Routine telemetry observation: no detection or correlation signal; retained in this demo'};
  if (score>=7) return {decision:'escalate',score,rationale:`score ${score.toFixed(1)} >= 7 (severity ${ev.severity}, asset criticality ${criticality})`};
  if (score<3 && history.total>=5 && !history.escalated && !ev.fields._telemetry) return {decision:'suppress',score,rationale:`score ${score.toFixed(1)} < 3; signature seen ${history.total}x, always benign, never overruled`};
  return {decision:'ambiguous',score};
}
