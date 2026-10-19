export default {
  "assets": {
    "db-prod-01": 2,
    "web-prod-01": 1.6,
    "ci-runner-01": 0.8,
    "dev-laptop-42": 0.5
  },
  "facts": [
    {
      "text": "backups run at 02:00 — nightly IO spike is normal",
      "host": "db-prod-01",
      "event_types": [
        "io_anomaly"
      ]
    },
    {
      "text": "CI runner process churn is expected",
      "host": "ci-runner-01",
      "event_types": [
        "process_anomaly",
        "process_burst",
        "process_exec"
      ]
    }
  ],
  "constants": {
    "_SENSITIVE_PORTS": [
      "22",
      "23",
      "3389",
      "5432",
      "3306",
      "1433",
      "6379",
      "27017",
      "9200",
      "5984"
    ],
    "_SENSITIVE_SVC": [
      "rdp",
      "ssh",
      "postgres",
      "mysql",
      "mssql",
      "redis",
      "mongo",
      "database",
      "db ",
      "winrm",
      "smb",
      "telnet"
    ],
    "_BROAD_SCOPE": [
      "0.0.0.0/0",
      "0.0.0.0",
      "::/0",
      "allow all",
      "from any",
      "any source",
      "all ports",
      "anywhere",
      "to the internet",
      "public internet",
      "0.0.0.0/1",
      "/1 ",
      "/0 "
    ],
    "_INTERNAL": [
      "10.",
      "192.168.",
      "172.16.",
      "172.17.",
      "172.18.",
      "172.19.",
      "172.2",
      "172.30.",
      "172.31.",
      "nas-01",
      "known backup host",
      "internal"
    ],
    "_EXTERNAL_SINKS": [
      "dropbox",
      "mega.nz",
      "pastebin",
      "anonfiles",
      "transfer.sh",
      "s3.amazonaws.com",
      "blob.core",
      "storage.googleapis",
      "wetransfer",
      "file.io",
      "0x0.st"
    ],
    "_LOLBINS": [
      "certutil",
      "bitsadmin",
      "mshta",
      "regsvr32",
      "rundll32",
      "wmic",
      "cscript",
      "wscript",
      "installutil",
      "msbuild",
      "powershell",
      "psexec"
    ],
    "_LOLBIN_CTX": [
      "urlcache",
      "-urlcache",
      "http://",
      "https://",
      "download",
      "-enc",
      "-encodedcommand",
      "encoded",
      "downloadstring",
      "iex",
      "/transfer",
      "process call create",
      "javascript:",
      "scrobj",
      ".hta",
      "-nop",
      "-w hidden",
      "hidden",
      "bypass",
      "base64",
      "unusual",
      "-split -f"
    ],
    "_PRIV_MARKER_GROUPS": [
      [
        "uid 0",
        "uid0"
      ],
      [
        "wheel"
      ],
      [
        "sudo",
        "sudoers"
      ],
      [
        "root"
      ],
      [
        "admin",
        "administrators",
        "administratoraccess",
        "domain admin"
      ],
      [
        "privileged",
        "elevated"
      ]
    ]
  },
  "rules": [
    {
      "code": "NON_SUPPRESSIBLE_TOOL_FINDING",
      "name": "high_priority_tool_finding",
      "reason": "a high-priority security-tool finding requires review; benign history or model confidence cannot dismiss it"
    },
    {
      "code": "NON_SUPPRESSIBLE_EXPOSURE",
      "name": "internet_exposure",
      "reason": "exposing a sensitive service to a broad/public scope is never a benign maintenance side-effect"
    },
    {
      "code": "NON_SUPPRESSIBLE_CRED_ACCESS",
      "name": "credential_access",
      "reason": "access to credential material (shadow/SAM/ntds/lsass) is always escalated"
    },
    {
      "code": "NON_SUPPRESSIBLE_PRIVESC",
      "name": "privilege_expansion",
      "reason": "creation or elevation of a privileged account (uid-0/wheel/sudo/admin) is always escalated"
    },
    {
      "code": "NON_SUPPRESSIBLE_DOWNLOAD_EXEC",
      "name": "download_execute",
      "reason": "download-and-execute (pipe-to-shell or fetch-then-run) is never benign"
    },
    {
      "code": "NON_SUPPRESSIBLE_INTEGRITY",
      "name": "integrity_change",
      "reason": "a binary/integrity change not confirmed by the package manager can't be excused by a maintenance window"
    },
    {
      "code": "NON_SUPPRESSIBLE_EXFIL",
      "name": "data_exfil",
      "reason": "data leaving to an external or file-sharing destination is never routine sync/backup traffic"
    },
    {
      "code": "NON_SUPPRESSIBLE_LOLBIN",
      "name": "lolbin",
      "reason": "a living-off-the-land binary (certutil/wmic/rundll32/mshta/powershell) used to download or run code is escalated"
    },
    {
      "code": "NON_SUPPRESSIBLE_SUPPLYCHAIN",
      "name": "supply_chain",
      "reason": "a package install/postinstall script that reaches the network is a supply-chain risk"
    },
    {
      "code": "NON_SUPPRESSIBLE_RANSOMWARE",
      "name": "ransomware",
      "reason": "mass file rename/encryption is ransomware behaviour regardless of extension or how signed the binary looks"
    },
    {
      "code": "NON_SUPPRESSIBLE_IMPOSSIBLE_TRAVEL",
      "name": "impossible_travel",
      "reason": "one account authenticating from two locations in an impossible timeframe is account takeover, never routine maintenance"
    }
  ]
};
