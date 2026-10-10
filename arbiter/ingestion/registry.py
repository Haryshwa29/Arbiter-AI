"""Extensible catalog. Unimplemented sources are visible but cannot enable."""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
from pathlib import Path
import re

from .collectors.aws import AWSCollector
from .collectors.future import FutureCollector
from .collectors.osquery import OsqueryCollector
from .collectors.suricata import SuricataCollector
from .collectors.syslog import SyslogCollector
from .collectors.windows import CHANNELS, WindowsCollector


@dataclass(frozen=True)
class ConnectorSpec:
    name: str
    label: str
    category: str
    factory: type
    adapter: str
    defaults: dict
    implemented: bool = True
    description: str = ""


class Registry:
    def __init__(self):
        self.specs: dict[str, ConnectorSpec] = {}

    def register(self, spec):
        if spec.name in self.specs:
            raise ValueError("duplicate connector")
        self.specs[spec.name] = spec

    def get(self, name):
        if name not in self.specs:
            raise ValueError("unknown connector")
        return self.specs[name]

    def validate(self, name, config):
        spec = self.get(name)
        if not spec.implemented:
            raise ValueError("connector is Coming Soon")
        if not isinstance(config, dict) or set(config) - set(spec.defaults):
            raise ValueError("unsupported configuration field; credentials are not accepted")
        result = {**spec.defaults, **config}
        if len(str(result)) > 8192:
            raise ValueError("configuration too large")
        for key in {"read_existing"} & set(result):
            if not isinstance(result[key], bool):
                raise ValueError("read_existing must be boolean")
        if "channels" in result:
            if not isinstance(result["channels"], list) or not result["channels"] or any(c not in CHANNELS for c in result["channels"]):
                raise ValueError("choose Security, System or Application channels")
        if "path" in result:
            if not isinstance(result["path"], str) or not Path(result["path"]).is_absolute():
                raise ValueError("absolute local path required")
            if name == "osquery" and Path(result["path"]).name.lower() not in {"osqueryi", "osqueryi.exe"}:
                raise ValueError("select the installed osqueryi executable")
        if "interval" in result:
            if isinstance(result["interval"], bool) or not isinstance(result["interval"], (int, float)) or not 60 <= result["interval"] <= 86400:
                raise ValueError("inventory interval must be 60–86400 seconds")
        if "region" in result:
            if not isinstance(result["region"], str) or not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-\d", result["region"]):
                raise ValueError("valid AWS region required")
            for key in ("profile", "detector_id"):
                if key in result and (not isinstance(result[key], str) or len(result[key]) > 128 or not re.fullmatch(r"[\w.-]*", result[key])):
                    raise ValueError("invalid AWS profile or detector ID")
        if name == "syslog":
            host = ipaddress.ip_address(result["host"])
            private = host.version == 4 and (host.is_loopback or any(host in ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")))
            if not private:
                raise ValueError("syslog binding must be loopback or an explicit private IPv4 address")
            if isinstance(result["port"], bool) or not isinstance(result["port"], int) or not 1024 <= result["port"] <= 65535:
                raise ValueError("syslog port must be 1024–65535")
            senders = result["allowed_senders"]
            if not isinstance(senders, list) or not 1 <= len(senders) <= 50:
                raise ValueError("sender allowlist required")
            for network in senders:
                net = ipaddress.ip_network(network)
                if net.version != 4 or net.prefixlen == 0:
                    raise ValueError("specific IPv4 sender networks required")
        return result

    def create(self, name, config, checkpoint=None):
        spec = self.get(name)
        valid = self.validate(name, config)
        return spec.factory({**valid, "adapter": spec.adapter}, checkpoint)


def default_registry():
    registry = Registry()
    specs = [
        ConnectorSpec("windows", "Windows Events", "Endpoints", WindowsCollector, "windows",
            {"channels": ["Security", "System", "Application"], "read_existing": False},
            description="Read Windows logs; Security may require Event Log Readers access."),
        ConnectorSpec("sysmon", "Sysmon", "Endpoints", WindowsCollector, "sysmon", {"read_existing": False},
            description="Read an installed Sysmon operational channel. No installation is performed."),
        ConnectorSpec("osquery", "osquery", "Endpoints", OsqueryCollector, "osquery", {"path": "", "interval": 300},
            description="Installed osqueryi path; fixed read-only inventory queries."),
        ConnectorSpec("suricata", "Suricata", "Network", SuricataCollector, "suricata", {"path": ""},
            description="Absolute path to an existing EVE JSON file; read from beginning on first enable."),
        ConnectorSpec("syslog", "Syslog", "Other", SyslogCollector, "syslog",
            {"host": "127.0.0.1", "port": 5514, "allowed_senders": ["127.0.0.0/8"]},
            description="UDP RFC3164/5424; private bind requires a sender allowlist. No TLS in MVP."),
        ConnectorSpec("cloudtrail", "AWS CloudTrail", "Cloud", AWSCollector, "cloudtrail", {"region": "us-east-1", "profile": ""},
            description="Opt-in regional management event history using the AWS SDK credential chain."),
        ConnectorSpec("guardduty", "AWS GuardDuty", "Cloud", AWSCollector, "guardduty",
            {"region": "us-east-1", "profile": "", "detector_id": ""},
            description="Opt-in finding retrieval; existing detector required."),
    ]
    for name, label, category in [("zeek", "Zeek", "Network"), ("azure", "Azure", "Cloud"),
        ("gcp", "GCP", "Cloud"), ("vpc_flow", "AWS VPC Flow Logs", "Cloud"),
        ("security_hub", "AWS Security Hub", "Cloud"), ("cloudwatch", "AWS CloudWatch Logs", "Cloud")]:
        specs.append(ConnectorSpec(name, label, category, FutureCollector, name, {}, False,
                                   "Adapter foundation only; transport not implemented."))
    for spec in specs:
        registry.register(spec)
    return registry
