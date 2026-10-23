"""Explicit local enforcement scope and a TTL-native Linux adapter."""
import ipaddress
import json
import platform
import shutil
import subprocess
import uuid


class ContainmentScope:
    """Opt-in target networks plus never-block management/service networks."""

    def __init__(self, allowed, protected):
        self.allowed = tuple(ipaddress.ip_network(n, strict=True) for n in allowed)
        self.protected = tuple(ipaddress.ip_network(n, strict=True) for n in protected)
        if not self.allowed or not self.protected:
            raise ValueError("explicit allowed and protected networks are required")
        if any(n.prefixlen == 0 for n in self.allowed):
            raise ValueError("a default route is not a containment scope")

    def permits(self, target):
        try:
            ip = ipaddress.ip_address(target)
        except ValueError:
            return False
        if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
            return False
        if getattr(ip, "ipv4_mapped", None):
            return False
        if any(ip in n for n in self.protected):
            return False
        matches = [n for n in self.allowed if ip in n]
        if not matches:
            return False
        # Network/broadcast addresses cannot identify one remote host.
        return any(ip.version == 6 or n.prefixlen >= 31 or
                   ip not in (n.network_address, n.broadcast_address) for n in matches)


class LinuxFirewall:
    """One owned table per action. Kernel set expiry survives agent shutdown.

    No system ruleset flush, shell, forwarded-traffic policy or permanent rule.
    A timed-out element leaves empty accept-policy chains, removed on undo.
    """
    def __init__(self, executable=None):
        self.executable = executable or shutil.which("nft")

    @staticmethod
    def table(action_id):
        return "arbiter_" + uuid.UUID(action_id).hex

    def run(self, arguments, script=None):
        if platform.system() != "Linux" or not self.executable:
            raise ValueError("Linux nftables is required")
        result = subprocess.run([self.executable, *arguments], input=script,
                                capture_output=True, text=True, timeout=15)
        if result.returncode:
            raise ValueError("nftables operation failed; check NET_ADMIN and network namespace")
        return result.stdout

    def block(self, action_id, target):
        name = self.table(action_id)
        address = ipaddress.ip_address(target)
        family, kind = ("ip", "ipv4_addr") if address.version == 4 else ("ip6", "ipv6_addr")
        # create (not add) refuses a pre-existing name. One atomic transaction
        # installs both chains and the finite-lifetime element.
        script = f"""create table inet {name}
add set inet {name} peer {{ type {kind}; flags timeout; timeout 300s; }}
add element inet {name} peer {{ {address} timeout 300s }}
add chain inet {name} ingress {{ type filter hook input priority -10; policy accept; }}
add chain inet {name} egress {{ type filter hook output priority -10; policy accept; }}
add rule inet {name} ingress {family} saddr @peer counter drop
add rule inet {name} egress {family} daddr @peer counter drop
"""
        self.run(["-f", "-"], script)

    def tables(self):
        data = json.loads(self.run(["-j", "list", "tables"]))
        return {item["table"]["name"] for item in data["nftables"] if
                "table" in item and item["table"].get("family") == "inet"}

    def active(self, action_id, target):
        name = self.table(action_id)
        address = str(ipaddress.ip_address(target))
        if name not in self.tables():
            return False
        data = json.loads(self.run(["-j", "list", "set", "inet", name, "peer"]))
        for item in data["nftables"]:
            for element in item.get("set", {}).get("elem", []):
                if isinstance(element, str) and element == address:
                    return True
                if isinstance(element, dict):
                    value = element.get("elem", element)
                    if value.get("val") == address and value.get("expires", 1) > 0:
                        return True
        return False

    def undo(self, action_id):
        name = self.table(action_id)
        if name in self.tables():
            self.run(["delete", "table", "inet", name])

    def removed(self, action_id):
        return self.table(action_id) not in self.tables()


def local_firewall():
    if platform.system() == "Windows":
        from .protection import WindowsFirewall
        return WindowsFirewall()
    if platform.system() == "Linux":
        return LinuxFirewall()
    raise ValueError("local containment supports Windows and Linux")
