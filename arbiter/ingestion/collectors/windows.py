"""Read Windows event XML using the built-in wevtutil, never a shell."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET

from ..base import Collector
from ..normalization import windows

CHANNELS = ("Security", "System", "Application")
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"


def channel_installed(channel):
    """A registered channel may exist even when Windows cannot open its logger."""
    if os.name != "nt":
        return False
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels" + "\\" + channel):
            return True
    except OSError:
        return False


def parse_xml(text: str) -> list[dict]:
    if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper() or len(text) > 8 * 1024 * 1024:
        raise ValueError("unsafe or oversized Windows XML")
    # wevtutil may concatenate Event elements without a single root.
    text = text.strip().lstrip("\ufeff")
    if not text:
        return []
    root = ET.fromstring("<Events>" + text + "</Events>")
    result = []
    for element in root.iter():
        element.tag = element.tag.split("}")[-1]
    for element in root.iter("Event"):
        system = element.find("System")
        if system is None:
            continue
        values = {e.tag: e.text or "" for e in system}
        values["TimeCreated"] = system.find("TimeCreated").get("SystemTime", "") if system.find("TimeCreated") is not None else ""
        provider = system.find("Provider")
        values["Provider"] = provider.get("Name", "") if provider is not None else ""
        data = {e.get("Name", f"field_{n}"): e.text or "" for n, e in enumerate(element.findall("EventData/Data"))}
        user_data = element.find("UserData")
        if user_data is not None:
            data.update({e.tag: e.text or "" for e in user_data.iter() if len(e) == 0})
        result.append({"System": values, "EventData": data,
                       "Message": element.findtext("RenderingInfo/Message", ""),
                       "xml": ET.tostring(element, encoding="unicode")})
    return result


class WindowsCollector(Collector):
    interval = 3.0

    def __init__(self, config, checkpoint=None):
        super().__init__(config, checkpoint)
        self.channels = [SYSMON_CHANNEL] if config["adapter"] == "sysmon" else config.get("channels", list(CHANNELS))
        self.executable = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "wevtutil.exe"

    def _query(self, channel, cursor=None, newest=False):
        if os.name != "nt":
            raise OSError("Windows only")
        args = [str(self.executable), "qe", channel, "/f:xml", "/uni:true",
                "/rd:true" if newest else "/rd:false", "/c:1" if newest else "/c:200"]
        if cursor is not None:
            args.append(f"/q:*[System[(EventRecordID > {int(cursor)})]]")
        try:
            result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=15, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except subprocess.TimeoutExpired as exc:
            raise OSError("event query timed out") from exc
        if result.returncode:
            raise OSError("event channel unavailable")
        raw = result.stdout
        return parse_xml(raw.decode("utf-16" if raw.startswith((b'\xff\xfe', b'\xfe\xff')) or b'\x00' in raw[:100] else "utf-8"))

    def collect(self):
        self.error = ""
        available = 0
        for channel in self.channels:
            try:
                newest = self._query(channel, newest=True)
                latest = int(newest[0]["System"]["EventRecordID"]) if newest else 0
                key = channel
                if key not in self.checkpoint:
                    self.checkpoint[key] = 0 if self.config.get("read_existing", False) else latest
                if latest < self.checkpoint[key]:
                    self.checkpoint[key] = 0  # log cleared/rotated
                available += 1
                for raw in self._query(channel, self.checkpoint[key]):
                    yield raw
                    self.checkpoint[key] = int(raw["System"]["EventRecordID"])
            except OSError:
                self.errors += 1
                self.error = f"{channel}: unavailable or access denied"
        self.status = "Connected" if available else (
            "Not detected" if self.config["adapter"] == "sysmon" and not channel_installed(SYSMON_CHANNEL) else "Error")

    def normalize(self, raw):
        return windows(raw, self.config["adapter"])
