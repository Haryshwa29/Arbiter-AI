"""Explicit Windows UAC relaunch of the local packaged dashboard."""
import base64
import ctypes
import os
from pathlib import Path
import subprocess
import sys


def is_elevated():
    return bool(ctypes.windll.shell32.IsUserAnAdmin()) if os.name == "nt" else False


def ps_quote(value):
    return "'" + str(value).replace("'", "''") + "'"


def request_elevation(argv, port):
    """Only server-owned arguments are accepted. UAC approval is required."""
    if os.name != "nt" or is_elevated():
        raise ValueError("elevation is unavailable or already granted")
    executable = Path(sys.executable).resolve()
    arguments = subprocess.list2cmdline(argv)
    # The elevated helper waits for a graceful shutdown before reusing SQLite.
    script = f"""
 $deadline = (Get-Date).AddSeconds(150)
 do {{
   Start-Sleep -Milliseconds 500
   $listener = Get-Process -Id {os.getpid()} -ErrorAction SilentlyContinue
 }} while ($listener -and (Get-Date) -lt $deadline)
 if ($listener) {{ exit 1 }}
 Start-Process -FilePath {ps_quote(executable)} -ArgumentList {ps_quote(arguments)} -WorkingDirectory {ps_quote(Path.cwd())} -WindowStyle Hidden
"""
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    launcher = f"try {{ Start-Process -FilePath powershell.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '-NoProfile','-EncodedCommand','{encoded}' -ErrorAction Stop | Out-Null }} catch {{ exit 1 }}"
    try:
        result = subprocess.run(["powershell.exe", "-NoProfile", "-Command", launcher],
            capture_output=True, timeout=60, creationflags=subprocess.CREATE_NO_WINDOW)
    except subprocess.TimeoutExpired:
        raise ValueError("Windows permission request timed out") from None
    if result.returncode:
        raise ValueError("Windows permission request was cancelled or failed")
