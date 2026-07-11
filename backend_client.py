"""
backend_client.py — HTTP client for DRM Guard backend API.

This module handles all communication between the desktop app and the
FastAPI backend server (Phase 3 integration).

The client is intentionally synchronous (using requests) so it can be
called cleanly from worker threads inside the Tkinter app.
"""

from __future__ import annotations

import base64
import json
import os
import socket
import uuid
from dataclasses import dataclass, field
from typing import Optional

try:
    import requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False


# ─── Session state (held in memory, never persisted to disk) ──────────────────

@dataclass
class ServerSession:
    """Holds the connected server URL and the creator's JWT token."""
    base_url:   str  = ""
    token:      str  = ""
    user_email: str  = ""
    user_id:    str  = ""
    connected:  bool = False

    def auth_headers(self) -> dict:
        return {"Authorization": f"Bearer {self.token}"}

    def clear(self):
        self.token      = ""
        self.user_email = ""
        self.user_id    = ""
        self.connected  = False

    @property
    def url(self) -> str:
        return self.base_url.rstrip("/")


# Global singleton session (shared across the entire desktop app session)
_session = ServerSession()


def get_session() -> ServerSession:
    return _session


# ─── Connectivity check ──────────────────────────────────────────────────────

def check_connectivity(base_url: str, timeout: int = 4) -> bool:
    """Ping the /health endpoint. Returns True if server is reachable."""
    if not _HAS_REQUESTS:
        raise RuntimeError("requests library not installed. Run: pip install requests")
    try:
        r = requests.get(f"{base_url.rstrip('/')}/health", timeout=timeout)
        return r.status_code == 200
    except Exception:
        return False


# ─── Auth ────────────────────────────────────────────────────────────────────

def login(base_url: str, email: str, password: str) -> ServerSession:
    """
    Login to the DRM Guard backend.
    On success, populates and returns the global session.
    On failure, raises RuntimeError with the server's error message.
    """
    if not _HAS_REQUESTS:
        raise RuntimeError("requests library not installed. Run: pip install requests")

    url = f"{base_url.rstrip('/')}/auth/login"
    try:
        r = requests.post(url, json={"email": email, "password": password}, timeout=8)
    except requests.exceptions.ConnectionError:
        raise RuntimeError(f"Cannot connect to server at {base_url}.\nIs the server running?")
    except requests.exceptions.Timeout:
        raise RuntimeError("Connection timed out. Check the server URL.")

    if r.status_code == 200:
        data = r.json()
        _session.base_url   = base_url.rstrip("/")
        _session.token      = data["access_token"]
        _session.connected  = True

        # Fetch profile to get email + id
        me = requests.get(
            f"{_session.url}/auth/me",
            headers=_session.auth_headers(),
            timeout=5,
        )
        if me.status_code == 200:
            profile = me.json()
            _session.user_email = profile.get("email", email)
            _session.user_id    = profile.get("id", "")
        return _session

    elif r.status_code == 401:
        raise PermissionError("Incorrect email or password.")
    elif r.status_code == 403:
        raise PermissionError("Account is deactivated.")
    else:
        try:
            detail = r.json().get("detail", r.text)
        except Exception:
            detail = r.text
        raise RuntimeError(f"Login failed ({r.status_code}): {detail}")


def logout():
    """Clear the in-memory session."""
    _session.clear()


def register(base_url: str, email: str, password: str, full_name: str) -> dict:
    """Register a new creator account."""
    if not _HAS_REQUESTS:
        raise RuntimeError("requests library not installed.")
    url = f"{base_url.rstrip('/')}/auth/register"
    try:
        r = requests.post(url, json={
            "email": email, "password": password, "full_name": full_name
        }, timeout=8)
    except requests.exceptions.ConnectionError:
        raise RuntimeError(f"Cannot connect to server at {base_url}.")

    if r.status_code == 201:
        return r.json()
    elif r.status_code == 409:
        raise ValueError("An account with this email already exists.")
    else:
        try:
            detail = r.json().get("detail", r.text)
        except Exception:
            detail = r.text
        raise RuntimeError(f"Registration failed: {detail}")


# ─── File registration (Encrypt → Server) ────────────────────────────────────

def register_drm_file(
    aes_key_b64: str,
    iv_b64:      str,
    original_name: str,
    original_ext:  str,
    expiry_str:    str,           # "YYYY-MM-DD HH:MM"
    lock_type:     str,           # "MAC" | "IP" | "NONE"
    lock_identifier: Optional[str],
    watermark_text:  str = "",
    watermark_opacity: int = 0,
    file_size_bytes: Optional[int] = None,
) -> str:
    """
    Register a newly encrypted file with the backend.
    Sends the AES key + IV to the server for storage.
    Returns the file_id (UUID) assigned by the server.
    """
    if not _session.connected:
        raise RuntimeError("Not connected to server. Please log in first.")

    # Convert "YYYY-MM-DD HH:MM" → ISO 8601 for the API
    from datetime import datetime
    expiry_dt = datetime.strptime(expiry_str, "%Y-%m-%d %H:%M")
    expiry_iso = expiry_dt.isoformat()

    payload = {
        "original_name":     original_name,
        "original_ext":      original_ext,
        "file_size_bytes":   file_size_bytes,
        "lock_type":         lock_type,
        "lock_identifier":   lock_identifier,
        "expiry_dt":         expiry_iso,
        "watermark_text":    watermark_text,
        "watermark_opacity": watermark_opacity,
        "aes_key_b64":       aes_key_b64,
        "iv_b64":            iv_b64,
    }

    try:
        r = requests.post(
            f"{_session.url}/files/",
            json=payload,
            headers=_session.auth_headers(),
            timeout=10,
        )
    except requests.exceptions.ConnectionError:
        raise RuntimeError("Lost connection to server during file registration.")

    if r.status_code == 201:
        return r.json()["id"]
    else:
        try:
            detail = r.json().get("detail", r.text)
        except Exception:
            detail = r.text
        raise RuntimeError(f"File registration failed: {detail}")


# ─── Key request (Decrypt ← Server) ──────────────────────────────────────────

def request_decryption_key(file_id: str, server_url: str) -> dict:
    """
    Request the AES decryption key from the backend.
    Sends: file_id + MAC address.
    Returns a dict with: aes_key_b64, iv_b64, watermark_text, watermark_opacity, original_ext, expiry_dt.

    Raises:
      PermissionError  — if revoked / expired / MAC mismatch
      RuntimeError     — if server unreachable or file not found
    """
    if not _HAS_REQUESTS:
        raise RuntimeError("requests library not installed. Run: pip install requests")

    mac = _get_mac()
    ip  = _get_ip()
    url = f"{server_url.rstrip('/')}/kms/request-key"

    try:
        r = requests.post(url, json={
            "file_id":       file_id,
            "requester_mac": mac,
            "requester_ip":  ip,
            "user_agent":    "DRMGuard-Desktop/4.0",
        }, timeout=8)
    except requests.exceptions.ConnectionError:
        raise RuntimeError(
            f"Cannot reach the DRM server at:\n{server_url}\n\n"
            "Check your internet connection and ensure the server is running."
        )
    except requests.exceptions.Timeout:
        raise RuntimeError("Key request timed out. The server may be busy.")

    if r.status_code == 200:
        return r.json()
    elif r.status_code == 403:
        try:
            detail = r.json().get("detail", "Access denied.")
        except Exception:
            detail = "Access denied."
        raise PermissionError(detail)
    elif r.status_code == 404:
        raise RuntimeError(
            f"File ID '{file_id}' not found on server.\n"
            "The file may not have been registered, or the server URL is wrong."
        )
    else:
        try:
            detail = r.json().get("detail", r.text)
        except Exception:
            detail = r.text
        raise RuntimeError(f"Key request failed ({r.status_code}): {detail}")


# ─── Dashboard helpers ────────────────────────────────────────────────────────

def get_my_files() -> list[dict]:
    """Fetch the creator's file list from the backend."""
    if not _session.connected:
        return []
    try:
        r = requests.get(
            f"{_session.url}/files/",
            headers=_session.auth_headers(),
            timeout=8,
        )
        return r.json() if r.status_code == 200 else []
    except Exception:
        return []


def revoke_file(file_id: str) -> bool:
    """Instantly revoke access to a file. Returns True on success."""
    if not _session.connected:
        return False
    try:
        r = requests.patch(
            f"{_session.url}/files/{file_id}/revoke",
            headers=_session.auth_headers(),
            timeout=8,
        )
        return r.status_code == 200
    except Exception:
        return False


def get_audit_logs(file_id: Optional[str] = None, limit: int = 100) -> list[dict]:
    """Fetch audit logs from the backend (all files or one file)."""
    if not _session.connected:
        return []
    try:
        url = (f"{_session.url}/audit/{file_id}"
               if file_id else f"{_session.url}/audit/")
        r = requests.get(
            url,
            headers=_session.auth_headers(),
            params={"limit": limit},
            timeout=8,
        )
        data = r.json()
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return data.get("entries", [])
        return []
    except Exception:
        return []


# ─── Helpers (duplicated to avoid importing drm_guard circular) ───────────────

def _get_mac() -> str:
    return ":".join(("%012X" % uuid.getnode())[i:i+2] for i in range(0, 12, 2))


def _get_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"
