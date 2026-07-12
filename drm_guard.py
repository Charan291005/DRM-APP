"""
DRM Guard v5.0 -- Phase 3: Server Integration
=============================================
Security:
  - In-memory decryption (bytes NEVER touch disk)
  - AES-256-CBC + PKCS7 padding
  - Dual-mode: LOCAL (offline) and SERVER (online KMS)
  - SERVER mode: AES key stored on backend, never in the .drm file
  - Backend validates MAC + expiry + revocation before issuing key

UI:
  - Slate + Cyan dark palette (Linear / Vercel / Notion inspired)
  - 4-section sidebar: Encrypt / Decrypt / Audit Log / Settings
  - SettingsPage: server login, connection status, account info
  - Mode badge on Encrypt/Decrypt pages (LOCAL / SERVER)
"""

import os
import io
import sys
import uuid
import hashlib
import platform
import csv
import threading
import socket
import base64
from datetime import datetime

import tkinter as tk
from tkinter import filedialog, ttk
from tkcalendar import Calendar
from PIL import Image, ImageTk, ImageDraw, ImageFont
import fitz
from Crypto.Cipher import AES

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    _HAS_DND = True
except ImportError:
    _HAS_DND = False

_HAS_BACKEND = False


# ---------------------------------------------------------------------------
# Anti-Screenshot  (Windows only)
# ---------------------------------------------------------------------------
def _apply_anti_screenshot(hwnd):
    if platform.system() == "Windows":
        try:
            import ctypes
            WDA_EXCLUDEFROMCAPTURE = 0x00000011
            ctypes.windll.user32.SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE)
        except Exception:
            pass
# ---------------------------------------------------------------------------
# Global OS-Level Keyboard Hook
# ---------------------------------------------------------------------------
_hook_id = None
_hook_proc_ref = None

def _start_keyboard_hook():
    global _hook_id, _hook_proc_ref
    if platform.system() != "Windows":
        return

    try:
        import ctypes
        from ctypes import wintypes
        import threading
        
        user32 = ctypes.windll.user32
        user32.CallNextHookEx.argtypes = [ctypes.c_void_p, ctypes.c_int, wintypes.WPARAM, wintypes.LPARAM]
        user32.SetWindowsHookExW.argtypes = [ctypes.c_int, ctypes.c_void_p, wintypes.HINSTANCE, wintypes.DWORD]
        user32.SetWindowsHookExW.restype = ctypes.c_void_p
        user32.UnhookWindowsHookEx.argtypes = [ctypes.c_void_p]

        WH_KEYBOARD_LL = 13
        VK_SNAPSHOT = 0x2C
        VK_C = 0x43
        VK_P = 0x50
        VK_S = 0x53
        VK_LWIN = 0x5B
        VK_RWIN = 0x5C
        VK_SHIFT = 0x10
        VK_CONTROL = 0x11
        
        WM_KEYDOWN = 0x0100
        WM_SYSKEYDOWN = 0x0104

        @ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_int, wintypes.WPARAM, wintypes.LPARAM)
        def hook_proc(nCode, wParam, lParam):
            if nCode >= 0 and (wParam == WM_KEYDOWN or wParam == WM_SYSKEYDOWN):
                vk_code = ctypes.cast(lParam, ctypes.POINTER(ctypes.c_int))[0]
                
                # Print Screen
                if vk_code == VK_SNAPSHOT:
                    return 1
                    
                # Win + Shift + S (Snipping Tool)
                if vk_code == VK_S:
                    lwin = user32.GetAsyncKeyState(VK_LWIN) & 0x8000
                    rwin = user32.GetAsyncKeyState(VK_RWIN) & 0x8000
                    shift = user32.GetAsyncKeyState(VK_SHIFT) & 0x8000
                    if (lwin or rwin) and shift:
                        return 1
                        
                # Ctrl + C or Ctrl + P
                if vk_code in (VK_C, VK_P):
                    ctrl = user32.GetAsyncKeyState(VK_CONTROL) & 0x8000
                    if ctrl:
                        return 1

            return user32.CallNextHookEx(None, nCode, wParam, lParam)

        _hook_proc_ref = hook_proc

        def _hook_thread():
            global _hook_id
            _hook_id = user32.SetWindowsHookExW(WH_KEYBOARD_LL, _hook_proc_ref, None, 0)
            msg = wintypes.MSG()
            while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
                user32.TranslateMessage(ctypes.byref(msg))
                user32.DispatchMessageW(ctypes.byref(msg))

        t = threading.Thread(target=_hook_thread, daemon=True)
        t.start()
    except Exception as e:
        print("Failed to start keyboard hook:", e)

def _stop_keyboard_hook():
    global _hook_id
    if _hook_id and platform.system() == "Windows":
        try:
            import ctypes
            ctypes.windll.user32.UnhookWindowsHookEx(_hook_id)
            _hook_id = None
        except Exception:
            pass

# ---------------------------------------------------------------------------
# Aggressive Process Monitor (Anti-Capture)
# ---------------------------------------------------------------------------
_monitor_running = False

def _anti_capture_monitor():
    global _monitor_running
    if platform.system() != "Windows":
        return
    import time
    import subprocess
    
    blacklisted = {
        "snippingtool.exe", 
        "screenclippinghost.exe", 
        "lightshot.exe", 
        "sharex.exe",
        "obs64.exe",
        "obs32.exe",
        "camtasia.exe",
        "greenshot.exe"
    }
    
    while _monitor_running:
        try:
            output = subprocess.check_output(
                ["tasklist", "/FO", "CSV", "/NH"], 
                creationflags=subprocess.CREATE_NO_WINDOW
            ).decode('utf-8', errors='ignore').lower()
            
            for line in output.splitlines():
                if not line: continue
                proc = line.split('","')[0].strip('"')
                if proc in blacklisted:
                    subprocess.run(
                        ["taskkill", "/F", "/IM", proc], 
                        creationflags=subprocess.CREATE_NO_WINDOW, 
                        stdout=subprocess.DEVNULL, 
                        stderr=subprocess.DEVNULL
                    )
        except Exception:
            pass
        time.sleep(2)

def _start_monitor():
    global _monitor_running
    if not _monitor_running:
        _monitor_running = True
        import threading
        threading.Thread(target=_anti_capture_monitor, daemon=True).start()

def _stop_monitor():
    global _monitor_running
    _monitor_running = False
# ===========================================================================
# DESIGN TOKENS  -- Slate + Cyan palette
# ===========================================================================
BG_BASE     = "#0a0a0f"
BG_SURFACE  = "#111118"
BG_CARD     = "#16161e"
BG_CARD2    = "#1c1c26"
BG_INPUT    = "#12121a"
BDR_SUB     = "#22222e"
BDR_MUTED   = "#2e2e3e"

ACCENT      = "#06b6d4"
ACCENT_DARK = "#0891b2"
ACCENT_DIM  = "#0c2a32"

SUCCESS     = "#10b981"
SUCCESS_DIM = "#052e1c"
WARN        = "#f59e0b"
WARN_DIM    = "#2d1e02"
ERROR       = "#ef4444"
ERROR_DIM   = "#2d0a0a"

TEXT_1      = "#f1f5f9"
TEXT_2      = "#94a3b8"
TEXT_3      = "#4b5563"
TEXT_ACCENT = "#22d3ee"

SIDEBAR_W   = 234
HEADER_H    = 52

FONT_BRAND  = ("Segoe UI", 14, "bold")
FONT_TITLE  = ("Segoe UI", 20, "bold")
FONT_SUB    = ("Segoe UI", 10)
FONT_LABEL  = ("Segoe UI", 9, "bold")
FONT_BODY   = ("Segoe UI", 10)
FONT_MONO   = ("Consolas", 9)
FONT_SMALL  = ("Segoe UI", 8)


# ===========================================================================
# CRYPTO UTILITIES
# ===========================================================================
def _pad(data: bytes) -> bytes:
    length = 16 - (len(data) % 16)
    return data + bytes([length] * length)


def _unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    return data[:-pad_len]


def get_mac() -> str:
    return ":".join(("%012X" % uuid.getnode())[i:i+2] for i in range(0, 12, 2))


def get_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _derive_key(identifier: str, expiry: str, password: str) -> bytes:
    raw = f"{identifier}||{expiry}||{password}".encode()
    return hashlib.sha256(raw).digest()


def _password_hash(password: str) -> str:
    salt = b"drmguard_v4_salt"
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000).hex()


def encrypt_file(path: str, expiry: str, identifier: str,
                 password: str, watermark_text: str = "",
                 watermark_opacity: int = 0,
                 progress_callback=None, out_path: str = None) -> str:
    key        = _derive_key(identifier, expiry, password)
    iv         = os.urandom(16)
    cipher     = AES.new(key, AES.MODE_CBC, iv)
    ext        = os.path.splitext(path)[1][1:]
    pw_hash    = _password_hash(password)
    wm_b64     = base64.b64encode(watermark_text.encode()).decode()
    header     = f"{expiry}|{identifier}|{ext}|{pw_hash}|{wm_b64}|{watermark_opacity}".encode()
    
    if not out_path:
        out_path = os.path.splitext(path)[0] + ".drm"
    
    total_size = os.path.getsize(path)
    processed = 0

    with open(out_path, "wb") as f_out:
        f_out.write(header + b"\n" + iv)
        with open(path, "rb") as f_in:
            while True:
                chunk = f_in.read(64 * 1024)
                if len(chunk) < 64 * 1024:
                    f_out.write(cipher.encrypt(_pad(chunk)))
                    processed += len(chunk)
                    if progress_callback: progress_callback(1.0)
                    break
                else:
                    f_out.write(cipher.encrypt(chunk))
                    processed += len(chunk)
                    if progress_callback and total_size > 0:
                        progress_callback(processed / total_size)
    return out_path


def decrypt_to_bytes(drm_path: str, provided_password: str):
    """LOCAL mode: fully in-memory decryption. Returns (bytes, ext, wm_text, wm_opacity)."""
    with open(drm_path, "rb") as f:
        header_bytes = f.readline().strip()
        iv           = f.read(16)
        ciphertext   = f.read()
    parts = header_bytes.decode().split("|")
    if len(parts) != 6:
        raise ValueError("Invalid or corrupted DRM header.")
    expiry_str, identifier, original_ext, pw_hash, wm_b64, wm_opacity_str = parts
    watermark_text    = base64.b64decode(wm_b64).decode()
    watermark_opacity = int(wm_opacity_str)
    if _password_hash(provided_password) != pw_hash:
        raise PermissionError("Incorrect password.")
    if datetime.now() > datetime.strptime(expiry_str, "%Y-%m-%d %H:%M"):
        raise PermissionError("This file has expired and can no longer be opened.")
    if identifier not in ("None", get_mac(), get_ip()):
        raise PermissionError(
            f"Access denied: file locked to a different device.\n"
            f"Expected: {identifier}\nYour MAC: {get_mac()}"
        )
    key    = _derive_key(identifier, expiry_str, provided_password)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plain  = _unpad(cipher.decrypt(ciphertext))
    return plain, original_ext, watermark_text, watermark_opacity


# ===========================================================================
# AUDIT LOG
# ===========================================================================
LOG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "drm_audit.csv")


def log_action(action, filename, identifier, expiry, status="OK"):
    exists = os.path.exists(LOG_PATH)
    with open(LOG_PATH, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if not exists:
            w.writerow(["Timestamp","Action","File","Identifier","Expiry","MAC","IP","Status"])
        w.writerow([datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    action, filename, identifier, expiry,
                    get_mac(), get_ip(), status])


def read_log(n=100):
    rows = []
    if os.path.exists(LOG_PATH):
        with open(LOG_PATH, newline="", encoding="utf-8") as f:
            r = csv.reader(f)
            next(r, None)
            rows = list(r)
    return rows[-n:]


# ===========================================================================
# WIDGET PRIMITIVES
# ===========================================================================

class Toast(tk.Toplevel):
    _KINDS = {
        "success": (SUCCESS, "v"),
        "error":   (ERROR,   "x"),
        "warn":    (WARN,    "!"),
        "info":    (ACCENT,  "i"),
    }

    def __init__(self, master, message, kind="info", duration=3400):
        super().__init__(master)
        self.overrideredirect(True)
        self.attributes("-topmost", True)
        self.configure(bg=BG_CARD2)
        color, icon = self._KINDS.get(kind, (ACCENT, "i"))
        tk.Frame(self, bg=color, width=3).pack(side="left", fill="y")
        body = tk.Frame(self, bg=BG_CARD2, padx=14, pady=10)
        body.pack(side="left")
        tk.Label(body, text=f"[{icon}]  {message}",
                 bg=BG_CARD2, fg=TEXT_1, font=FONT_BODY,
                 wraplength=300, justify="left").pack(anchor="w")
        self.update_idletasks()
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        w, h   = self.winfo_width(), self.winfo_height()
        self.geometry(f"+{sw-w-24}+{sh-h-60}")
        self.after(duration, self.destroy)


def toast(master, message, kind="info"):
    try:
        Toast(master, message, kind)
    except Exception:
        pass


class StyledEntry(tk.Entry):
    def __init__(self, parent, placeholder="", show_char=None, **kw):
        self._ph    = placeholder
        self._ph_on = False
        opts = dict(
            bg=BG_INPUT, fg=TEXT_1, insertbackground=ACCENT,
            relief="flat", font=FONT_BODY,
            highlightthickness=1, highlightbackground=BDR_MUTED,
            highlightcolor=ACCENT, bd=0,
        )
        if show_char:
            opts["show"] = show_char
        opts.update(kw)
        super().__init__(parent, **opts)
        if placeholder and not show_char:
            self._show_ph()
            self.bind("<FocusIn>",  self._clear_ph)
            self.bind("<FocusOut>", self._set_ph)

    def _show_ph(self):
        self.insert(0, self._ph)
        self.config(fg=TEXT_3)
        self._ph_on = True

    def _clear_ph(self, _=None):
        if self._ph_on:
            self.delete(0, "end")
            self.config(fg=TEXT_1)
            self._ph_on = False

    def _set_ph(self, _=None):
        if not self.get():
            self._show_ph()

    def get_value(self):
        return "" if self._ph_on else self.get()

    def set_value(self, v):
        self._ph_on = False
        self.config(fg=TEXT_1)
        self.delete(0, "end")
        self.insert(0, v)

    def clear(self):
        self.delete(0, "end")
        if self._ph:
            self._show_ph()


class GlassCard(tk.Frame):
    def __init__(self, parent, title=None, icon="", **kw):
        super().__init__(parent, bg=BG_CARD,
                         highlightthickness=1, highlightbackground=BDR_SUB, **kw)
        if title:
            hdr = tk.Frame(self, bg=BG_CARD)
            hdr.pack(fill="x", padx=16, pady=(14, 0))
            lbl_txt = f"[{icon}]  {title}" if icon else title
            tk.Label(hdr, text=lbl_txt, bg=BG_CARD, fg=TEXT_2, font=FONT_LABEL).pack(side="left")
            tk.Frame(self, bg=BDR_SUB, height=1).pack(fill="x", padx=16, pady=(10, 0))
        self.inner = tk.Frame(self, bg=BG_CARD)
        self.inner.pack(fill="both", expand=True, padx=16, pady=(12, 16))


class AccentButton(tk.Canvas):
    def __init__(self, parent, text, command=None, width=200, height=38, primary=True, **kw):
        try:
            bg = parent.cget("bg")
        except Exception:
            bg = BG_BASE
        kw.pop("bg", None)
        super().__init__(parent, width=width, height=height, bg=bg,
                         highlightthickness=0, bd=0, cursor="hand2", **kw)
        self._text    = text
        self._cmd     = command
        self._primary = primary
        self._btn_w, self._btn_h = width, height
        self._hovered = False
        self.bind("<Enter>",           self._enter)
        self.bind("<Leave>",           self._leave)
        self.bind("<ButtonPress-1>",   self._press)
        self.bind("<ButtonRelease-1>", self._release)
        self.after(5, self._draw)

    def _cols(self, press=False):
        if self._primary:
            if press:
                return ACCENT_DIM, TEXT_2
            return (ACCENT_DARK, "#000") if self._hovered else (ACCENT, "#000")
        else:
            if press:
                return BG_INPUT, TEXT_1
            return (BDR_MUTED, TEXT_1) if self._hovered else (BG_CARD2, TEXT_1)

    def _draw(self, press=False):
        self.delete("all")
        bg, fg = self._cols(press)
        r   = self._btn_h // 2
        pts = [
            r, 0, self._btn_w-r, 0, self._btn_w, 0, self._btn_w, r,
            self._btn_w, self._btn_h-r, self._btn_w, self._btn_h, self._btn_w-r, self._btn_h,
            r, self._btn_h, 0, self._btn_h, 0, self._btn_h-r, 0, r, 0, 0,
        ]
        self.create_polygon(pts, smooth=True, fill=bg)
        self.create_text(self._btn_w//2, self._btn_h//2, text=self._text,
                         fill=fg, font=("Segoe UI", 10, "bold"))

    def _enter(self, _):
        self._hovered = True
        self._draw()

    def _leave(self, _):
        self._hovered = False
        self._draw()

    def _press(self, _):
        self._draw(press=True)

    def _release(self, _):
        self._draw()
        if self._cmd:
            self._cmd()


class PasswordStrengthBar(tk.Frame):
    def __init__(self, parent, **kw):
        super().__init__(parent, bg=BG_CARD, **kw)
        row = tk.Frame(self, bg=BG_CARD)
        row.pack(fill="x")
        self._segs = []
        for _ in range(4):
            seg = tk.Frame(row, bg=BDR_SUB, height=4, width=44)
            seg.pack(side="left", padx=(0, 4))
            seg.pack_propagate(False)
            self._segs.append(seg)
        self._lbl = tk.Label(self, text="", bg=BG_CARD, fg=TEXT_3, font=FONT_SMALL)
        self._lbl.pack(anchor="w", pady=(3, 0))

    def evaluate(self, pw):
        score = sum([
            len(pw) >= 8,
            len(pw) >= 12,
            any(c.isdigit() for c in pw),
            any(c in "!@#$%^&*()-_+=[]{}|;:,.<>?" for c in pw),
        ])
        colors = [ERROR, WARN, "#eab308", SUCCESS]
        labels = ["Weak", "Fair", "Good", "Strong"]
        for i, seg in enumerate(self._segs):
            seg.config(bg=colors[score-1] if i < score else BDR_SUB)
        if score:
            self._lbl.config(text=labels[score-1], fg=colors[score-1])
        else:
            self._lbl.config(text="Enter a password", fg=TEXT_3)


class ScrollableFrame(tk.Frame):
    def __init__(self, parent, **kw):
        super().__init__(parent, bg=BG_BASE, **kw)
        cv  = tk.Canvas(self, bg=BG_BASE, highlightthickness=0, bd=0)
        vsb = tk.Scrollbar(self, orient="vertical", command=cv.yview)
        cv.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        cv.pack(side="left", fill="both", expand=True)
        self.frame = tk.Frame(cv, bg=BG_BASE)
        _w = cv.create_window((0, 0), window=self.frame, anchor="nw")
        self.frame.bind("<Configure>",
                        lambda e: cv.configure(scrollregion=cv.bbox("all")))
        cv.bind("<Configure>", lambda e: cv.itemconfig(_w, width=e.width))
        
        def _on_mousewheel(e):
            try:
                cv.yview_scroll(int(-1*(e.delta/120)), "units")
            except Exception:
                pass
                
        cv.bind_all("<MouseWheel>", _on_mousewheel)


class TimePicker(tk.Frame):
    def __init__(self, parent, **kw):
        super().__init__(parent, bg=BG_CARD, **kw)
        self._h = tk.StringVar(value="23")
        self._m = tk.StringVar(value="59")
        self._build()

    def _build(self):
        row = tk.Frame(self, bg=BG_CARD)
        row.pack(pady=4)
        self._spinner(row, self._h, 0, 23).pack(side="left")
        tk.Label(row, text=":", bg=BG_CARD, fg=ACCENT,
                 font=("Segoe UI", 24, "bold")).pack(side="left", padx=6)
        self._spinner(row, self._m, 0, 59).pack(side="left")
        self._preview = tk.Label(self, text="23:59", bg=BG_CARD,
                                 fg=TEXT_ACCENT, font=("Segoe UI", 12, "bold"))
        self._preview.pack(pady=(4, 0))
        for v in (self._h, self._m):
            v.trace_add("write", self._refresh)

    def _spinner(self, parent, var, lo, hi):
        f = tk.Frame(parent, bg=BG_CARD)
        for txt, delta in [("^", 1), (None, None), ("v", -1)]:
            if txt is None:
                tk.Entry(f, textvariable=var, width=3, justify="center",
                         bg=BG_INPUT, fg=TEXT_1, insertbackground=ACCENT,
                         relief="flat", font=("Segoe UI", 20, "bold"),
                         highlightthickness=1, highlightbackground=BDR_MUTED,
                         highlightcolor=ACCENT, bd=0).pack(ipady=5)
            else:
                lbl = tk.Label(f, text=txt, bg=BG_CARD, fg=TEXT_2,
                               font=("Segoe UI", 11, "bold"), cursor="hand2")
                lbl.pack(pady=2)
                lbl.bind("<ButtonPress-1>",
                         lambda e, v=var, d=delta: self._inc(v, lo, hi, d))
                lbl.bind("<Enter>", lambda e, w=lbl: w.config(fg=ACCENT))
                lbl.bind("<Leave>", lambda e, w=lbl: w.config(fg=TEXT_2))
        return f

    def _inc(self, var, lo, hi, d):
        try:
            val = int(var.get())
        except ValueError:
            val = lo
        val = (val + d - lo) % (hi - lo + 1) + lo
        var.set(f"{val:02d}")

    def _refresh(self, *_):
        try:
            h, m = int(self._h.get()), int(self._m.get())
            self._preview.config(text=f"{h:02d}:{m:02d}")
        except ValueError:
            pass

    def get(self):
        try:    h = f"{int(self._h.get()):02d}"
        except: h = "23"
        try:    m = f"{int(self._m.get()):02d}"
        except: m = "59"
        return h, m


# ===========================================================================
# DROP ZONE
# ===========================================================================
class DropZone(tk.Frame):
    def __init__(self, parent, on_file, filetypes=None,
                 label="Drop file here or click to browse", **kw):
        super().__init__(parent, bg=ACCENT_DIM,
                         highlightthickness=1, highlightbackground=ACCENT,
                         cursor="hand2", **kw)
        self._on_file   = on_file
        self._filetypes = filetypes or []
        self._label_txt = label
        self._file      = ""

        self._icon_lbl = tk.Label(self, text="^", bg=ACCENT_DIM, fg=ACCENT,
                                   font=("Segoe UI", 20, "bold"))
        self._icon_lbl.pack(pady=(18, 4))
        self._lbl = tk.Label(self, text=label, bg=ACCENT_DIM, fg=TEXT_2,
                              font=FONT_BODY, wraplength=340, justify="center")
        self._lbl.pack(pady=(0, 4))
        self._sub = tk.Label(self, text="", bg=ACCENT_DIM, fg=TEXT_ACCENT, font=FONT_SMALL)
        self._sub.pack(pady=(0, 14))

        for w in (self, self._icon_lbl, self._lbl, self._sub):
            w.bind("<ButtonPress-1>", self._browse)
            w.bind("<Enter>",  self._hover_on)
            w.bind("<Leave>",  self._hover_off)

        if _HAS_DND:
            try:
                self.drop_target_register(DND_FILES)
                self.dnd_bind("<<Drop>>", self._on_drop)
            except Exception:
                pass

    def _hover_on(self, _):
        bg = "#0e3040"
        self.config(bg=bg, highlightbackground=TEXT_ACCENT)
        for w in (self._icon_lbl, self._lbl, self._sub):
            w.config(bg=bg)

    def _hover_off(self, _):
        self.config(bg=ACCENT_DIM, highlightbackground=ACCENT)
        for w in (self._icon_lbl, self._lbl, self._sub):
            w.config(bg=ACCENT_DIM)

    def _browse(self, _=None):
        if self._filetypes:
            path = filedialog.askopenfilename(filetypes=self._filetypes)
        else:
            path = filedialog.askopenfilename()
        if path:
            self._set(path)

    def _on_drop(self, event):
        path = event.data.strip().strip("{}")
        self._set(path)

    def _set(self, path):
        self._file = path
        self._lbl.config(text=os.path.basename(path), fg=TEXT_1)
        size_kb = os.path.getsize(path) / 1024
        self._sub.config(
            text=f"{size_kb:.1f} KB  |  {os.path.splitext(path)[1].upper()}")
        self._on_file(path)

    def get_path(self):
        return self._file

    def reset(self):
        self._file = ""
        self._lbl.config(text=self._label_txt, fg=TEXT_2)
        self._sub.config(text="")


# ===========================================================================
# IN-MEMORY PDF VIEWER
# ===========================================================================
class PDFViewer(tk.Toplevel):
    def __init__(self, master, pdf_bytes: bytes, watermark_text="", watermark_opacity=0):
        super().__init__(master)
        self.title("Secure PDF Viewer - DRM Guard")
        self.geometry("1000x780")
        self.configure(bg=BG_BASE)
        self.update_idletasks()
        try:
            _apply_anti_screenshot(self.winfo_id())
        except Exception:
            pass
        self.doc              = fitz.open(stream=pdf_bytes, filetype="pdf")
        self.page_number      = 0
        self.zoom             = 1.0
        self.watermark_text   = watermark_text
        self.watermark_opacity = watermark_opacity / 100.0
        self._build()
        self._show_page(0)

    def _build(self):
        tb = tk.Frame(self, bg=BG_SURFACE, height=HEADER_H)
        tb.pack(fill="x")
        tb.pack_propagate(False)
        tk.Label(tb, text="[DG] Secure PDF Viewer", bg=BG_SURFACE,
                 fg=TEXT_1, font=FONT_BRAND).pack(side="left", padx=16)
        tk.Label(tb, text=" READ-ONLY ", bg=ERROR_DIM, fg=ERROR,
                 font=FONT_SMALL, pady=3, padx=6).pack(side="left", padx=4)
        self._pg_lbl = tk.Label(tb, text="", bg=BG_SURFACE, fg=TEXT_2, font=FONT_BODY)
        self._pg_lbl.pack(side="right", padx=16)
        for txt, cmd in [("< Prev", self._prev), ("Next >", self._next),
                          ("+ Zoom", self._zoom_in), ("- Zoom", self._zoom_out)]:
            b = tk.Label(tb, text=txt, bg=BG_SURFACE, fg=ACCENT,
                         font=("Segoe UI", 11, "bold"), cursor="hand2", padx=10)
            b.pack(side="left", padx=2)
            b.bind("<ButtonPress-1>", lambda e, c=cmd: c())
            b.bind("<Enter>", lambda e, w=b: w.config(fg=TEXT_ACCENT))
            b.bind("<Leave>", lambda e, w=b: w.config(fg=ACCENT))
        cf = tk.Frame(self, bg="#08080d")
        cf.pack(fill="both", expand=True)
        vsb = tk.Scrollbar(cf)
        vsb.pack(side="right", fill="y")
        self._canvas = tk.Canvas(cf, bg="#08080d", highlightthickness=0,
                                 yscrollcommand=vsb.set)
        vsb.config(command=self._canvas.yview)
        self._canvas.pack(fill="both", expand=True)
        self._canvas.bind("<MouseWheel>",
            lambda e: self._canvas.yview_scroll(int(-1*(e.delta/120)), "units"))
        
        # Security bindings against data theft
        for b in ("<Button-3>", "<Button-2>", "<Control-c>", "<Print>"):
            self.bind(b, lambda e: "break")
            self._canvas.bind(b, lambda e: "break")

    def _render(self):
        page = self.doc.load_page(self.page_number)
        mat  = fitz.Matrix(self.zoom, self.zoom)
        pix  = page.get_pixmap(matrix=mat, alpha=False)
        img  = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
        if self.watermark_text:
            draw = ImageDraw.Draw(img, "RGBA")
            fs   = max(14, int(min(img.width, img.height) / 12))
            try:
                font = ImageFont.truetype("arial.ttf", fs)
            except Exception:
                font = ImageFont.load_default()
            color = (0, 0, 0, int(255 * self.watermark_opacity))
            try:
                bb = draw.textbbox((0, 0), self.watermark_text, font=font)
                tw, th = bb[2]-bb[0], bb[3]-bb[1]
            except AttributeError:
                tw, th = draw.textsize(self.watermark_text, font=font)
            draw.text(((img.width-tw)/2, (img.height-th)/2),
                      self.watermark_text, font=font, fill=color)
        self._photo = ImageTk.PhotoImage(img)
        self._canvas.delete("all")
        cw = max(self._canvas.winfo_width(), img.width)
        self._canvas.config(scrollregion=(0, 0, cw, img.height + 20))
        self._canvas.create_image(cw//2, 10, anchor="n", image=self._photo)
        self._pg_lbl.config(text=f"Page {self.page_number+1} / {len(self.doc)}")

    def _show_page(self, n):
        if 0 <= n < len(self.doc):
            self.page_number = n
            self._render()

    def _prev(self):    self._show_page(self.page_number - 1)
    def _next(self):    self._show_page(self.page_number + 1)
    def _zoom_in(self): self.zoom = min(self.zoom + 0.25, 3.0); self._render()
    def _zoom_out(self): self.zoom = max(self.zoom - 0.25, 0.5); self._render()


# ===========================================================================
# IN-MEMORY IMAGE VIEWER
# ===========================================================================
class ImageViewer(tk.Toplevel):
    def __init__(self, master, img_bytes: bytes, ext: str,
                 watermark_text="", watermark_opacity=0):
        super().__init__(master)
        self.title("Secure Image Viewer - DRM Guard")
        self.geometry("900x720")
        self.configure(bg=BG_BASE)
        self.update_idletasks()
        try:
            _apply_anti_screenshot(self.winfo_id())
        except Exception:
            pass
        self._orig             = Image.open(io.BytesIO(img_bytes))
        self.zoom              = 1.0
        self.watermark_text    = watermark_text
        self.watermark_opacity = watermark_opacity / 100.0
        self._build()
        self._render()

    def _build(self):
        tb = tk.Frame(self, bg=BG_SURFACE, height=HEADER_H)
        tb.pack(fill="x")
        tb.pack_propagate(False)
        tk.Label(tb, text="[DG] Secure Image Viewer", bg=BG_SURFACE,
                 fg=TEXT_1, font=FONT_BRAND).pack(side="left", padx=16)
        for txt, cmd in [("+ Zoom", self._zoom_in), ("- Zoom", self._zoom_out)]:
            b = tk.Label(tb, text=txt, bg=BG_SURFACE, fg=ACCENT,
                         font=("Segoe UI", 11, "bold"), cursor="hand2", padx=10)
            b.pack(side="left", padx=2)
            b.bind("<ButtonPress-1>", lambda e, c=cmd: c())
        cf = tk.Frame(self, bg="#08080d")
        cf.pack(fill="both", expand=True)
        vsb = tk.Scrollbar(cf)
        vsb.pack(side="right", fill="y")
        hsb = tk.Scrollbar(cf, orient="horizontal")
        hsb.pack(side="bottom", fill="x")
        self._canvas = tk.Canvas(cf, bg="#08080d", highlightthickness=0,
                                 yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.config(command=self._canvas.yview)
        hsb.config(command=self._canvas.xview)
        self._canvas.pack(fill="both", expand=True)
        
        # Security bindings against data theft
        for b in ("<Button-3>", "<Button-2>", "<Control-c>", "<Print>"):
            self.bind(b, lambda e: "break")
            self._canvas.bind(b, lambda e: "break")

    def _render(self):
        w = int(self._orig.width  * self.zoom)
        h = int(self._orig.height * self.zoom)
        img = self._orig.resize((w, h), Image.LANCZOS)
        if self.watermark_text:
            draw = ImageDraw.Draw(img, "RGBA")
            fs   = max(14, int(min(w, h) / 12))
            try:
                font = ImageFont.truetype("arial.ttf", fs)
            except Exception:
                font = ImageFont.load_default()
            color = (0, 0, 0, int(255 * self.watermark_opacity))
            try:
                bb = draw.textbbox((0, 0), self.watermark_text, font=font)
                tw, th = bb[2]-bb[0], bb[3]-bb[1]
            except AttributeError:
                tw, th = draw.textsize(self.watermark_text, font=font)
            draw.text(((w-tw)/2, (h-th)/2), self.watermark_text, font=font, fill=color)
        self._photo = ImageTk.PhotoImage(img)
        self._canvas.delete("all")
        self._canvas.config(scrollregion=(0, 0, w, h))
        self._canvas.create_image(0, 0, anchor="nw", image=self._photo)

    def _zoom_in(self):  self.zoom = min(self.zoom + 0.25, 3.0); self._render()
    def _zoom_out(self): self.zoom = max(self.zoom - 0.25, 0.5); self._render()


# ===========================================================================
# ENCRYPTOR PAGE
# ===========================================================================
class EncryptorPage(tk.Frame):
    def __init__(self, parent, app, **kw):
        super().__init__(parent, bg=BG_BASE, **kw)
        self._app  = app
        self._file = ""
        self._build()

    def _build(self):
        sf = ScrollableFrame(self)
        sf.pack(fill="both", expand=True)
        c = sf.frame
        c.config(padx=40, pady=30)

        # ── Header ──────────────────────────────────────────────────────────
        hrow = tk.Frame(c, bg=BG_BASE)
        hrow.pack(fill="x", pady=(0, 28))
        tk.Label(hrow, text="  ENCRYPT  ", bg=ACCENT_DIM, fg=ACCENT,
                 font=FONT_SMALL, pady=3, padx=8).pack(anchor="w", pady=(0, 6))
        
        title_row = tk.Frame(hrow, bg=BG_BASE)
        title_row.pack(fill="x")
        tk.Label(title_row, text="Protect a File", bg=BG_BASE,
                 fg=TEXT_1, font=FONT_TITLE).pack(side="left")
        

        self._desc_lbl = tk.Label(hrow, text="", bg=BG_BASE, fg=TEXT_2, font=FONT_SUB)
        self._desc_lbl.pack(anchor="w", pady=(4, 0))

        # ── Drop Zone ────────────────────────────────────────────────────────
        self._dz = DropZone(
            c, on_file=lambda p: setattr(self, "_file", p),
            label="Drop any file here  |  click to browse"
        )
        self._dz.pack(fill="x", ipady=8, pady=(0, 16))

        # ── Expiry row ───────────────────────────────────────────────────────
        exp_row = tk.Frame(c, bg=BG_BASE)
        exp_row.pack(fill="x", pady=(0, 16))

        cal_card = GlassCard(exp_row, "Expiry Date", "Cal")
        cal_card.pack(side="left", fill="both", expand=True, padx=(0, 10))
        self._cal = Calendar(
            cal_card.inner, selectmode="day", font=FONT_BODY,
            background=BG_SURFACE,   foreground=TEXT_1,
            bordercolor=BDR_SUB,
            headersbackground=BG_BASE, headersforeground=ACCENT,
            selectbackground=ACCENT,   selectforeground="#000",
            normalbackground=BG_SURFACE, normalforeground=TEXT_1,
            weekendbackground=BG_SURFACE, weekendforeground=TEXT_2,
            othermonthbackground=BG_BASE, othermonthwebackground=BG_BASE,
            othermonthforeground=TEXT_3,  othermonthweforeground=TEXT_3,
        )
        self._cal.pack()

        time_card = GlassCard(exp_row, "Expiry Time", "Clk")
        time_card.pack(side="left", fill="y")
        self._time = TimePicker(time_card.inner)
        self._time.pack()

        # ── Device Lock + Password ───────────────────────────────────────────
        opts_row = tk.Frame(c, bg=BG_BASE)
        opts_row.pack(fill="x", pady=(0, 16))

        lock_card = GlassCard(opts_row, "Device Lock", "MAC")
        lock_card.pack(side="left", fill="both", expand=True, padx=(0, 10))

        self._lock_var = tk.StringVar(value="MAC Address")
        for val, desc in [
            ("MAC Address", "Target MAC Address"),
            ("IP Address",  "Target IP address"),
            ("None",        "No device restriction"),
        ]:
            row = tk.Frame(lock_card.inner, bg=BG_CARD)
            row.pack(fill="x", pady=4)
            tk.Radiobutton(
                row, variable=self._lock_var, value=val,
                bg=BG_CARD, fg=TEXT_1, selectcolor=BG_CARD,
                activebackground=BG_CARD, activeforeground=ACCENT,
                font=FONT_BODY, text=val, command=self._on_lock_change
            ).pack(side="left")
            tk.Label(row, text=f"  {desc}", bg=BG_CARD,
                     fg=TEXT_3, font=FONT_SMALL).pack(side="left")

        self._lock_input_f = tk.Frame(lock_card.inner, bg=BG_CARD)
        self._lock_input_f.pack(fill="x", pady=(8, 0))
        tk.Label(self._lock_input_f, text="Recipient's Identifier", bg=BG_CARD, fg=TEXT_2, font=FONT_LABEL).pack(anchor="w", pady=(0, 4))
        self._target_id_entry = StyledEntry(self._lock_input_f, placeholder="e.g. 00:1A:2B:3C:4D:5E")
        self._target_id_entry.pack(fill="x", ipady=8)
        
        hrow = tk.Frame(self._lock_input_f, bg=BG_CARD)
        hrow.pack(fill="x", pady=(6, 0))
        AccentButton(hrow, "Use My MAC", command=lambda: self._target_id_entry.set_value(get_mac()), primary=False, width=100, height=24).pack(side="left", padx=(0, 6))
        AccentButton(hrow, "Use My IP", command=lambda: self._target_id_entry.set_value(get_ip()), primary=False, width=100, height=24).pack(side="left")

        self._pw_card = GlassCard(opts_row, "Encryption Password", "Key")
        self._pw_card.pack(side="left", fill="both", expand=True)

        tk.Label(self._pw_card.inner, text="Password", bg=BG_CARD,
                 fg=TEXT_2, font=FONT_LABEL).pack(anchor="w", pady=(0, 4))
        self._pw = StyledEntry(self._pw_card.inner, show_char="*")
        self._pw.pack(fill="x", ipady=8)
        self._pw.bind("<KeyRelease>", lambda e: self._strength.evaluate(self._pw.get()))
        self._strength = PasswordStrengthBar(self._pw_card.inner)
        self._strength.pack(fill="x", pady=(8, 0))

        tk.Label(self._pw_card.inner, text="Confirm Password", bg=BG_CARD,
                 fg=TEXT_2, font=FONT_LABEL).pack(anchor="w", pady=(14, 4))
        self._pw2 = StyledEntry(self._pw_card.inner, show_char="*")
        self._pw2.pack(fill="x", ipady=8)

        # ── Watermark ────────────────────────────────────────────────────────
        wm_card = GlassCard(c, "Watermark (Optional)", "Wm")
        wm_card.pack(fill="x", pady=(0, 16))

        toggle_row = tk.Frame(wm_card.inner, bg=BG_CARD)
        toggle_row.pack(fill="x", pady=(0, 8))
        self._wm_var = tk.BooleanVar()
        self._tc = tk.Canvas(toggle_row, width=44, height=22,
                             bg=BG_CARD, highlightthickness=0, bd=0)
        self._tc.pack(side="left")
        self._tc.bind("<ButtonPress-1>", self._toggle_wm)
        self._draw_toggle(False)
        tk.Label(toggle_row, text="  Overlay watermark on decrypted content",
                 bg=BG_CARD, fg=TEXT_1, font=FONT_BODY).pack(side="left")

        self._wm_sub = tk.Frame(wm_card.inner, bg=BG_CARD)
        self._wm_sub.pack(fill="x")
        tk.Label(self._wm_sub, text="Watermark Text", bg=BG_CARD,
                 fg=TEXT_2, font=FONT_LABEL).pack(anchor="w", pady=(0, 4))
        self._wm_entry = StyledEntry(self._wm_sub,
                                      placeholder="e.g. CONFIDENTIAL - John Smith")
        self._wm_entry.pack(fill="x", ipady=7)
        tk.Label(self._wm_sub, text="Opacity", bg=BG_CARD,
                 fg=TEXT_2, font=FONT_LABEL).pack(anchor="w", pady=(10, 4))
        srow = tk.Frame(self._wm_sub, bg=BG_CARD)
        srow.pack(fill="x")
        self._opacity = tk.IntVar(value=40)
        tk.Scale(srow, variable=self._opacity, from_=5, to=100,
                 orient="horizontal", bg=BG_CARD, fg=TEXT_1,
                 troughcolor=BG_INPUT, activebackground=ACCENT,
                 highlightthickness=0, bd=0, font=FONT_SMALL
                 ).pack(side="left", fill="x", expand=True)
        tk.Label(srow, textvariable=self._opacity, bg=BG_CARD,
                 fg=ACCENT, font=("Segoe UI", 11, "bold"), width=4).pack(side="left")
        self._update_wm()

        # ── Actions ──────────────────────────────────────────────────────────
        arow = tk.Frame(c, bg=BG_BASE)
        arow.pack(fill="x", pady=(8, 0))
        AccentButton(arow, "ENCRYPT FILE", command=self._encrypt,
                     primary=True, width=220, height=40).pack(side="left", padx=(0, 10))
        AccentButton(arow, "Open Decryptor ->", command=self._app.show_decrypt,
                     primary=False, width=190, height=40).pack(side="left")

        self._progress_var = tk.DoubleVar()
        self._progress = ttk.Progressbar(arow, variable=self._progress_var, maximum=1.0, length=200)
        self._progress.pack(side="left", padx=(20, 0), pady=10)


    # ── Helpers ──────────────────────────────────────────────────────────────
    def _draw_toggle(self, state):
        tc = ACCENT if state else BDR_MUTED
        self._tc.delete("all")
        self._tc.create_arc(0, 2, 22, 20, start=90,  extent=180, fill=tc, outline="")
        self._tc.create_arc(22, 2, 44, 20, start=270, extent=180, fill=tc, outline="")
        self._tc.create_rectangle(11, 2, 33, 20, fill=tc, outline="")
        tx = 31 if state else 13
        self._tc.create_oval(tx-8, 3, tx+8, 19, fill="#fff", outline="")

    def _toggle_wm(self, _=None):
        self._wm_var.set(not self._wm_var.get())
        self._draw_toggle(self._wm_var.get())
        self._update_wm()

    def _update_wm(self):
        state = "normal" if self._wm_var.get() else "disabled"
        for w in self._wm_sub.winfo_children():
            try:
                w.config(state=state)
            except tk.TclError:
                pass

    def _on_lock_change(self):
        if self._lock_var.get() == "None":
            self._target_id_entry.config(state="disabled")
            self._target_id_entry.set_value("No restriction")
        else:
            self._target_id_entry.config(state="normal")
            self._target_id_entry.clear()

    def _encrypt(self):
        f = self._file
        if not f or not os.path.exists(f):
            toast(self._app.root, "Please select a valid file first.", "warn")
            return

        pw = self._pw.get()
        if not pw:
            toast(self._app.root, "Please enter an encryption password.", "warn")
            return
        if pw != self._pw2.get():
            toast(self._app.root, "Passwords do not match.", "error")
            return

        sel_date   = self._cal.get_date()
        h, m       = self._time.get()
        expiry_raw = f"{sel_date} {h}:{m}"
        try:
            expiry_dt = datetime.strptime(expiry_raw, "%m/%d/%y %H:%M")
        except ValueError:
            toast(self._app.root, "Invalid date/time.", "error")
            return
        if expiry_dt <= datetime.now():
            toast(self._app.root, "Expiry must be in the future.", "warn")
            return

        expiry_str = expiry_dt.strftime("%Y-%m-%d %H:%M")
        pref       = self._lock_var.get()
        if pref == "None":
            identifier = "None"
        else:
            identifier = self._target_id_entry.get_value().strip()
            if not identifier:
                toast(self._app.root, f"Please enter the recipient's {pref}.", "warn")
                return
        wm_text    = self._wm_entry.get_value() if self._wm_var.get() else ""
        wm_opacity = self._opacity.get()         if self._wm_var.get() else 0

        default_out = os.path.splitext(f)[0] + ".drm"
        out_path = filedialog.asksaveasfilename(
            parent=self._app.root,
            title="Save Encrypted File As",
            initialfile=os.path.basename(default_out),
            defaultextension=".drm",
            filetypes=[("DRM Files", "*.drm"), ("All Files", "*.*")]
        )
        if not out_path:
            return

        def _run():
            try:
                def _update_prog(p):
                    self._progress_var.set(p)

                out = encrypt_file(f, expiry_str, identifier, pw, wm_text, wm_opacity, progress_callback=_update_prog, out_path=out_path)
                log_action("ENCRYPT", os.path.basename(f), identifier, expiry_str, "OK")
                self._app.root.after(0, lambda: toast(
                    self._app.root, f"Saved: {os.path.basename(out)}", "success"))
                self._app.root.after(0, self._app.refresh_log)
                self._app.root.after(0, lambda: self._progress_var.set(0))
            except Exception as e:
                log_action("ENCRYPT", os.path.basename(f), identifier, expiry_str, "FAIL")
                self._app.root.after(0, lambda: toast(
                    self._app.root, f"Encryption failed: {e}", "error"))
                self._app.root.after(0, lambda: self._progress_var.set(0))

        threading.Thread(target=_run, daemon=True).start()
        toast(self._app.root, "Encrypting...", "info")


# ===========================================================================
# DECRYPTOR PAGE
# ===========================================================================
class DecryptorPage(tk.Frame):
    def __init__(self, parent, app, **kw):
        super().__init__(parent, bg=BG_BASE, **kw)
        self._app  = app
        self._file = ""
        self._build()

    def _build(self):
        sf = ScrollableFrame(self)
        sf.pack(fill="both", expand=True)
        c = sf.frame
        c.config(padx=40, pady=30)

        hrow = tk.Frame(c, bg=BG_BASE)
        hrow.pack(fill="x", pady=(0, 28))
        tk.Label(hrow, text="  DECRYPT  ", bg=SUCCESS_DIM, fg=SUCCESS,
                 font=FONT_SMALL, pady=3, padx=8).pack(anchor="w", pady=(0, 6))
                 
        title_row = tk.Frame(hrow, bg=BG_BASE)
        title_row.pack(fill="x")
        tk.Label(title_row, text="Open a Protected File", bg=BG_BASE,
                 fg=TEXT_1, font=FONT_TITLE).pack(side="left")
                 

        tk.Label(hrow, text="Decryption happens entirely in memory — the file is never written to disk",
                 bg=BG_BASE, fg=TEXT_2, font=FONT_SUB).pack(anchor="w", pady=(4, 0))

        self._dz = DropZone(
            c, on_file=self._on_file_selected,
            filetypes=[("DRM Files", "*.drm")],
            label="Drop .drm file here  |  click to browse"
        )
        self._dz.pack(fill="x", ipady=8, pady=(0, 16))

        # Security checklist
        info = GlassCard(c, "Security Checks Performed", "SEC")
        info.pack(fill="x", pady=(0, 16))
        for txt in [
            "Your MAC address is validated against the file device lock",
            "Expiry date and time are verified against the system clock",
            "Password is verified using PBKDF2-SHA256 hash (not stored in plaintext)",
            "Decrypted bytes live in RAM only — never written to disk",
        ]:
            row = tk.Frame(info.inner, bg=BG_CARD)
            row.pack(fill="x", pady=3)
            tk.Label(row, text="v", bg=BG_CARD, fg=SUCCESS,
                     font=("Segoe UI", 12, "bold"), width=2).pack(side="left")
            tk.Label(row, text=txt, bg=BG_CARD, fg=TEXT_2,
                     font=FONT_BODY).pack(side="left")

        # Device identity
        id_card = GlassCard(c, "Your Device Identity", "ID")
        id_card.pack(fill="x", pady=(0, 16))
        id_inner = tk.Frame(id_card.inner, bg=BG_CARD2,
                             highlightthickness=1, highlightbackground=BDR_SUB)
        id_inner.pack(fill="x")
        tk.Label(id_inner, text=f"  MAC Address   {get_mac()}",
                 bg=BG_CARD2, fg=TEXT_ACCENT, font=FONT_MONO
                 ).pack(anchor="w", padx=10, pady=(8, 2))
        tk.Label(id_inner, text=f"  IP Address    {get_ip()}",
                 bg=BG_CARD2, fg=TEXT_ACCENT, font=FONT_MONO
                 ).pack(anchor="w", padx=10, pady=(0, 8))

        # Password
        self._pw_card = GlassCard(c, "Decryption Password", "Key")
        self._pw_card.pack(fill="x", pady=(0, 16))
        self._pw = StyledEntry(self._pw_card.inner, show_char="*",
                               placeholder="Enter the decryption password")
        self._pw.pack(fill="x", ipady=9)

        arow = tk.Frame(c, bg=BG_BASE)
        arow.pack(fill="x", pady=(8, 0))
        AccentButton(arow, "DECRYPT & VIEW", command=self._decrypt,
                     primary=True, width=220, height=40).pack(side="left", padx=(0, 10))
        AccentButton(arow, "<- Encryptor", command=self._app.show_encrypt,
                     primary=False, width=180, height=40).pack(side="left")

    def _on_file_selected(self, p):
        self._file = p
        if p.endswith(".drm"):
            for w in self._pw_card.inner.winfo_children():
                try: w.config(state="normal")
                except: pass
            self._pw_card.config(highlightbackground=BDR_SUB)
            self._pw.clear()

    def _decrypt(self):
        if not self._file:
            toast(self._app.root, "Please select a .drm file.", "warn")
            return
            
        pw = self._pw.get()
        if not pw:
            toast(self._app.root, "Please enter the decryption password.", "warn")
            return

        def _run():
            try:
                data, ext, wm_text, wm_opacity = decrypt_to_bytes(self._file, pw)
                log_action("DECRYPT", os.path.basename(self._file), get_mac(), "-", "OK")

                def _open():
                    if ext.lower() == "pdf":
                        PDFViewer(self._app.root, data, wm_text, wm_opacity)
                    elif ext.lower() in ("png", "jpg", "jpeg", "gif", "bmp", "webp", "tiff"):
                        ImageViewer(self._app.root, data, ext, wm_text, wm_opacity)
                    else:
                        toast(self._app.root,
                              f"Decryption OK but .{ext} files cannot be previewed.", "warn")

                self._app.root.after(0, _open)
                self._app.root.after(0, lambda: toast(
                    self._app.root, "File opened securely (LOCAL mode).", "success"))
                self._app.root.after(0, self._app.refresh_log)
            except PermissionError as e:
                log_action("DECRYPT", os.path.basename(self._file), get_mac(), "-", "DENIED")
                self._app.root.after(0, lambda: toast(self._app.root, str(e), "error"))
            except Exception as e:
                self._app.root.after(0, lambda: toast(
                    self._app.root, f"Decryption failed: {e}", "error"))

        threading.Thread(target=_run, daemon=True).start()
        toast(self._app.root, "Decrypting...", "info")


# ===========================================================================
# AUDIT LOG PAGE
# ===========================================================================
class LogPage(tk.Frame):
    def __init__(self, parent, app, **kw):
        super().__init__(parent, bg=BG_BASE, **kw)
        self._app = app
        self._build()

    def _build(self):
        c = tk.Frame(self, bg=BG_BASE, padx=40, pady=30)
        c.pack(fill="both", expand=True)

        hrow = tk.Frame(c, bg=BG_BASE)
        hrow.pack(fill="x", pady=(0, 24))
        tk.Label(hrow, text="  AUDIT LOG  ", bg=ACCENT_DIM, fg=ACCENT,
                 font=FONT_SMALL, pady=3, padx=8).pack(anchor="w", pady=(0, 6))
        tk.Label(hrow, text="Activity History", bg=BG_BASE,
                 fg=TEXT_1, font=FONT_TITLE).pack(anchor="w")
        tk.Label(hrow, text="All encryption and decryption events stored locally",
                 bg=BG_BASE, fg=TEXT_2, font=FONT_SUB).pack(anchor="w", pady=(4, 0))
        AccentButton(hrow, "Refresh", command=self.refresh,
                     primary=False, width=110, height=34).pack(side="right", anchor="ne")

        cols = ("Timestamp", "Action", "File", "MAC", "Status")
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("DRM.Treeview",
                        background=BG_CARD, foreground=TEXT_1,
                        fieldbackground=BG_CARD, rowheight=28, font=FONT_BODY)
        style.configure("DRM.Treeview.Heading",
                        background=BG_SURFACE, foreground=TEXT_2,
                        font=FONT_LABEL, relief="flat")
        style.map("DRM.Treeview",
                  background=[("selected", ACCENT_DIM)],
                  foreground=[("selected", TEXT_ACCENT)])

        frame = tk.Frame(c, bg=BG_CARD,
                         highlightthickness=1, highlightbackground=BDR_SUB)
        frame.pack(fill="both", expand=True)
        vsb = ttk.Scrollbar(frame, orient="vertical")
        vsb.pack(side="right", fill="y")
        self._tree = ttk.Treeview(frame, columns=cols, show="headings",
                                   style="DRM.Treeview", yscrollcommand=vsb.set)
        vsb.config(command=self._tree.yview)
        widths = {"Timestamp": 160, "Action": 80, "File": 220,
                  "MAC": 160, "Status": 70}
        for col in cols:
            self._tree.heading(col, text=col)
            self._tree.column(col, width=widths.get(col, 100), anchor="w")
        self._tree.pack(fill="both", expand=True)
        self.refresh()

    def refresh(self):
        for row in self._tree.get_children():
            self._tree.delete(row)
        for r in reversed(read_log(100)):
            if len(r) >= 8:
                tag = "ok" if r[7] == "OK" else "fail"
                self._tree.insert("", "end",
                                   values=(r[0], r[1], r[2], r[5], r[7]),
                                   tags=(tag,))
        self._tree.tag_configure("ok",   foreground=SUCCESS)
        self._tree.tag_configure("fail", foreground=ERROR)


# ===========================================================================
# SIDEBAR
# ===========================================================================
class Sidebar(tk.Frame):
    NAV = [
        ("encrypt",  "^",  "Encrypt File",  "show_encrypt"),
        ("decrypt",  "v",  "Decrypt File",  "show_decrypt"),
        ("log",      "=",  "Audit Log",     "show_log"),
    ]

    def __init__(self, parent, app, **kw):
        super().__init__(parent, bg=BG_SURFACE, width=SIDEBAR_W, **kw)
        self.pack_propagate(False)
        self._app    = app
        self._active = "encrypt"
        self._btns   = {}
        self._conn_lbl = None
        self._build()

    def _build(self):
        # Brand
        brand = tk.Frame(self, bg=BG_SURFACE)
        brand.pack(fill="x", padx=20, pady=(24, 0))
        icon_cv = tk.Canvas(brand, width=34, height=34,
                            bg=BG_SURFACE, highlightthickness=0)
        icon_cv.pack(side="left")
        icon_cv.create_oval(2, 2, 32, 32, fill=ACCENT_DIM, outline=ACCENT, width=1.5)
        icon_cv.create_text(17, 17, text="DG", fill=ACCENT, font=("Segoe UI", 11, "bold"))
        bt = tk.Frame(brand, bg=BG_SURFACE)
        bt.pack(side="left", padx=10)
        tk.Label(bt, text="DRM Guard", bg=BG_SURFACE,
                 fg=TEXT_1, font=FONT_BRAND).pack(anchor="w")
        tk.Label(bt, text="v4.0  Production", bg=BG_SURFACE,
                 fg=TEXT_3, font=FONT_SMALL).pack(anchor="w")

        tk.Frame(self, bg=BDR_SUB, height=1).pack(fill="x", padx=16, pady=20)
        tk.Label(self, text="WORKSPACE", bg=BG_SURFACE,
                 fg=TEXT_3, font=("Segoe UI", 8, "bold")).pack(anchor="w", padx=20, pady=(0, 8))

        for key, icon, label, cmd in self.NAV:
            self._btns[key] = self._nav_btn(key, icon, label, cmd)

        tk.Frame(self, bg=BDR_SUB, height=1).pack(fill="x", padx=16, pady=(24, 12))
        info = tk.Frame(self, bg=BG_SURFACE)
        info.pack(fill="x", padx=16)
        tk.Label(info, text="AES-256-CBC + PKCS7",
                 bg=BG_SURFACE, fg=ACCENT, font=FONT_SMALL).pack(anchor="w")
        tk.Label(info, text="PBKDF2-SHA256  |  MAC Lock",
                 bg=BG_SURFACE, fg=TEXT_3, font=FONT_SMALL).pack(anchor="w")
        tk.Label(info, text="In-memory decryption",
                 bg=BG_SURFACE, fg=TEXT_3, font=FONT_SMALL).pack(anchor="w", pady=(0, 6))


        self._set_active("encrypt")



    def _nav_btn(self, key, icon, label, method_name):
        outer = tk.Frame(self, bg=BG_SURFACE, cursor="hand2")
        outer.pack(fill="x", padx=10, pady=2)
        bar   = tk.Frame(outer, bg=BG_SURFACE, width=3)
        bar.pack(side="left", fill="y")
        inner = tk.Frame(outer, bg=BG_SURFACE, pady=11, padx=12)
        inner.pack(side="left", fill="both", expand=True)
        icon_lbl = tk.Label(inner, text=icon, bg=BG_SURFACE,
                            fg=TEXT_2, font=("Segoe UI", 13, "bold"))
        icon_lbl.pack(side="left")
        text_lbl = tk.Label(inner, text=f"  {label}", bg=BG_SURFACE,
                            fg=TEXT_2, font=("Segoe UI", 11))
        text_lbl.pack(side="left")

        def _click(_=None):
            getattr(self._app, method_name)()

        for w in (outer, inner, bar, icon_lbl, text_lbl):
            w.bind("<ButtonPress-1>", _click)
            w.bind("<Enter>",
                   lambda e, o=outer, i=inner, il=icon_lbl, tl=text_lbl, k=key:
                   self._hover(o, i, il, tl, k, True))
            w.bind("<Leave>",
                   lambda e, o=outer, i=inner, il=icon_lbl, tl=text_lbl, k=key:
                   self._hover(o, i, il, tl, k, False))

        outer._bar   = bar
        outer._icon  = icon_lbl
        outer._text  = text_lbl
        outer._inner = inner
        return outer

    def _hover(self, outer, inner, icon_lbl, text_lbl, key, entering):
        if key == self._active:
            return
        bg = BG_CARD  if entering else BG_SURFACE
        fg = TEXT_1   if entering else TEXT_2
        for w in (outer, inner):
            w.config(bg=bg)
        for w in (icon_lbl, text_lbl):
            w.config(bg=bg, fg=fg)

    def _set_active(self, key):
        self._active = key
        for k, btn in self._btns.items():
            active = (k == key)
            bg  = BG_CARD  if active else BG_SURFACE
            fg  = TEXT_1   if active else TEXT_2
            bar = ACCENT   if active else BG_SURFACE
            ifg = ACCENT   if active else TEXT_2
            btn._bar.config(bg=bar)
            btn.config(bg=bg)
            btn._inner.config(bg=bg)
            btn._icon.config(bg=bg, fg=ifg)
            btn._text.config(bg=bg, fg=fg)

    def set_active(self, key):
        self._set_active(key)


# ===========================================================================
# MAIN APPLICATION
# ===========================================================================
class DRMGuardApp:
    def __init__(self, root):
        self.root = root
        self.root.title("DRM Guard - Secure File Protection Suite")
        self.root.geometry("1180x820")
        self.root.minsize(960, 640)
        self.root.configure(bg=BG_BASE)
        self.root.update_idletasks()
        try:
            _apply_anti_screenshot(self.root.winfo_id())
        except Exception:
            pass
            
        _start_keyboard_hook()
        _start_monitor()
        
        def _on_close():
            _stop_keyboard_hook()
            _stop_monitor()
            self.root.destroy()
        self.root.protocol("WM_DELETE_WINDOW", _on_close)
        
        # Global security bindings against data theft
        for b in ("<Button-3>", "<Button-2>", "<Control-c>", "<Print>"):
            self.root.bind_all(b, lambda e: "break")

        self._layout = tk.Frame(self.root, bg=BG_BASE)
        self._layout.pack(fill="both", expand=True)

        self.sidebar = Sidebar(self._layout, self)
        self.sidebar.pack(side="left", fill="y")

        tk.Frame(self._layout, bg=BDR_SUB, width=1).pack(side="left", fill="y")

        self._content = tk.Frame(self._layout, bg=BG_BASE)
        self._content.pack(side="left", fill="both", expand=True)

        self._current = None
        self.show_encrypt()

    def _switch(self, cls, key):
        if self._current:
            self._current.destroy()
        self._current = cls(self._content, self)
        self._current.pack(fill="both", expand=True)
        self.sidebar.set_active(key)

    def show_encrypt(self):  self._switch(EncryptorPage, "encrypt")
    def show_decrypt(self):  self._switch(DecryptorPage, "decrypt")
    def show_log(self):      self._switch(LogPage,        "log")

    def refresh_log(self):
        if isinstance(self._current, LogPage):
            self._current.refresh()




# ===========================================================================
# ENTRY POINT
# ===========================================================================
if __name__ == "__main__":
    if _HAS_DND:
        root = TkinterDnD.Tk()
    else:
        root = tk.Tk()

    if platform.system() == "Windows":
        try:
            from ctypes import windll
            windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass

    DRMGuardApp(root)
    root.mainloop()
