import os
import uuid
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
from tkcalendar import Calendar
from PIL import Image, ImageTk, ImageDraw, ImageFont
import fitz  # PyMuPDF
from datetime import datetime
from Crypto.Cipher import AES
import csv
import tempfile
import threading
import socket
import base64

# ====================
# Color Palette
# ====================

DARK_BG       = "#0f1117"
SIDEBAR_BG    = "#16181f"
CARD_BG       = "#1e2130"
CARD_BORDER   = "#2a2d3e"
ACCENT        = "#6c63ff"
ACCENT_HOVER  = "#8b85ff"
ACCENT_LIGHT  = "#2d2b5e"
TEXT_PRIMARY  = "#e8eaf6"
TEXT_SECONDARY= "#9095b0"
TEXT_MUTED    = "#565b78"
SUCCESS       = "#22c55e"
ERROR         = "#ef4444"
ENTRY_BG      = "#252838"
ENTRY_BORDER  = "#363a55"
SEP_COLOR     = "#252838"

# ====================
# Utility functions
# ====================

def get_mac():
    return ':'.join(("%012X" % uuid.getnode())[i:i+2] for i in range(0, 12, 2))

def get_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip_address = s.getsockname()[0]
        s.close()
        return ip_address
    except Exception:
        return "127.0.0.1"

def pad(data):
    while len(data) % 16 != 0:
        data += b'\x00'
    return data

def unpad(data):
    return data.rstrip(b'\x00')

def encrypt_file_util(path, expiry, identifier, password, watermark_text="", watermark_opacity=0):
    with open(path, 'rb') as f:
        plaintext = f.read()

    key = hashlib.sha256((identifier + expiry + password).encode()).digest()
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext))

    ext = os.path.splitext(path)[1][1:]
    encoded_watermark_text = base64.b64encode(watermark_text.encode()).decode()
    header = f"{expiry}|{identifier}|{ext}|{password}|{encoded_watermark_text}|{watermark_opacity}".encode()
    encrypted_file_path = f"{os.path.splitext(path)[0]}.drm"

    with open(encrypted_file_path, 'wb') as f:
        f.write(header + b'\n' + iv + ciphertext)

    return encrypted_file_path, ext

def decrypt_file_util(encrypted_path, provided_password):
    try:
        with open(encrypted_path, 'rb') as f:
            header_bytes = f.readline().strip()
            iv = f.read(16)
            ciphertext = f.read()

        header_parts = header_bytes.decode().split('|')
        if len(header_parts) != 6:
            raise ValueError("Invalid file header format.")

        expiry_str, identifier_from_file, original_ext, password_from_file, encoded_watermark_text, watermark_opacity_str = header_parts
        watermark_text = base64.b64decode(encoded_watermark_text).decode()
        watermark_opacity = int(watermark_opacity_str)

        if provided_password != password_from_file:
            raise ValueError("Incorrect password.")

        if datetime.now() > datetime.strptime(expiry_str, "%Y-%m-%d %H:%M"):
            raise ValueError("File has expired.")

        if identifier_from_file not in ("None", get_mac(), get_ip()):
            if identifier_from_file != get_mac() and identifier_from_file != get_ip():
                raise ValueError("Access denied: Identifier mismatch.")

        key = hashlib.sha256((identifier_from_file + expiry_str + password_from_file).encode()).digest()
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext))

        temp_dir = tempfile.gettempdir()
        temp_file_path = os.path.join(temp_dir, f"temp_decrypted.{original_ext}")
        with open(temp_file_path, 'wb') as f:
            f.write(plaintext)

        return temp_file_path, original_ext, watermark_text, watermark_opacity

    except Exception as e:
        raise Exception(f"Decryption failed: {e}")

def log_action(action, filename, identifier, expiry):
    file_exists = os.path.exists("log.csv")
    with open("log.csv", "a", newline="") as log:
        writer = csv.writer(log)
        if not file_exists:
            writer.writerow(["Action", "Filename", "Identifier", "Expiry", "Timestamp"])
        writer.writerow([action, filename, identifier, expiry, datetime.now().strftime("%Y-%m-%d %H:%M")])

# ====================
# Themed Tk Widgets
# ====================

class ThemedEntry(tk.Entry):
    """A custom Entry widget with dark theme and focus highlight."""
    def __init__(self, parent, show=None, **kwargs):
        self._var = tk.StringVar()
        opts = dict(
            textvariable=self._var,
            bg=ENTRY_BG,
            fg=TEXT_PRIMARY,
            insertbackground=ACCENT,
            relief="flat",
            font=("Segoe UI", 11),
            highlightthickness=1,
            highlightbackground=ENTRY_BORDER,
            highlightcolor=ACCENT,
            bd=0,
        )
        if show:
            opts["show"] = show
        opts.update(kwargs)
        super().__init__(parent, **opts)

    def get_value(self):
        return self._var.get()

    def set_value(self, v):
        self._var.set(v)

    def clear(self):
        self._var.set("")


class ThemedButton(tk.Frame):
    """Custom animated button with rounded corners."""
    def __init__(self, parent, text, command=None, accent=True, width=200, height=40, **kwargs):
        super().__init__(parent, bg=DARK_BG, cursor="hand2")
        self._text = text
        self._command = command
        self._accent = accent
        self._btn_w = width
        self._btn_h = height
        self._normal_color = ACCENT if accent else CARD_BG
        self._hover_color = ACCENT_HOVER if accent else ENTRY_BG
        self._text_color = "#ffffff" if accent else TEXT_PRIMARY
        self._current_color = self._normal_color

        self._canvas = tk.Canvas(self, width=width, height=height,
                                 bg=DARK_BG, highlightthickness=0, bd=0, cursor="hand2")
        self._canvas.pack()
        self._canvas.after(10, self._draw)
        self._canvas.bind("<Enter>", self._on_enter)
        self._canvas.bind("<Leave>", self._on_leave)
        self._canvas.bind("<ButtonPress-1>", self._on_press)
        self._canvas.bind("<ButtonRelease-1>", self._on_release)
        self.bind("<ButtonPress-1>", self._on_press)
        self.bind("<ButtonRelease-1>", self._on_release)

    def _draw(self, color=None):
        c = color or self._current_color
        self._canvas.delete("all")
        r = 8
        w, h = self._btn_w, self._btn_h
        self._round_rect(0, 0, w, h, r, fill=c)
        self._canvas.create_text(w//2, h//2, text=self._text,
                         fill=self._text_color, font=("Segoe UI", 11, "bold"))

    def _round_rect(self, x1, y1, x2, y2, r, **kwargs):
        points = [x1+r, y1, x2-r, y1, x2, y1, x2, y1+r,
                  x2, y2-r, x2, y2, x2-r, y2, x1+r, y2,
                  x1, y2, x1, y2-r, x1, y1+r, x1, y1]
        self._canvas.create_polygon(points, smooth=True, **kwargs)

    def _on_enter(self, e):
        self._current_color = self._hover_color
        self._draw()

    def _on_leave(self, e):
        self._current_color = self._normal_color
        self._draw()

    def _on_press(self, e):
        self._draw(color="#4a44c4" if self._accent else CARD_BORDER)

    def _on_release(self, e):
        self._current_color = self._hover_color
        self._draw()
        if self._command:
            self._command()

    def config_text(self, text):
        self._text = text
        self._draw()


# ====================
# Time Picker Widget
# ====================

class TimePicker(tk.Frame):
    """Compact, styled time picker with +/- spinners."""
    def __init__(self, parent, **kwargs):
        super().__init__(parent, bg=CARD_BG, **kwargs)
        self._hour = tk.StringVar(value="12")
        self._minute = tk.StringVar(value="00")
        self._build()

    def _build(self):
        # Title row
        header = tk.Label(self, text="⏰  Select Time", bg=CARD_BG,
                          fg=TEXT_SECONDARY, font=("Segoe UI", 10, "bold"))
        header.pack(anchor="w", padx=16, pady=(12, 8))

        row = tk.Frame(self, bg=CARD_BG)
        row.pack(padx=16, pady=(0, 12))

        # Hour spinner
        h_frame = self._spinner_block(row, self._hour, 0, 23, "HH")
        h_frame.pack(side="left")

        # Colon separator
        colon = tk.Label(row, text=":", bg=CARD_BG, fg=ACCENT,
                         font=("Segoe UI", 28, "bold"))
        colon.pack(side="left", padx=8, pady=(0, 4))

        # Minute spinner
        m_frame = self._spinner_block(row, self._minute, 0, 59, "MM")
        m_frame.pack(side="left")

        # Live preview
        self._preview = tk.Label(self, text="12:00", bg=CARD_BG,
                                 fg=ACCENT, font=("Segoe UI", 13, "bold"))
        self._preview.pack(pady=(0, 10))

        self._hour.trace_add("write", self._update_preview)
        self._minute.trace_add("write", self._update_preview)

    def _spinner_block(self, parent, var, min_val, max_val, placeholder):
        frame = tk.Frame(parent, bg=CARD_BG)

        # Up arrow
        up = tk.Label(frame, text="▲", bg=CARD_BG, fg=TEXT_SECONDARY,
                      font=("Segoe UI", 11), cursor="hand2")
        up.pack()
        up.bind("<ButtonPress-1>", lambda e, v=var, mn=min_val, mx=max_val: self._increment(v, mn, mx, 1))
        up.bind("<Enter>", lambda e, w=up: w.config(fg=ACCENT))
        up.bind("<Leave>", lambda e, w=up: w.config(fg=TEXT_SECONDARY))

        # Entry
        entry = tk.Entry(frame, textvariable=var, width=4, justify="center",
                         bg=ENTRY_BG, fg=TEXT_PRIMARY, insertbackground=ACCENT,
                         relief="flat", font=("Segoe UI", 22, "bold"),
                         highlightthickness=1, highlightbackground=ENTRY_BORDER,
                         highlightcolor=ACCENT, bd=0)
        entry.pack(ipady=6)

        # Down arrow
        dn = tk.Label(frame, text="▼", bg=CARD_BG, fg=TEXT_SECONDARY,
                      font=("Segoe UI", 11), cursor="hand2")
        dn.pack()
        dn.bind("<ButtonPress-1>", lambda e, v=var, mn=min_val, mx=max_val: self._increment(v, mn, mx, -1))
        dn.bind("<Enter>", lambda e, w=dn: w.config(fg=ACCENT))
        dn.bind("<Leave>", lambda e, w=dn: w.config(fg=TEXT_SECONDARY))

        return frame

    def _increment(self, var, min_val, max_val, delta):
        try:
            val = int(var.get())
        except ValueError:
            val = 0
        val = (val + delta - min_val) % (max_val - min_val + 1) + min_val
        var.set(f"{val:02d}")

    def _update_preview(self, *_):
        try:
            h = int(self._hour.get())
            m = int(self._minute.get())
            self._preview.config(text=f"{h:02d}:{m:02d}")
        except ValueError:
            pass

    def get_hour(self):
        try:
            return f"{int(self._hour.get()):02d}"
        except ValueError:
            return "12"

    def get_minute(self):
        try:
            return f"{int(self._minute.get()):02d}"
        except ValueError:
            return "00"


# ====================
# PDF Viewer window
# ====================

class PDFViewer(tk.Toplevel):
    def __init__(self, master, pdf_path, watermark_text="", watermark_opacity=0):
        super().__init__(master)
        self.title("PDF Viewer — DRM")
        self.geometry("960x760")
        self.configure(bg=DARK_BG)
        self.doc = fitz.open(pdf_path)
        self.page_number = 0
        self.zoom = 1.0
        self.watermark_text = watermark_text
        self.watermark_opacity = watermark_opacity / 100.0
        self.create_widgets()
        self.show_page(0)

    def create_widgets(self):
        # Top toolbar
        toolbar = tk.Frame(self, bg=SIDEBAR_BG, height=52)
        toolbar.pack(fill="x")
        toolbar.pack_propagate(False)

        tk.Label(toolbar, text="📄  PDF Viewer", bg=SIDEBAR_BG,
                 fg=TEXT_PRIMARY, font=("Segoe UI", 13, "bold")).pack(side="left", padx=16)

        self.page_label = tk.Label(toolbar, text="", bg=SIDEBAR_BG,
                                   fg=TEXT_SECONDARY, font=("Segoe UI", 11))
        self.page_label.pack(side="right", padx=16)

        for text, cmd in [("◀ Prev", self.prev_page), ("Next ▶", self.next_page),
                           ("🔍+", self.zoom_in), ("🔍−", self.zoom_out)]:
            b = tk.Label(toolbar, text=text, bg=SIDEBAR_BG, fg=ACCENT,
                         font=("Segoe UI", 11, "bold"), cursor="hand2", padx=10)
            b.pack(side="left", padx=4)
            b.bind("<ButtonPress-1>", lambda e, c=cmd: c())
            b.bind("<Enter>", lambda e, w=b: w.config(fg=ACCENT_HOVER))
            b.bind("<Leave>", lambda e, w=b: w.config(fg=ACCENT))

        # Canvas area
        canvas_frame = tk.Frame(self, bg="#1a1a2e")
        canvas_frame.pack(fill="both", expand=True)

        self.canvas = tk.Canvas(canvas_frame, bg="#1a1a2e", highlightthickness=0)
        self.canvas.pack(fill="both", expand=True)

    def render_page(self):
        page = self.doc.load_page(self.page_number)
        mat = fitz.Matrix(self.zoom, self.zoom)
        pix = page.get_pixmap(matrix=mat)

        img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
        draw = ImageDraw.Draw(img, "RGBA")

        if self.watermark_text:
            font_size = int(min(img.width, img.height) / 15)
            try:
                font = ImageFont.truetype("arial.ttf", font_size)
            except IOError:
                font = ImageFont.load_default()
            text_color = (0, 0, 0, int(255 * self.watermark_opacity))
            try:
                bbox = draw.textbbox((0, 0), self.watermark_text, font=font)
                text_width = bbox[2] - bbox[0]
                text_height = bbox[3] - bbox[1]
            except AttributeError:
                text_width, text_height = draw.textsize(self.watermark_text, font=font)
            x = (img.width - text_width) / 2
            y = (img.height - text_height) / 2
            draw.text((x, y), self.watermark_text, font=font, fill=text_color)

        self.img = ImageTk.PhotoImage(img)
        self.canvas.delete("all")
        self.canvas.config(scrollregion=(0, 0, self.img.width(), self.img.height()))
        self.canvas.create_image(self.canvas.winfo_width()//2, 10, anchor="n", image=self.img)
        self.page_label.config(text=f"Page {self.page_number+1} / {len(self.doc)}")

    def show_page(self, n):
        if 0 <= n < len(self.doc):
            self.page_number = n
            self.render_page()

    def prev_page(self):
        if self.page_number > 0:
            self.show_page(self.page_number - 1)

    def next_page(self):
        if self.page_number < len(self.doc) - 1:
            self.show_page(self.page_number + 1)

    def zoom_in(self):
        self.zoom = min(self.zoom + 0.25, 3.0)
        self.render_page()

    def zoom_out(self):
        self.zoom = max(self.zoom - 0.25, 0.5)
        self.render_page()


# ====================
# Image Viewer window
# ====================

class ImageViewer(tk.Toplevel):
    def __init__(self, master, image_path, watermark_text="", watermark_opacity=0):
        super().__init__(master)
        self.title("Image Viewer — DRM")
        self.geometry("960x760")
        self.configure(bg=DARK_BG)
        self.zoom = 1.0
        self.original_image = Image.open(image_path)
        self.watermark_text = watermark_text
        self.watermark_opacity = watermark_opacity / 100.0
        self.create_widgets()
        self.show_image()

    def create_widgets(self):
        toolbar = tk.Frame(self, bg=SIDEBAR_BG, height=52)
        toolbar.pack(fill="x")
        toolbar.pack_propagate(False)

        tk.Label(toolbar, text="🖼  Image Viewer", bg=SIDEBAR_BG,
                 fg=TEXT_PRIMARY, font=("Segoe UI", 13, "bold")).pack(side="left", padx=16)

        for text, cmd in [("🔍+", self.zoom_in), ("🔍−", self.zoom_out)]:
            b = tk.Label(toolbar, text=text, bg=SIDEBAR_BG, fg=ACCENT,
                         font=("Segoe UI", 11, "bold"), cursor="hand2", padx=10)
            b.pack(side="left", padx=4)
            b.bind("<ButtonPress-1>", lambda e, c=cmd: c())
            b.bind("<Enter>", lambda e, w=b: w.config(fg=ACCENT_HOVER))
            b.bind("<Leave>", lambda e, w=b: w.config(fg=ACCENT))

        canvas_frame = tk.Frame(self, bg="#1a1a2e")
        canvas_frame.pack(fill="both", expand=True)

        h_scroll = tk.Scrollbar(canvas_frame, orient="horizontal", bg=DARK_BG)
        h_scroll.pack(side="bottom", fill="x")
        v_scroll = tk.Scrollbar(canvas_frame, orient="vertical", bg=DARK_BG)
        v_scroll.pack(side="right", fill="y")

        self.canvas = tk.Canvas(canvas_frame, bg="#1a1a2e", highlightthickness=0,
                                xscrollcommand=h_scroll.set, yscrollcommand=v_scroll.set)
        self.canvas.pack(fill="both", expand=True)
        h_scroll.config(command=self.canvas.xview)
        v_scroll.config(command=self.canvas.yview)

    def show_image(self):
        w, h = int(self.original_image.width * self.zoom), int(self.original_image.height * self.zoom)
        resized = self.original_image.resize((w, h), Image.LANCZOS)

        if self.watermark_text:
            draw = ImageDraw.Draw(resized, "RGBA")
            font_size = int(min(w, h) / 15)
            try:
                font = ImageFont.truetype("arial.ttf", font_size)
            except IOError:
                font = ImageFont.load_default()
            text_color = (0, 0, 0, int(255 * self.watermark_opacity))
            try:
                bbox = draw.textbbox((0, 0), self.watermark_text, font=font)
                text_width = bbox[2] - bbox[0]
                text_height = bbox[3] - bbox[1]
            except AttributeError:
                text_width, text_height = draw.textsize(self.watermark_text, font=font)
            x = (w - text_width) / 2
            y = (h - text_height) / 2
            draw.text((x, y), self.watermark_text, font=font, fill=text_color)

        self.photo = ImageTk.PhotoImage(resized)
        self.canvas.delete("all")
        self.canvas.create_image(0, 0, anchor="nw", image=self.photo)
        self.canvas.config(scrollregion=(0, 0, w, h))

    def zoom_in(self):
        self.zoom = min(self.zoom + 0.25, 3.0)
        self.show_image()

    def zoom_out(self):
        self.zoom = max(self.zoom - 0.25, 0.5)
        self.show_image()


# ====================
# Section Card helper
# ====================

def make_card(parent, title=None, icon=""):
    """Return (outer_frame, inner_content_frame) styled as a card."""
    outer = tk.Frame(parent, bg=CARD_BG, highlightbackground=CARD_BORDER,
                     highlightthickness=1)
    if title:
        hdr = tk.Frame(outer, bg=CARD_BG)
        hdr.pack(fill="x", padx=16, pady=(14, 0))
        tk.Label(hdr, text=f"{icon}  {title}" if icon else title,
                 bg=CARD_BG, fg=TEXT_SECONDARY,
                 font=("Segoe UI", 9, "bold")).pack(side="left")
        # thin accent line
        sep = tk.Frame(outer, bg=SEP_COLOR, height=1)
        sep.pack(fill="x", padx=16, pady=(8, 0))

    inner = tk.Frame(outer, bg=CARD_BG)
    inner.pack(fill="both", expand=True, padx=16, pady=(10, 16))
    return outer, inner


# ====================
# File Row helper
# ====================

def make_file_row(parent, on_browse):
    """Returns (entry_widget, browse_button_widget) inside a styled row frame."""
    row = tk.Frame(parent, bg=CARD_BG)
    row.pack(fill="x")

    entry = ThemedEntry(row)
    entry.pack(side="left", fill="x", expand=True, ipady=7)

    browse_btn = tk.Label(row, text="Browse", bg=ACCENT, fg="#ffffff",
                          font=("Segoe UI", 10, "bold"), cursor="hand2",
                          padx=14, pady=7)
    browse_btn.pack(side="left", padx=(8, 0))
    browse_btn.bind("<ButtonPress-1>", lambda e: on_browse())
    browse_btn.bind("<Enter>", lambda e: browse_btn.config(bg=ACCENT_HOVER))
    browse_btn.bind("<Leave>", lambda e: browse_btn.config(bg=ACCENT))

    return entry, browse_btn


# ====================
# Scrollable Canvas Frame
# ====================

class ScrollableFrame(tk.Frame):
    def __init__(self, parent, *args, **kwargs):
        super().__init__(parent, bg=DARK_BG, *args, **kwargs)
        self.canvas = tk.Canvas(self, bg=DARK_BG, highlightthickness=0, bd=0)
        self.frame = tk.Frame(self.canvas, bg=DARK_BG)

        self.vsb = tk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.vsb.set)

        self.vsb.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)
        self._win = self.canvas.create_window((0, 0), window=self.frame, anchor="nw")

        self.frame.bind("<Configure>", self._on_frame_configure)
        self.canvas.bind("<Configure>", self._on_canvas_configure)
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)

    def _on_frame_configure(self, event):
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _on_canvas_configure(self, event):
        self.canvas.itemconfig(self._win, width=event.width)

    def _on_mousewheel(self, event):
        self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")


# ====================
# Section label helper
# ====================

def section_label(parent, text):
    tk.Label(parent, text=text, bg=DARK_BG,
             fg=TEXT_SECONDARY, font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(16, 4))


# ====================
# Encryptor UI Class
# ====================

class Encryptor:
    def __init__(self, root, app_instance):
        self.root = root
        self.app = app_instance
        self.file_path = ""
        self._build_ui()

    def _build_ui(self):
        sf = ScrollableFrame(self.root)
        sf.pack(fill="both", expand=True)
        container = sf.frame
        container.config(padx=32, pady=28)

        # Page title
        title_row = tk.Frame(container, bg=DARK_BG)
        title_row.pack(fill="x", pady=(0, 24))
        tk.Label(title_row, text="🔒", bg=DARK_BG, fg=ACCENT,
                 font=("Segoe UI", 28)).pack(side="left")
        title_col = tk.Frame(title_row, bg=DARK_BG)
        title_col.pack(side="left", padx=12)
        tk.Label(title_col, text="Encrypt File", bg=DARK_BG,
                 fg=TEXT_PRIMARY, font=("Segoe UI", 22, "bold")).pack(anchor="w")
        tk.Label(title_col, text="Protect your documents with AES encryption",
                 bg=DARK_BG, fg=TEXT_MUTED, font=("Segoe UI", 10)).pack(anchor="w")

        # ── File selection ──────────────────────────────────────────
        card_outer, card_inner = make_card(container, "Select File", "📁")
        card_outer.pack(fill="x", pady=(0, 14))

        tk.Label(card_inner, text="Choose the file you want to encrypt",
                 bg=CARD_BG, fg=TEXT_SECONDARY, font=("Segoe UI", 10)).pack(anchor="w", pady=(0, 8))

        row = tk.Frame(card_inner, bg=CARD_BG)
        row.pack(fill="x")
        self.file_entry = ThemedEntry(row)
        self.file_entry.pack(side="left", fill="x", expand=True, ipady=7)

        browse_btn = tk.Label(row, text="  Browse  ", bg=ACCENT, fg="#ffffff",
                              font=("Segoe UI", 10, "bold"), cursor="hand2", pady=7)
        browse_btn.pack(side="left", padx=(8, 0))
        browse_btn.bind("<ButtonPress-1>", lambda e: self._browse_file())
        browse_btn.bind("<Enter>", lambda e: browse_btn.config(bg=ACCENT_HOVER))
        browse_btn.bind("<Leave>", lambda e: browse_btn.config(bg=ACCENT))

        # ── Expiry date ─────────────────────────────────────────────
        card_outer2, card_inner2 = make_card(container, "Expiry Date", "📅")
        card_outer2.pack(fill="x", pady=(0, 14))

        tk.Label(card_inner2, text="The file will become inaccessible after this date",
                 bg=CARD_BG, fg=TEXT_SECONDARY, font=("Segoe UI", 10)).pack(anchor="w", pady=(0, 10))

        # Calendar with matching dark colors
        cal_frame = tk.Frame(card_inner2, bg=CARD_BG)
        cal_frame.pack(anchor="w")
        self.calendar = Calendar(
            cal_frame,
            selectmode="day",
            font=("Segoe UI", 10),
            background=SIDEBAR_BG,
            foreground=TEXT_PRIMARY,
            bordercolor=CARD_BORDER,
            headersbackground=DARK_BG,
            headersforeground=ACCENT,
            selectbackground=ACCENT,
            selectforeground="#ffffff",
            normalbackground=SIDEBAR_BG,
            normalforeground=TEXT_PRIMARY,
            weekendbackground=SIDEBAR_BG,
            weekendforeground=TEXT_SECONDARY,
            othermonthbackground=DARK_BG,
            othermonthwebackground=DARK_BG,
            othermonthforeground=TEXT_MUTED,
            othermonthweforeground=TEXT_MUTED,
            disableddaybackground=DARK_BG,
            disableddayforeground=TEXT_MUTED,
            tooltipbackground=CARD_BG,
            tooltipforeground=TEXT_PRIMARY,
        )
        self.calendar.pack()

        # ── Time picker ─────────────────────────────────────────────
        card_outer3, card_inner3 = make_card(container, "Expiry Time", "⏱")
        card_outer3.pack(fill="x", pady=(0, 14))

        tk.Label(card_inner3, text="Set the exact hour and minute for expiry",
                 bg=CARD_BG, fg=TEXT_SECONDARY, font=("Segoe UI", 10)).pack(anchor="w", pady=(0, 8))

        self.time_picker = TimePicker(card_inner3)
        self.time_picker.pack(anchor="w")

        # ── Identifier ──────────────────────────────────────────────
        card_outer4, card_inner4 = make_card(container, "Device Lock", "🖥")
        card_outer4.pack(fill="x", pady=(0, 14))

        tk.Label(card_inner4, text="Restrict decryption to a specific device identifier",
                 bg=CARD_BG, fg=TEXT_SECONDARY, font=("Segoe UI", 10)).pack(anchor="w", pady=(0, 8))

        self._pref_var = tk.StringVar(value="MAC Address")
        for val, desc in [("MAC Address", "Bind to hardware address (recommended)"),
                          ("IP Address",  "Bind to current IP address"),
                          ("None",        "No device restriction")]:
            row_rb = tk.Frame(card_inner4, bg=CARD_BG)
            row_rb.pack(fill="x", pady=3)
            rb = tk.Radiobutton(row_rb, variable=self._pref_var, value=val,
                                bg=CARD_BG, fg=TEXT_PRIMARY, selectcolor=CARD_BG,
                                activebackground=CARD_BG, activeforeground=ACCENT,
                                font=("Segoe UI", 11), text=val)
            rb.pack(side="left")
            tk.Label(row_rb, text=f"  —  {desc}", bg=CARD_BG,
                     fg=TEXT_MUTED, font=("Segoe UI", 9)).pack(side="left")

        # ── Password ────────────────────────────────────────────────
        card_outer5, card_inner5 = make_card(container, "Encryption Password", "🔑")
        card_outer5.pack(fill="x", pady=(0, 14))

        tk.Label(card_inner5, text="This password will be required for decryption",
                 bg=CARD_BG, fg=TEXT_SECONDARY, font=("Segoe UI", 10)).pack(anchor="w", pady=(0, 8))

        self.password_entry = ThemedEntry(card_inner5, show="•")
        self.password_entry.pack(fill="x", ipady=8)

        # ── Watermark ───────────────────────────────────────────────
        card_outer6, card_inner6 = make_card(container, "Watermark (Optional)", "💧")
        card_outer6.pack(fill="x", pady=(0, 14))

        self._wm_enabled = tk.BooleanVar()
        chk_row = tk.Frame(card_inner6, bg=CARD_BG)
        chk_row.pack(fill="x", pady=(0, 8))

        # Custom toggle
        self._toggle_canvas = tk.Canvas(chk_row, width=44, height=22,
                                        bg=CARD_BG, highlightthickness=0, bd=0)
        self._toggle_canvas.pack(side="left")
        self._toggle_canvas.bind("<ButtonPress-1>", self._toggle_wm)
        self._draw_toggle(False)

        tk.Label(chk_row, text="  Enable watermark overlay on decrypted files",
                 bg=CARD_BG, fg=TEXT_PRIMARY, font=("Segoe UI", 10)).pack(side="left")

        # Watermark sub-fields
        self._wm_frame = tk.Frame(card_inner6, bg=CARD_BG)
        self._wm_frame.pack(fill="x")

        tk.Label(self._wm_frame, text="Watermark Text", bg=CARD_BG,
                 fg=TEXT_SECONDARY, font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(8, 4))
        self.wm_text_entry = ThemedEntry(self._wm_frame)
        self.wm_text_entry.pack(fill="x", ipady=7)

        tk.Label(self._wm_frame, text="Opacity", bg=CARD_BG,
                 fg=TEXT_SECONDARY, font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(10, 4))

        slider_row = tk.Frame(self._wm_frame, bg=CARD_BG)
        slider_row.pack(fill="x")
        self._opacity_var = tk.IntVar(value=50)
        self._opacity_slider = tk.Scale(slider_row, variable=self._opacity_var,
                                        from_=0, to=100, orient="horizontal",
                                        bg=CARD_BG, fg=TEXT_PRIMARY,
                                        troughcolor=ENTRY_BG, activebackground=ACCENT,
                                        highlightthickness=0, bd=0,
                                        font=("Segoe UI", 9))
        self._opacity_slider.pack(side="left", fill="x", expand=True)
        self._opacity_lbl = tk.Label(slider_row, textvariable=self._opacity_var,
                                     bg=CARD_BG, fg=ACCENT,
                                     font=("Segoe UI", 11, "bold"), width=4)
        self._opacity_lbl.pack(side="left")

        self._update_wm_state()

        # ── Action buttons ───────────────────────────────────────────
        btn_row = tk.Frame(container, bg=DARK_BG)
        btn_row.pack(fill="x", pady=(10, 0))

        enc_btn = ThemedButton(btn_row, "🔒  Encrypt File",
                               command=self._encrypt, accent=True, width=260, height=44)
        enc_btn.pack(side="left", padx=(0, 10))

        switch_btn = ThemedButton(btn_row, "→  Go to Decryptor",
                                  command=self.app.show_decryptor, accent=False, width=200, height=44)
        switch_btn.pack(side="left")

    # ── Helpers ────────────────────────────────────────────────────

    def _draw_toggle(self, state):
        self._toggle_canvas.delete("all")
        track_color = ACCENT if state else ENTRY_BORDER
        self._toggle_canvas.create_rounded_rect = lambda *a, **k: None
        # Draw track
        self._toggle_canvas.create_arc(0, 2, 22, 20, start=90, extent=180, fill=track_color, outline="")
        self._toggle_canvas.create_arc(22, 2, 44, 20, start=270, extent=180, fill=track_color, outline="")
        self._toggle_canvas.create_rectangle(11, 2, 33, 20, fill=track_color, outline="")
        # Draw thumb
        thumb_x = 31 if state else 13
        self._toggle_canvas.create_oval(thumb_x - 8, 3, thumb_x + 8, 19,
                                        fill="#ffffff", outline="")

    def _toggle_wm(self, event):
        self._wm_enabled.set(not self._wm_enabled.get())
        self._draw_toggle(self._wm_enabled.get())
        self._update_wm_state()

    def _update_wm_state(self):
        state = "normal" if self._wm_enabled.get() else "disabled"
        for w in self._wm_frame.winfo_children():
            try:
                w.config(state=state)
            except tk.TclError:
                pass

    def _browse_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.file_path = path
            self.file_entry.set_value(path)

    def _encrypt(self):
        file_to_encrypt = self.file_entry.get_value()
        selected_date = self.calendar.get_date()
        selected_hour = self.time_picker.get_hour()
        selected_minute = self.time_picker.get_minute()
        identifier_pref = self._pref_var.get()
        password = self.password_entry.get_value()
        watermark_enabled = self._wm_enabled.get()
        watermark_text = self.wm_text_entry.get_value() if watermark_enabled else ""
        watermark_opacity = self._opacity_var.get() if watermark_enabled else 0

        if not file_to_encrypt or not os.path.exists(file_to_encrypt):
            messagebox.showerror("Error", "Please select a valid file.")
            return
        if not password:
            messagebox.showerror("Error", "Please enter a password.")
            return

        try:
            expiry_datetime_str = f"{selected_date} {selected_hour}:{selected_minute}"
            expiry_datetime = datetime.strptime(expiry_datetime_str, "%m/%d/%y %H:%M")

            if expiry_datetime <= datetime.now():
                messagebox.showerror("Error", "Expiry date and time must be in the future.")
                return

            if identifier_pref == "MAC Address":
                identifier = get_mac()
            elif identifier_pref == "IP Address":
                identifier = get_ip()
            else:
                identifier = "None"

            encrypted_file, _ = encrypt_file_util(
                file_to_encrypt, expiry_datetime_str, identifier,
                password, watermark_text, watermark_opacity
            )
            log_action("Encrypt", os.path.basename(file_to_encrypt), identifier, expiry_datetime_str)
            messagebox.showinfo("Success ✅",
                                f"File encrypted successfully!\nSaved as:\n{encrypted_file}")
        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))


# ====================
# Decryptor UI Class
# ====================

class Decryptor:
    def __init__(self, root, app_instance):
        self.root = root
        self.app = app_instance
        self.encrypted_file_path = ""
        self._build_ui()

    def _build_ui(self):
        sf = ScrollableFrame(self.root)
        sf.pack(fill="both", expand=True)
        container = sf.frame
        container.config(padx=32, pady=28)

        # Page title
        title_row = tk.Frame(container, bg=DARK_BG)
        title_row.pack(fill="x", pady=(0, 24))
        tk.Label(title_row, text="🔓", bg=DARK_BG, fg=SUCCESS,
                 font=("Segoe UI", 28)).pack(side="left")
        title_col = tk.Frame(title_row, bg=DARK_BG)
        title_col.pack(side="left", padx=12)
        tk.Label(title_col, text="Decrypt File", bg=DARK_BG,
                 fg=TEXT_PRIMARY, font=("Segoe UI", 22, "bold")).pack(anchor="w")
        tk.Label(title_col, text="Open a protected .drm file securely",
                 bg=DARK_BG, fg=TEXT_MUTED, font=("Segoe UI", 10)).pack(anchor="w")

        # ── File selection ──────────────────────────────────────────
        card_outer, card_inner = make_card(container, "Select DRM File", "📂")
        card_outer.pack(fill="x", pady=(0, 14))

        tk.Label(card_inner, text="Choose the encrypted .drm file to open",
                 bg=CARD_BG, fg=TEXT_SECONDARY, font=("Segoe UI", 10)).pack(anchor="w", pady=(0, 8))

        row = tk.Frame(card_inner, bg=CARD_BG)
        row.pack(fill="x")
        self.file_entry = ThemedEntry(row)
        self.file_entry.pack(side="left", fill="x", expand=True, ipady=7)

        browse_btn = tk.Label(row, text="  Browse  ", bg=SUCCESS, fg="#ffffff",
                              font=("Segoe UI", 10, "bold"), cursor="hand2", pady=7)
        browse_btn.pack(side="left", padx=(8, 0))
        browse_btn.bind("<ButtonPress-1>", lambda e: self._browse_file())
        browse_btn.bind("<Enter>", lambda e: browse_btn.config(bg="#16a34a"))
        browse_btn.bind("<Leave>", lambda e: browse_btn.config(bg=SUCCESS))

        # ── Password ────────────────────────────────────────────────
        card_outer2, card_inner2 = make_card(container, "Decryption Password", "🔑")
        card_outer2.pack(fill="x", pady=(0, 14))

        tk.Label(card_inner2, text="Enter the password used during encryption",
                 bg=CARD_BG, fg=TEXT_SECONDARY, font=("Segoe UI", 10)).pack(anchor="w", pady=(0, 8))

        self.password_entry = ThemedEntry(card_inner2, show="•")
        self.password_entry.pack(fill="x", ipady=8)

        # ── Info card ───────────────────────────────────────────────
        info_card, info_inner = make_card(container, "How it works", "ℹ")
        info_card.pack(fill="x", pady=(0, 14))

        for line in [
            "✔  Validates your device identifier (MAC / IP)",
            "✔  Checks the file hasn't expired",
            "✔  Decrypts and opens the file in a secure viewer",
            "✔  Temporary files are cleaned up automatically",
        ]:
            tk.Label(info_inner, text=line, bg=CARD_BG, fg=TEXT_SECONDARY,
                     font=("Segoe UI", 10), anchor="w").pack(fill="x", pady=2)

        # ── Action buttons ───────────────────────────────────────────
        btn_row = tk.Frame(container, bg=DARK_BG)
        btn_row.pack(fill="x", pady=(10, 0))

        dec_btn = ThemedButton(btn_row, "🔓  Decrypt & View",
                               command=self._decrypt_and_view, accent=True, width=240, height=44)
        dec_btn.pack(side="left", padx=(0, 10))

        switch_btn = ThemedButton(btn_row, "← Go to Encryptor",
                                  command=self.app.show_encryptor, accent=False, width=200, height=44)
        switch_btn.pack(side="left")

    def _browse_file(self):
        path = filedialog.askopenfilename(filetypes=[("DRM files", "*.drm")])
        if path:
            self.encrypted_file_path = path
            self.file_entry.set_value(path)

    def _decrypt_and_view(self):
        if not self.encrypted_file_path:
            messagebox.showerror("Error", "Please select a .drm file.")
            return
        password = self.password_entry.get_value()
        if not password:
            messagebox.showerror("Error", "Please enter the decryption password.")
            return

        try:
            decrypted_file_path, original_ext, watermark_text, watermark_opacity = decrypt_file_util(
                self.encrypted_file_path, password
            )
            log_action("Decrypt", os.path.basename(self.encrypted_file_path), "N/A", "N/A")

            if original_ext.lower() == "pdf":
                PDFViewer(self.root, decrypted_file_path, watermark_text, watermark_opacity)
            elif original_ext.lower() in ["png", "jpg", "jpeg", "gif", "bmp"]:
                ImageViewer(self.root, decrypted_file_path, watermark_text, watermark_opacity)
            else:
                messagebox.showinfo("Decryption Success",
                                    f"File decrypted to:\n{decrypted_file_path}\n\n"
                                    "This file type cannot be previewed in-app.")
        except Exception as e:
            messagebox.showerror("Decryption Error", str(e))
        finally:
            if 'decrypted_file_path' in locals() and os.path.exists(decrypted_file_path):
                self.root.after(5000, lambda: self._cleanup(decrypted_file_path))

    def _cleanup(self, path):
        try:
            if os.path.exists(path):
                os.remove(path)
        except OSError:
            pass


# ====================
# Sidebar navigation
# ====================

class Sidebar(tk.Frame):
    def __init__(self, parent, on_encrypt, on_decrypt):
        super().__init__(parent, bg=SIDEBAR_BG, width=220)
        self.pack_propagate(False)
        self._on_encrypt = on_encrypt
        self._on_decrypt = on_decrypt
        self._active = "encrypt"
        self._btns = {}
        self._build()

    def _build(self):
        # Logo / Brand
        brand = tk.Frame(self, bg=SIDEBAR_BG)
        brand.pack(fill="x", padx=20, pady=(24, 30))
        tk.Label(brand, text="🛡", bg=SIDEBAR_BG, fg=ACCENT,
                 font=("Segoe UI", 22)).pack(side="left")
        brand_txt = tk.Frame(brand, bg=SIDEBAR_BG)
        brand_txt.pack(side="left", padx=8)
        tk.Label(brand_txt, text="DRM Guard", bg=SIDEBAR_BG,
                 fg=TEXT_PRIMARY, font=("Segoe UI", 13, "bold")).pack(anchor="w")
        tk.Label(brand_txt, text="v3.0", bg=SIDEBAR_BG,
                 fg=TEXT_MUTED, font=("Segoe UI", 8)).pack(anchor="w")

        # Separator
        tk.Frame(self, bg=SEP_COLOR, height=1).pack(fill="x", padx=16, pady=(0, 16))

        # Nav label
        tk.Label(self, text="NAVIGATION", bg=SIDEBAR_BG,
                 fg=TEXT_MUTED, font=("Segoe UI", 8, "bold")).pack(anchor="w", padx=20, pady=(0, 8))

        # Nav buttons
        for key, icon, label, cmd in [
            ("encrypt", "🔒", "Encrypt File", self._click_encrypt),
            ("decrypt", "🔓", "Decrypt File", self._click_decrypt),
        ]:
            btn = self._nav_button(key, icon, label, cmd)
            self._btns[key] = btn

        # Bottom version info
        tk.Frame(self, bg=SEP_COLOR, height=1).pack(fill="x", padx=16, pady=(24, 12))
        tk.Label(self, text="AES-256 · CBC Mode", bg=SIDEBAR_BG,
                 fg=TEXT_MUTED, font=("Segoe UI", 8)).pack(padx=20, anchor="w")

        self._set_active("encrypt")

    def _nav_button(self, key, icon, label, cmd):
        frame = tk.Frame(self, bg=SIDEBAR_BG, cursor="hand2")
        frame.pack(fill="x", padx=10, pady=2)

        accent_bar = tk.Frame(frame, bg=SIDEBAR_BG, width=3)
        accent_bar.pack(side="left", fill="y")

        inner = tk.Frame(frame, bg=SIDEBAR_BG, pady=10, padx=12)
        inner.pack(side="left", fill="both", expand=True)

        icon_lbl = tk.Label(inner, text=icon, bg=SIDEBAR_BG,
                            fg=TEXT_SECONDARY, font=("Segoe UI", 14))
        icon_lbl.pack(side="left")
        lbl = tk.Label(inner, text=f"  {label}", bg=SIDEBAR_BG,
                       fg=TEXT_SECONDARY, font=("Segoe UI", 11))
        lbl.pack(side="left")

        def on_click(e=None):
            cmd()

        for w in [frame, inner, icon_lbl, lbl, accent_bar]:
            w.bind("<ButtonPress-1>", on_click)
            w.bind("<Enter>", lambda e, f=frame, i=inner, il=icon_lbl, l=lbl: self._hover(f, i, il, l, key))
            w.bind("<Leave>", lambda e, f=frame, i=inner, il=icon_lbl, l=lbl: self._unhover(f, i, il, l, key))

        frame._accent_bar = accent_bar
        frame._icon_lbl = icon_lbl
        frame._label = lbl
        frame._inner = inner
        return frame

    def _hover(self, frame, inner, icon_lbl, lbl, key):
        if key != self._active:
            for w in [frame, inner]:
                w.config(bg=CARD_BG)
            for w in [icon_lbl, lbl]:
                w.config(bg=CARD_BG, fg=TEXT_PRIMARY)

    def _unhover(self, frame, inner, icon_lbl, lbl, key):
        if key != self._active:
            for w in [frame, inner]:
                w.config(bg=SIDEBAR_BG)
            for w in [icon_lbl, lbl]:
                w.config(bg=SIDEBAR_BG, fg=TEXT_SECONDARY)

    def _set_active(self, key):
        self._active = key
        for k, btn in self._btns.items():
            active = (k == key)
            bar_color = ACCENT if active else SIDEBAR_BG
            bg = ACCENT_LIGHT if active else SIDEBAR_BG
            fg_text = TEXT_PRIMARY if active else TEXT_SECONDARY
            btn._accent_bar.config(bg=bar_color)
            btn.config(bg=bg)
            btn._inner.config(bg=bg)
            btn._icon_lbl.config(bg=bg, fg=ACCENT if active else TEXT_SECONDARY)
            btn._label.config(bg=bg, fg=fg_text)

    def _click_encrypt(self):
        self._set_active("encrypt")
        self._on_encrypt()

    def _click_decrypt(self):
        self._set_active("decrypt")
        self._on_decrypt()


# ====================
# Main Application
# ====================

class DRMApp:
    def __init__(self, root):
        self.root = root
        self.root.title("DRM Guard — File Protection Suite")
        self.root.geometry("1100x800")
        self.root.minsize(900, 600)
        self.root.configure(bg=DARK_BG)

        # Layout: sidebar + content
        self._layout = tk.Frame(root, bg=DARK_BG)
        self._layout.pack(fill="both", expand=True)

        self.sidebar = Sidebar(self._layout, self.show_encryptor, self.show_decryptor)
        self.sidebar.pack(side="left", fill="y")

        # Thin separator line between sidebar and content
        tk.Frame(self._layout, bg=SEP_COLOR, width=1).pack(side="left", fill="y")

        self.content_area = tk.Frame(self._layout, bg=DARK_BG)
        self.content_area.pack(side="left", fill="both", expand=True)

        self.current_frame = None
        self.show_encryptor()

    def show_encryptor(self):
        if self.current_frame:
            self.current_frame.destroy()
        self.current_frame = tk.Frame(self.content_area, bg=DARK_BG)
        self.current_frame.pack(fill="both", expand=True)
        Encryptor(self.current_frame, self)

    def show_decryptor(self):
        if self.current_frame:
            self.current_frame.destroy()
        self.current_frame = tk.Frame(self.content_area, bg=DARK_BG)
        self.current_frame.pack(fill="both", expand=True)
        Decryptor(self.current_frame, self)


if __name__ == "__main__":
    root = tk.Tk()
    app = DRMApp(root)
    root.mainloop()
