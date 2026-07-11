import os
import uuid
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
from tkcalendar import Calendar
from PIL import Image, ImageTk
import fitz  # PyMuPDF
from datetime import datetime
from Crypto.Cipher import AES
import csv
import tempfile
import threading
import socket

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
        return "127.0.0.1"  # Default to localhost if unable to fetch

def pad(data):
    while len(data) % 16 != 0:
        data += b'\x00'
    return data

def unpad(data):
    return data.rstrip(b'\x00')

def encrypt_file_util(path, expiry, identifier, password):
    with open(path, 'rb') as f:
        plaintext = f.read()

    key = hashlib.sha256((identifier + expiry + password).encode()).digest()
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext))

    ext = os.path.splitext(path)[1][1:]  # file extension without dot
    header = f"{expiry}|{identifier}|{ext}|{password}".encode()
    encrypted_file_path = f"{os.path.splitext(path)[0]}.drm"

    with open(encrypted_file_path, 'wb') as f:
        f.write(header + b'\n' + iv + ciphertext)

    return encrypted_file_path, ext

def log_action(action, filename, identifier, expiry):
    file_exists = os.path.exists("log.csv")
    with open("log.csv", "a", newline="") as log:
        writer = csv.writer(log)
        if not file_exists:
            writer.writerow(["Action", "Filename", "Identifier", "Expiry", "Timestamp"])
        writer.writerow([action, filename, identifier, expiry, datetime.now().strftime("%Y-%m-%d %H:%M")])

# ====================
# Scrollable frame helper for forms
# ====================

class ScrollableFrame(ttk.Frame):
    def __init__(self, parent, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)

        self.canvas = tk.Canvas(self, borderwidth=0, highlightthickness=0, background='#ffffff')
        self.frame = ttk.Frame(self.canvas, style="Card.TFrame")

        self.vsb = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.vsb.set)

        self.vsb.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)
        self.canvas.create_window((0,0), window=self.frame, anchor="nw")

        self.frame.bind("<Configure>", self.on_frame_configure)
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)

    def on_frame_configure(self, event):
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _on_mousewheel(self, event):
        self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

# ====================
# PDF Viewer window
# ====================

class PDFViewer(tk.Toplevel):
    def __init__(self, master, pdf_path):
        super().__init__(master)
        self.title("PDF Viewer")
        self.geometry("900x700")
        self.configure(bg="#ffffff")
        self.doc = fitz.open(pdf_path)
        self.page_number = 0
        self.zoom = 1.0

        self.create_widgets()
        self.show_page(0)

    def create_widgets(self):
        self.canvas = tk.Canvas(self, bg="#ffffff", highlightthickness=0)
        self.canvas.pack(fill="both", expand=True)

        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill="x", padx=10, pady=12)

        style = ttk.Style()
        style.configure("Viewer.TButton",
                        foreground="#111827",
                        background="#e5e7eb",
                        font=("Inter", 14, "bold"),
                        padding=10)
        style.map("Viewer.TButton",
                  background=[("active", "#2563eb"), ("!active", "#e5e7eb")],
                  foreground=[("active", "#fff"), ("!active", "#111827")])

        self.btn_prev = ttk.Button(btn_frame, text="Previous", command=self.prev_page, style="Viewer.TButton")
        self.btn_prev.pack(side="left", padx=(0, 8))

        self.btn_next = ttk.Button(btn_frame, text="Next", command=self.next_page, style="Viewer.TButton")
        self.btn_next.pack(side="left", padx=(0, 12))

        self.zoom_in_btn = ttk.Button(btn_frame, text="Zoom In", command=self.zoom_in, style="Viewer.TButton")
        self.zoom_in_btn.pack(side="left", padx=8)

        self.zoom_out_btn = ttk.Button(btn_frame, text="Zoom Out", command=self.zoom_out, style="Viewer.TButton")
        self.zoom_out_btn.pack(side="left", padx=8)

        self.page_label = ttk.Label(btn_frame, text="", font=("Inter", 14))
        self.page_label.pack(side="right")

    def render_page(self):
        page = self.doc.load_page(self.page_number)
        mat = fitz.Matrix(self.zoom, self.zoom)
        pix = page.get_pixmap(matrix=mat)
        img_data = pix.tobytes("ppm")

        self.img = tk.PhotoImage(data=img_data)
        self.canvas.delete("all")
        self.canvas.config(scrollregion=(0, 0, self.img.width(), self.img.height()))
        self.canvas.create_image(0, 0, anchor="nw", image=self.img)
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
    def __init__(self, master, image_path):
        super().__init__(master)
        self.title("Image Viewer")
        self.geometry("900x700")
        self.configure(bg="#ffffff")
        self.zoom = 1.0
        self.original_image = Image.open(image_path)

        self.create_widgets()
        self.show_image()

    def create_widgets(self):
        self.canvas = tk.Canvas(self, bg="#ffffff", highlightthickness=0)
        self.canvas.pack(fill="both", expand=True)

        self.h_scroll = ttk.Scrollbar(self, orient="horizontal", command=self.canvas.xview)
        self.h_scroll.pack(side="bottom", fill="x")

        self.v_scroll = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.v_scroll.pack(side="right", fill="y")

        self.canvas.configure(xscrollcommand=self.h_scroll.set, yscrollcommand=self.v_scroll.set)

        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill="x", padx=10, pady=12)

        style = ttk.Style()
        style.configure("Viewer.TButton",
                        foreground="#111827",
                        background="#e5e7eb",
                        font=("Inter", 14, "bold"),
                        padding=10)
        style.map("Viewer.TButton",
                  background=[("active", "#2563eb"), ("!active", "#e5e7eb")],
                  foreground=[("active", "#fff"), ("!active", "#111827")])

        self.zoom_in_btn = ttk.Button(btn_frame, text="Zoom In", command=self.zoom_in, style="Viewer.TButton")
        self.zoom_in_btn.pack(side="left", padx=5)

        self.zoom_out_btn = ttk.Button(btn_frame, text="Zoom Out", command=self.zoom_out, style="Viewer.TButton")
        self.zoom_out_btn.pack(side="left", padx=5)

    def show_image(self):
        w, h = (int(self.original_image.width * self.zoom), int(self.original_image.height * self.zoom))
        resized = self.original_image.resize((w, h), Image.LANCZOS)
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
# Encryptor UI Class
# ====================

class Encryptor:
    def __init__(self, root):
        self.root = root
        self.create_widgets()

    def create_widgets(self):
        style = ttk.Style()
        style.theme_use('default')

        background_color = "#ffffff"
        card_color = "#f9fafb"
        label_color = "#6b7280"
        header_color = "#111827"
        button_bg = "#111827"
        button_active_bg = "#374151"
        button_fg = "#ffffff"

        # Configure styles
        style.configure("TFrame", background=background_color)
        style.configure("Card.TFrame", background=card_color, relief="flat", padding=20)
        style.configure("TLabel", background=background_color, foreground=label_color, font=("Inter", 16))
        style.configure("Header.TLabel", background=background_color, foreground=header_color, font=("Inter", 48, "bold"))
        style.configure("TEntry", foreground="#111827", fieldbackground="#ffffff", background="#ffffff",
                        font=("Inter", 16))
        style.configure("TCombobox", foreground="#111827", fieldbackground="#ffffff", background="#ffffff",
                        font=("Inter", 16))
        style.configure("TButton", font=("Inter", 16, "bold"),
                        background=button_bg, foreground=button_fg, padding=14, borderwidth=0)
        style.map("TButton",
                  background=[("active", button_active_bg), ("!active", button_bg)],
                  foreground=[("active", button_fg), ("!active", button_fg)])

        # Main frame with scroll
        scroll_frame = ScrollableFrame(self.root)
        scroll_frame.pack(fill="both", expand=True, padx=40, pady=40)

        container = scroll_frame.frame
        container.columnconfigure(0, weight=1)

        title = ttk.Label(container, text="Encrypt File", style="Header.TLabel")
        title.grid(row=0, column=0, sticky="w", pady=(0, 30))

        file_label = ttk.Label(container, text="Select a file to encrypt:")
        file_label.grid(row=1, column=0, sticky="w", pady=(0, 8))

        file_frame = ttk.Frame(container, style="Card.TFrame")
        file_frame.grid(row=2, column=0, sticky="ew", pady=(0, 24))
        file_frame.columnconfigure(0, weight=1)

        self.file_entry = ttk.Entry(file_frame)
        self.file_entry.grid(row=0, column=0, sticky="ew", ipady=10, padx=(0,8))

        self.browse_button = ttk.Button(file_frame, text="Browse", command=self.browse_file)
        self.browse_button.grid(row=0, column=1, ipadx=20, ipady=14)

        expiry_label = ttk.Label(container, text="Select expiry date and time:")
        expiry_label.grid(row=3, column=0, sticky="w", pady=(0, 8))

        self.calendar = Calendar(container, background=card_color, foreground=header_color,
                                 selectbackground=button_bg, selectforeground="#FFF",
                                 bordercolor=card_color, headersbackground=card_color,
                                 normalbackground=card_color, normalforeground=header_color,
                                 weekendbackground=card_color, weekendforeground=header_color,
                                 othermonthbackground=card_color, othermonthwebackground=card_color,
                                 othermonthforeground="#64748B", font=("Inter", 12))
        self.calendar.grid(row=4, column=0, sticky="ew", pady=(0, 24))

        time_frame = ttk.Frame(container, style="Card.TFrame")
        time_frame.grid(row=5, column=0, sticky="w", pady=(0, 24))

        self.hour_entry = ttk.Combobox(time_frame, values=[f"{i:02}" for i in range(24)],
                                       width=8, state="readonly", font=("Inter", 16))
        self.hour_entry.set("Hour")
        self.hour_entry.grid(row=0, column=0, padx=(0, 12), ipady=8)

        self.minute_entry = ttk.Combobox(time_frame, values=[f"{i:02}" for i in range(60)],
                                         width=8, state="readonly", font=("Inter", 16))
        self.minute_entry.set("Minute")
        self.minute_entry.grid(row=0, column=1, ipady=8)

        # Preference Selection
        pref_label = ttk.Label(container, text="Select Identifier Preference:", wraplength=700)
        pref_label.grid(row=6, column=0, sticky="w", pady=(0, 8))

        self.pref_combo = ttk.Combobox(container, values=["MAC Address", "IP Address", "None"],
                                        width=20, state="readonly", font=("Inter", 16))
        self.pref_combo.set("MAC Address")  # Default preference
        self.pref_combo.grid(row=7, column=0,