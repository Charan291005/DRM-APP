# DRM Guard v4.0 — Secure File Protection Suite

> **Production-grade Digital Rights Management (DRM) desktop application.**  
> Built with Python + Tkinter. AES-256-CBC encryption, MAC address device locking, in-memory decryption, and a premium dark UI.

---

## Features

| Feature | Details |
|---|---|
| **AES-256-CBC Encryption** | Industry-standard symmetric encryption with PKCS7 padding |
| **MAC Address Device Lock** | Files can be bound to a specific machine's hardware MAC address |
| **IP Address Lock** | Alternatively lock files to a specific network IP |
| **Expiry Date & Time** | Files automatically become inaccessible after a set date/time |
| **In-Memory Decryption** | Decrypted bytes never touch the hard drive — RAM only |
| **PBKDF2-SHA256 Password** | Passwords are stored as a secure hash, never in plaintext |
| **Watermark Overlay** | Optional dynamic watermark on decrypted PDFs & images |
| **Drag & Drop** | Drop files directly onto the app window to encrypt/decrypt |
| **Audit Log** | Every encrypt/decrypt event is logged with timestamp, MAC & IP |
| **Anti-Screenshot** | Uses Windows `SetWindowDisplayAffinity` to block screen capture |
| **PDF Viewer** | Built-in secure PDF viewer using PyMuPDF (in-memory rendering) |
| **Image Viewer** | Built-in secure image viewer supporting PNG, JPG, BMP, WEBP, TIFF |
| **Password Strength Meter** | Real-time 4-level password strength indicator |

---

## Supported File Types

- **Encrypt:** Any file type
- **Preview after decrypt:** PDF, PNG, JPG, JPEG, GIF, BMP, WEBP, TIFF

---

## Installation

### 1. Clone the repository
```bash
git clone https://github.com/Charan291005/DRM-APP.git
cd DRM-APP
```

### 2. Create a virtual environment (recommended)
```bash
python -m venv .venv
.venv\Scripts\activate   # Windows
```

### 3. Install dependencies
```bash
pip install pillow pymupdf pycryptodome tkcalendar tkinterdnd2
```

### 4. Run the application
```bash
python drm_guard.py
```

---

## Usage

### Encrypting a File
1. Open the app and go to **Encrypt File** in the sidebar
2. Drag & drop a file (or click to browse)
3. Set an **expiry date and time**
4. Choose a **device lock** (MAC Address recommended)
5. Enter a **strong password** and confirm it
6. Optionally enable a **watermark overlay**
7. Click **ENCRYPT FILE** — the `.drm` file is saved next to your original

### Decrypting a File
1. Go to **Decrypt File** in the sidebar
2. Drop the `.drm` file onto the drop zone
3. Enter the password
4. Click **DECRYPT & VIEW** — the file opens in the secure in-memory viewer

### Viewing the Audit Log
- Click **Audit Log** in the sidebar to see all events  
- Log is saved as `drm_audit.csv` in the application directory

---

## Security Architecture

```
Encryption:
  plaintext  →  AES-256-CBC(key=SHA256(MAC||expiry||password))  →  .drm file
  
Header (stored in .drm):
  expiry | identifier | extension | PBKDF2_SHA256(password) | watermark_b64 | opacity

Decryption:
  .drm file  →  verify password hash  →  check expiry  →  check MAC
             →  AES-256-CBC decrypt  →  bytes in RAM  →  secure viewer
```

**Key improvements over v3.0 (test3.py):**
- ✅ Password is stored as a PBKDF2 hash — not plaintext
- ✅ Decryption is entirely in-memory (no temp files)  
- ✅ Anti-screenshot protection on Windows
- ✅ PKCS7 padding (replaces zero-byte padding)

---

## Tech Stack

| Component | Library |
|---|---|
| GUI | Tkinter + tkinterdnd2 + tkcalendar |
| Encryption | PyCryptodome (AES-256-CBC) |
| PDF Rendering | PyMuPDF (fitz) |
| Image Processing | Pillow |
| Password Hashing | hashlib (PBKDF2-HMAC-SHA256) |

---

## Roadmap (Startup Phase)

- [ ] **Phase 2:** FastAPI backend — Centralized Key Management System (KMS)
- [ ] **Phase 3:** Server-side MAC validation + online key fetching
- [ ] **Phase 4:** Creator Web Dashboard (React) — manage files, revoke access, view analytics

---

## License

MIT License — see [LICENSE](LICENSE) file.

---

*Built as a college project, evolving into a production-grade startup.*
