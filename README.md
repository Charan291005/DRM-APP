<div align="center">
  <img src="logo.png" alt="DRM Guard Logo" width="150" />
  <h1>DRM Guard Suite</h1>
  <p><strong>Military-Grade, Offline-First Digital Rights Management</strong></p>
</div>

---

**DRM Guard** is a production-grade software suite designed to protect highly sensitive corporate assets (PDFs, Images, and general files). It ensures that proprietary data can be securely distributed to clients and partners without the risk of unauthorized distribution, data theft, or prolonged access.

## 🛡️ Core Security Features

- **Mobile-Delegated Biometrics (TOTP 2FA):** Forces users to verify identity using their phone's FaceID/Fingerprint via Authenticator apps (100% offline).
- **Zero-Footprint Decryption:** Files are decrypted directly into RAM. Unencrypted bytes *never* touch the hard drive.
- **Hardware Binding:** Documents can be cryptographically locked to a recipient's specific physical machine (MAC address) or network (IP address).
- **Anti-Capture Defenses:** Employs low-level Windows APIs and process monitoring to instantly block screen recording (OBS) and screenshot tools (Snipping Tool).
- **Time-Bomb Expiry:** Files permanently self-destruct (become inaccessible) after a strict expiration date and time.
- **AES-256-CBC Encryption:** Industry-standard encryption using PKCS7 padding and PBKDF2-SHA256 password hashing.

---

## 🏗️ The Dual-Software Architecture

To eliminate the risk of reverse-engineering or data theft, the suite is surgically split into two entirely isolated executables:

### 1. `drm_admin.exe` (Internal Use)
Controlled by your organization. Used to generate `.drm` files, set strict access policies, generate 2FA biometric keys, and view local audit logs.

### 2. `drm_client.exe` (External Distribution)
Distributed to your customers. It acts as a strictly locked-down viewer. **All encryption algorithms and audit logic have been physically removed from this software.** Even if reverse-engineered, attackers cannot extract logic to manipulate files.

---

## 🚀 Quick Start

### 1. Installation
Clone the repository and install the required dependencies:
```bash
git clone https://github.com/Charan291005/DRM-APP.git
cd DRM-APP
pip install pyotp pillow pymupdf pycryptodome tkcalendar tkinterdnd2
```

### 2. Compiling Executables (For Production)
Distribute the software securely as standalone `.exe` files without exposing your Python source code.
```bash
pip install pyinstaller

# Build the Admin Application
pyinstaller --noconsole --onefile --icon=logo.ico --add-data "logo.png;." --add-data "logo.ico;." drm_admin.py

# Build the Client Viewer
pyinstaller --noconsole --onefile --icon=logo.ico --add-data "logo.png;." --add-data "logo.ico;." drm_client.py
```
> The compiled files will be located in the `dist/` folder.

---

## 📖 Operational Workflow

### Securing an Asset
1. Open `drm_admin.exe`.
2. Drag and drop the confidential file into the encryptor.
3. Apply policies: Expiry Date, MAC Address lock, and a strong Password.
4. **(Optional)** Check **Require Phone Authenticator** to enforce mobile biometric 2FA.
5. Click **ENCRYPT**. A secure `.drm` file is generated.

### Secure Viewing (Client Side)
1. The client opens `drm_client.exe` and drops the `.drm` file into it.
2. They enter the provided password.
3. If 2FA was enabled, the app will halt and demand a live 6-digit Authenticator code (requiring phone biometrics).
4. The file securely opens in the locked-down viewer. Copying, saving, and screenshots are aggressively blocked.

---

<div align="center">
  <i>Built with Python — Evolving into a production-grade startup.</i>
</div>
