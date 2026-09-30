<div align="center">
  <img src="logo.png" alt="DRM Guard Logo" width="150" />
  <h1>DRM Guard Suite (v5.0)</h1>
  <p><strong>Military-Grade Digital Rights Management for Highly Sensitive Assets</strong></p>
</div>

---

## 📖 Project Overview

**DRM Guard** is a comprehensive, production-grade software suite designed to protect highly sensitive corporate and intellectual property (PDFs, Images, and proprietary files). Its core mission is to ensure that your data can be distributed to clients and partners securely, completely eliminating the risk of unauthorized distribution, screenshots, screen recording, and unauthorized forwarding.

Whether you operate in a completely offline air-gapped environment or require centralized, real-time revocation and auditing via a centralized Key Management Server (KMS), DRM Guard has you covered.

---

## 🛡️ Core Security Features

- **In-Memory Zero-Footprint Decryption:** The decrypted contents of your file *never* touch the user's hard drive. It is decrypted directly into RAM and destroyed when the viewer is closed.
- **Dual-Mode Operation (Local & Server):** Choose between 100% offline encryption or online Key Management Server (KMS) integration for real-time validation and key retrieval.
- **Hardware Binding:** Cryptographically lock your documents to a recipient's specific physical machine (MAC address) or network infrastructure (IP address).
- **Anti-Capture Defenses:** Low-level Windows API hooks aggressively monitor and block screen recording (like OBS) and screenshot tools (like Snipping Tool) while the document is open.
- **Time-Bomb Expiry & Revocation:** Files permanently self-destruct after a strict date and time. In Server Mode, you can remotely revoke access to any file instantly.
- **Mobile-Delegated Biometrics (TOTP 2FA):** Enforce identity verification using the recipient's phone (FaceID/Fingerprint) via standard Authenticator apps before a file opens.
- **AES-256-CBC Encryption:** Industry-standard military-grade encryption using PKCS7 padding and PBKDF2-SHA256 password hashing.

---