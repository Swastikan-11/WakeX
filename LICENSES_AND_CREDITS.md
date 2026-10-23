# Licenses and Credits

WakeX is developed as an open-source, local-first PC orchestration utility. It relies on standard system libraries and foundational open-source packages:

## Open-Source Dependencies & Attributions

### Backend & Host
* **FastAPI** — Licensed under the MIT License. Copyright (c) 2018 Sebastián Ramírez.
* **Uvicorn** — Licensed under the BSD 3-Clause License. Copyright (c) 2017-present, Encode OSS Ltd.
* **psutil** — Licensed under the BSD 3-Clause License. Copyright (c) 2009, Jay Loden, Dave Daeschler, Giampaolo Rodola.
* **pystray** — Licensed under the GNU LGPL v3 License. Copyright (c) 2015 Moses Palmér.
* **Pillow (PIL)** — Licensed under the Historical Permission Notice and Disclaimer (HPND). Copyright (c) 1997-2001 by Secret Labs AB, 1995-2001 by Fredrik Lundh.
* **PyInstaller** — Licensed under the GNU General Public License v2 (GPLv2) with a special exception for produced executables allowing proprietary or permissive licensing of packaged applications.

### Android Companion Client
* **Android Open Source Project (AOSP)** — Apache License 2.0. Used via standard Android SDK build tools (`aapt`, `d8`, `apksigner`, `android.jar`).

### Frontend Cryptographic Fallback & Handshake
* **js-sha256** — Licensed under the MIT License. Copyright (c) 2014-2024 Chen, Yi-Cyuan.
  Used in `static/sha256.min.js` as an RFC 4231-compliant HMAC-SHA256 and SHA-256 fallback engine for plain HTTP LAN environments without Web Crypto API secure context.
* **TweetNaCl.js** — Public Domain / CC0-1.0. Ported by Dmitry Chestnykh from TweetNaCl by Daniel J. Bernstein, Bernard van Gastel, Wesley Janssen, Tanja Lange, Peter Schwabe, Sjaak Smetsers.
  Used in `static/tweetnacl.min.js` for ephemeral X25519 key exchange in plain HTTP LAN environments.

### Inspiration & Architectural Paradigms
Concepts and network patterns in WakeX were informed by open-source remote control and device integration projects:
* **KDE Connect** (GPLv2+) — Local-first device pairing and network discovery concepts.
* **HASS.Agent** (MIT) — Windows desktop telemetry collection and power state monitoring patterns.
* **Duorem / ShutApp** (GPL) — Target device isolation and Wake-on-LAN broadcast burst structures.

*Note: All code in WakeX was written cleanly and independently to guarantee complete license compliance and zero third-party license conflicts.*
