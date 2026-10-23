// WakeX Hub - Core Frontend Logic (Target-Isolated Multi-Device Architecture)

let currentPowerAction = null;
let currentActiveDeviceId = null;
let cachedDevices = [];
let targetRenameDeviceId = null;

document.addEventListener("DOMContentLoaded", async () => {
  initTheme();
  initNavigation();
  checkOnboarding();
  initBotAssistant();
  initPowerModals();
  await initAuthentication();
  startAppServices();
});

// --- Cryptographic HMAC-SHA256 & SHA256 Engine ---
async function computeSha256Hex(dataBytesOrStr) {
  if (window.crypto && window.crypto.subtle) {
    try {
      const buffer = typeof dataBytesOrStr === "string" ? new TextEncoder().encode(dataBytesOrStr) : dataBytesOrStr;
      const digest = await window.crypto.subtle.digest("SHA-256", buffer);
      return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
    } catch (e) {
      // Fallback
    }
  }
  if (window.sha256) {
    return window.sha256.hex(dataBytesOrStr);
  }
  throw new Error("No cryptographic SHA-256 provider available.");
}

async function computeHmacSha256Hex(secret, message) {
  if (window.crypto && window.crypto.subtle) {
    try {
      const encoder = new TextEncoder();
      const keyData = encoder.encode(secret);
      const cryptoKey = await window.crypto.subtle.importKey(
        "raw", keyData, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
      );
      const sigBuffer = await window.crypto.subtle.sign("HMAC", cryptoKey, encoder.encode(message));
      return Array.from(new Uint8Array(sigBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
    } catch (e) {
      // Fallback
    }
  }
  if (window.sha256 && typeof window.sha256.hmac === "function") {
    return window.sha256.hmac.hex(secret, message);
  }
  throw new Error("No cryptographic HMAC-SHA256 provider available.");
}

async function getAuthHeaders(method = "GET", path = "", bodyStr = "") {
  const headers = {
    "Content-Type": "application/json"
  };

  const localToken = localStorage.getItem("wakex_local_token");
  if (localToken) {
    headers["X-WakeX-Local-Token"] = localToken;
  }

  // 1. Hardware-Backed Native Bridge in Android Companion (Prefer Native Bridge)
  if (window.AndroidWakeX && typeof window.AndroidWakeX.signRequest === "function") {
    const nativeId = window.AndroidWakeX.getClientId();
    if (nativeId) {
      const ts = Math.floor(Date.now() / 1000).toString();
      const nonce = (window.crypto && typeof window.crypto.getRandomValues === "function")
        ? Array.from(window.crypto.getRandomValues(new Uint8Array(8))).map(b => b.toString(16).padStart(2, '0')).join('')
        : (Date.now().toString(16) + Math.random().toString(16).substring(2, 10));
      const bodyHex = await computeSha256Hex(bodyStr || "");
      const sig = window.AndroidWakeX.signRequest(method, path, ts, nonce, bodyHex);
      if (sig) {
        headers["X-WakeX-Client-Id"] = nativeId;
        headers["X-WakeX-Timestamp"] = ts;
        headers["X-WakeX-Nonce"] = nonce;
        headers["X-WakeX-Signature"] = sig;
        return headers;
      }
    }
  }

  // 2. Browser Signing (Supports both Web Crypto API in secure contexts and vendored js-sha256 on plain HTTP)
  const clientId = localStorage.getItem("wakex_client_id");
  const clientSecret = localStorage.getItem("wakex_client_secret");

  if (clientId && clientSecret) {
    const ts = Math.floor(Date.now() / 1000).toString();
    const nonce = (window.crypto && typeof window.crypto.getRandomValues === "function")
      ? Array.from(window.crypto.getRandomValues(new Uint8Array(8))).map(b => b.toString(16).padStart(2, '0')).join('')
      : (Date.now().toString(16) + Math.random().toString(16).substring(2, 10));

    const bodyHex = await computeSha256Hex(bodyStr || "");
    const message = `${method.toUpperCase()}:${path}:${ts}:${nonce}:${bodyHex}`;
    const sig = await computeHmacSha256Hex(clientSecret, message);

    headers["X-WakeX-Client-Id"] = clientId;
    headers["X-WakeX-Timestamp"] = ts;
    headers["X-WakeX-Nonce"] = nonce;
    headers["X-WakeX-Signature"] = sig;
  }

  return headers;
}

async function apiFetch(path, options = {}) {
  options.method = (options.method || "GET").toUpperCase();
  const bodyStr = options.body ? (typeof options.body === "string" ? options.body : JSON.stringify(options.body)) : "";
  if (bodyStr) options.body = bodyStr;
  options.headers = await getAuthHeaders(options.method, path, bodyStr);

  const timeoutMs = options.timeoutMs || 12000;
  const controller = new AbortController();
  const timer = setTimeout(() => {
    controller.abort(new Error("Request timed out after " + (timeoutMs / 1000) + "s. Plain-language fix: Ensure your PC is awake and reachable on your local Wi-Fi."));
  }, timeoutMs);

  if (!options.signal) {
    options.signal = controller.signal;
  }

  try {
    const res = await fetch(path, options);
    clearTimeout(timer);
    if (res.status === 401 && !path.startsWith("/api/auth/")) {
      showClientPairModal();
    }
    return res;
  } catch (err) {
    clearTimeout(timer);
    if (err.name === "AbortError" || (err.message && err.message.includes("timed out"))) {
      throw new Error("Request timed out. Plain-language fix: Check that your host PC is turned on and connected to the same Wi-Fi.");
    }
    if (err.name === "TypeError" && err.message && err.message.includes("fetch")) {
      throw new Error("Cannot connect to WakeX Hub. Plain-language fix: Verify your device is on the same local network subnet.");
    }
    throw err;
  }
}

function authHeaders() {
  const headers = { "Content-Type": "application/json" };
  const localToken = localStorage.getItem("wakex_local_token");
  if (localToken) headers["X-WakeX-Local-Token"] = localToken;
  return headers;
}

async function initAuthentication() {
  const isLocal = window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1";
  if (isLocal) {
    try {
      const res = await fetch("/api/auth/local-token");
      if (res.ok) {
        const data = await res.json();
        localStorage.setItem("wakex_local_token", data.token);
      }
    } catch (e) {
      console.warn("Could not retrieve local token:", e);
    }

    // Check if triggered from Tray Menu with a specific pairing code
    if (window.location.hash && window.location.hash.includes("pair-code=")) {
      const code = window.location.hash.split("pair-code=")[1].substring(0, 6);
      const display = document.getElementById("pairing-code-display");
      const modal = document.getElementById("pairing-code-modal");
      if (display && modal) {
        display.textContent = code;
        modal.classList.add("open");
      }
    }
    return;
  }

  // If remote phone arrived with a pair code in URL (e.g. from QR scan)
  if (window.location.hash && window.location.hash.includes("pair=")) {
    const code = window.location.hash.split("pair=")[1].substring(0, 6);
    const codeInput = document.getElementById("client-pair-code");
    if (codeInput) codeInput.value = code;
    showClientPairModal();
  }

  // If remote client (phone or LAN browser)
  try {
    const res = await fetch("/api/auth/status");
    if (res.ok) {
      const status = await res.json();
      const hasKey = !!localStorage.getItem("wakex_client_secret");
      if (!hasKey) {
        if (!status.pairing_required) {
          // Zero-config onboarding auto-pairing on first run
          await autoPairFirstClient();
        } else {
          showClientPairModal();
        }
      }
    }
  } catch (e) {
    console.warn("Auth status check:", e);
  }
}

async function autoPairFirstClient() {
  try {
    const deviceName = navigator.userAgent.includes("Android") ? "Android Phone" : "Browser Client";
    const res = await fetch("/api/auth/pair", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ client_name: deviceName })
    });
    if (res.ok) {
      const data = await res.json();
      localStorage.setItem("wakex_client_id", data.client_id);
      localStorage.setItem("wakex_client_secret", data.client_secret);
      if (window.AndroidWakeX && typeof window.AndroidWakeX.saveCredentials === "function") {
        window.AndroidWakeX.saveCredentials(data.client_id, data.client_secret);
      }
    }
  } catch (e) {
    console.error("Auto-pair error:", e);
  }
}

function showClientPairModal(reason) {
  const modal = document.getElementById("client-pair-modal");
  const desc = document.querySelector("#client-pair-modal .modal-desc");
  if (desc) {
    if (reason === "re-pair" || localStorage.getItem("wakex_client_id")) {
      desc.textContent = "⚠️ Hub upgraded or pairing session expired. Enter the fresh 6-digit PIN shown on your PC to re-pair:";
    } else {
      desc.textContent = "Enter the 6-digit pairing code shown on your PC Hub:";
    }
  }
  if (modal) modal.classList.add("open");
}

function closeClientPairModal() {
  const modal = document.getElementById("client-pair-modal");
  if (modal) modal.classList.remove("open");
}

function uint8ToHex(arr) {
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToUint8(hexStr) {
  const bytes = new Uint8Array(hexStr.length / 2);
  for (let i = 0; i < hexStr.length; i += 2) {
    bytes[i / 2] = parseInt(hexStr.substr(i, 2), 16);
  }
  return bytes;
}

function generateRandomHex(byteCount) {
  const arr = new Uint8Array(byteCount);
  if (window.crypto && window.crypto.getRandomValues) {
    window.crypto.getRandomValues(arr);
  } else {
    for (let i = 0; i < byteCount; i++) arr[i] = Math.floor(Math.random() * 256);
  }
  return uint8ToHex(arr);
}

async function submitClientPairing() {
  const input = document.getElementById("client-pair-code");
  const code = input ? input.value.trim() : "";
  if (!code || code.length !== 6 || !/^\d{6}$/.test(code)) {
    alert("Please enter a valid 6-digit numeric pairing PIN shown on your PC Hub.");
    return;
  }

  if (typeof nacl === "undefined" || !nacl.box || !nacl.box.keyPair) {
    alert("Cryptographic module (TweetNaCl) is loading. Please refresh and try again.");
    return;
  }

  let clientId = localStorage.getItem("wakex_client_id");
  if (!clientId) {
    clientId = "client_" + generateRandomHex(8);
  }

  const clientName = navigator.userAgent.includes("Android") ? "Android Companion" : "WakeX Web Client";

  try {
    // Step 1: Ephemeral X25519 Key Generation
    const clientKeyPair = nacl.box.keyPair();
    const clientNonceHex = generateRandomHex(16);
    const clientPubHex = uint8ToHex(clientKeyPair.publicKey);

    // Step 2: Key Exchange Endpoint
    const resEx = await fetch("/api/auth/pair/exchange", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_id: clientId,
        client_name: clientName,
        client_public_key: clientPubHex,
        client_nonce: clientNonceHex
      })
    });

    if (!resEx.ok) {
      const errData = await resEx.json().catch(() => ({}));
      throw new Error(errData.detail || "Pairing exchange rejected by Hub.");
    }

    const exData = await resEx.json();
    const sessionId = exData.session_id;
    const hubPubHex = exData.hub_public_key;
    const hubNonceHex = exData.hub_nonce;

    // Step 3: Compute ECDH Shared Secret
    const hubPubBytes = hexToUint8(hubPubHex);
    const sharedSecretBytes = nacl.scalarMult(clientKeyPair.secretKey, hubPubBytes);

    // Step 4: Derive Long-Term Client Secret via HKDF-SHA256 (RFC 5869)
    const saltBytes = hexToUint8(clientNonceHex + hubNonceHex);
    const prkHex = sha256.hmac.hex(saltBytes, sharedSecretBytes);
    const infoBytes = new TextEncoder().encode("wakex-client-secret-v1\x01");
    const derivedSecretHex = sha256.hmac.hex(hexToUint8(prkHex), infoBytes);

    // Step 5: Compute Handshake Transcript & Mutual PIN Proof
    const transcript = `${clientId}:${clientPubHex}:${clientNonceHex}:${hubPubHex}:${hubNonceHex}`;
    const clientProofHex = sha256.hmac.hex(code, `CLIENT:${transcript}`);

    // Step 6: Authenticate Handshake with PIN
    const resAuth = await fetch("/api/auth/pair/authenticate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        session_id: sessionId,
        pairing_code: code,
        client_proof: clientProofHex
      })
    });

    if (resAuth.ok) {
      localStorage.setItem("wakex_client_id", clientId);
      localStorage.setItem("wakex_client_secret", derivedSecretHex);
      if (window.AndroidWakeX && typeof window.AndroidWakeX.saveCredentials === "function") {
        window.AndroidWakeX.saveCredentials(clientId, derivedSecretHex);
      }
      closeClientPairModal();
      alert("✅ Phone paired successfully with WakeX Hub!\n256-bit cryptographic local keys established.");
      startAppServices();
    } else {
      const authErr = await resAuth.json().catch(() => ({}));
      let msg = authErr.detail || "Pairing authentication failed.";
      if (resAuth.status === 429) {
        msg = "⚠️ PIN revoked or temporary lockout: Too many incorrect PIN attempts (limit 5). Please generate a fresh PIN from your PC system tray.";
      } else if (resAuth.status === 401) {
        msg = "❌ Incorrect or expired PIN. Please generate a fresh PIN on your PC Hub and enter it within 5 minutes.";
      }
      alert(msg);
    }
  } catch (e) {
    alert(`Pairing error: ${e.message}\n\nPlain-language fix: Ensure your device is on the same Wi-Fi network as the PC.`);
  }
}

async function resetEverythingSecurity() {
  const confirmed = confirm(
    "⚠️ FACTORY RESET SECURITY\n\n" +
    "This will permanently revoke all paired mobile devices, clear replay security nonces, and revoke active sessions on this PC Hub.\n\n" +
    "You will need to re-pair any phone with a new 6-digit PIN.\n\n" +
    "Are you sure you want to proceed?"
  );
  if (!confirmed) return;

  try {
    const res = await apiFetch("/api/auth/reset", { method: "POST" });
    if (res.ok) {
      localStorage.removeItem("wakex_client_id");
      localStorage.removeItem("wakex_client_secret");
      if (window.AndroidWakeX && typeof window.AndroidWakeX.saveCredentials === "function") {
        window.AndroidWakeX.saveCredentials("", "");
      }
      alert("✅ Security state reset successfully. All paired devices revoked.");
      location.reload();
    } else {
      const err = await res.json().catch(() => ({}));
      alert("Reset error: " + (err.detail || "Could not complete reset"));
    }
  } catch (e) {
    alert("Reset failed: " + e.message);
  }
}

async function openPairingCodeModal() {
  const modal = document.getElementById("pairing-code-modal");
  const display = document.getElementById("pairing-code-display");
  if (display) display.textContent = "GENERATING...";
  if (modal) modal.classList.add("open");

  try {
    const res = await apiFetch("/api/auth/pairing-code", { method: "POST" });
    const data = await res.json();
    if (res.ok && display) {
      display.textContent = data.pairing_code;
    } else {
      if (display) display.textContent = "ERROR";
      alert(data.detail || "Could not generate pairing code.");
    }
  } catch (e) {
    if (display) display.textContent = "ERROR";
    alert(`Error: ${e.message}`);
  }
}

function closePairingCodeModal() {
  const modal = document.getElementById("pairing-code-modal");
  if (modal) modal.classList.remove("open");
}

function startAppServices() {
  initWebSocket();
  loadDevices();
  loadWorkspaces();
  loadSchedule();
  loadScreenSnapshot();
  loadReadinessReport();
}

async function loadReadinessReport() {
  try {
    const res = await apiFetch("/api/system/readiness");
    if (!res.ok) return;
    const data = await res.json();

    const badge = document.getElementById("readiness-badge");
    const title = document.getElementById("readiness-title");
    const sub = document.getElementById("readiness-subtitle");
    const list = document.getElementById("readiness-checklist");
    const tipsBox = document.getElementById("readiness-tips");

    if (badge) {
      badge.textContent = `${data.readiness_score}%`;
      const color = data.readiness_score >= 80 ? "var(--accent-green)" : (data.readiness_score >= 50 ? "var(--accent-cyan)" : "var(--accent-amber)");
      badge.style.color = color;
      badge.style.borderColor = color;
    }

    if (title && sub) {
      const activeAd = data.active_adapter ? `${data.active_adapter.name} (${data.active_adapter.type})` : "No active link";
      title.textContent = `WoL Hardware Readiness: ${data.status.toUpperCase()} (${data.readiness_score}/100)`;
      sub.textContent = `Active Interface: ${activeAd} • AC Power: ${data.ac_power ? "Connected" : "Battery"}`;
    }

    if (list) {
      // 1. Diagnostics Checks with Plain-Language Fixes
      let html = (data.checks || []).map(c => {
        const icon = c.status === "pass" ? "✅" : (c.status === "warning" ? "⚠️" : "ℹ️");
        const color = c.status === "pass" ? "var(--accent-green)" : (c.status === "warning" ? "var(--accent-amber)" : "var(--accent-cyan)");
        const fixHtml = c.fix ? `<div style="margin-top: 4px; font-size: 0.78rem; color: #ff6b7e;"><strong>🔧 Plain-language fix:</strong> ${escapeHtml(c.fix)}</div>` : "";
        return `
          <div style="display: flex; align-items: flex-start; gap: 8px; font-size: 0.83rem; background: rgba(255,255,255,0.02); padding: 8px 10px; border-radius: 6px; border-left: 2px solid ${color};">
            <span>${icon}</span>
            <div style="flex: 1;">
              <strong style="color: #fff;">${escapeHtml(c.name)}:</strong>
              <span style="color: var(--text-secondary); margin-left: 4px;">${escapeHtml(c.detail)}</span>
              ${fixHtml}
            </div>
          </div>
        `;
      }).join("");

      // 2. Adapter Wake Guidance: Explicitly show which MAC will actually wake the PC
      if (data.adapters && data.adapters.length > 0) {
        html += `<div style="margin-top: 12px; margin-bottom: 6px; font-weight: 700; font-size: 0.88rem; color: #fff;">🔌 Network Cards & Wake Verdicts:</div>`;
        html += data.adapters.map(ad => {
          const isPrimary = ad.is_primary_cold_wake;
          const badgeColor = isPrimary ? "var(--accent-green)" : "var(--accent-cyan)";
          const badgeText = isPrimary ? "COLD WAKE (0W SHUTDOWN)" : "STANDBY WAKE (WoWLAN)";
          return `
            <div style="background: rgba(0,0,0,0.3); border: 1px solid var(--border-color); border-radius: 8px; padding: 10px 12px; margin-top: 6px; font-size: 0.82rem;">
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px; flex-wrap: wrap; gap: 6px;">
                <span style="font-weight: 700; color: #fff;">${escapeHtml(ad.name)} <span style="font-weight: 400; color: var(--text-secondary);">(${escapeHtml(ad.type)})</span></span>
                <span style="font-size: 0.72rem; font-weight: 700; padding: 2px 8px; border-radius: 12px; background: rgba(255,42,68,0.12); color: ${badgeColor}; border: 1px solid ${badgeColor};">${badgeText}</span>
              </div>
              <div style="color: var(--text-secondary); font-family: monospace; font-size: 0.85rem; margin-bottom: 4px;">MAC: <strong style="color: #fff;">${escapeHtml(ad.mac)}</strong></div>
              <div style="font-size: 0.8rem; color: #a1a1aa; line-height: 1.4;">${escapeHtml(ad.verdict)}</div>
            </div>
          `;
        }).join("");
      }

      list.innerHTML = html;
    }

    if (tipsBox) {
      if (data.actionable_tips && data.actionable_tips.length > 0) {
        tipsBox.style.display = "block";
        tipsBox.innerHTML = `<strong>💡 Recommendations:</strong><ul style="margin: 4px 0 0 18px; padding: 0;">` +
          data.actionable_tips.map(t => `<li>${escapeHtml(t)}</li>`).join("") +
          `</ul>`;
      } else {
        tipsBox.style.display = "none";
      }
    }
  } catch (e) {
    console.warn("Readiness report error:", e);
  }
}

async function testWolPacketSelf() {
  try {
    const res = await apiFetch("/api/system/test-wol", { method: "POST" });
    const data = await res.json();
    if (res.ok) {
      const macs = (data.tested_macs || []).join(", ");
      const subnets = (data.broadcast_targets || []).join(", ");
      alert(`⚡ [WAKE-ON-LAN SELF-TEST SUCCESS]\n\n` +
            `Magic Packets broadcasted across ports 9 and 7.\n\n` +
            `• Target MACs: ${macs}\n` +
            `• Broadcast Subnets: ${subnets}\n` +
            `• Primary Cold Wake: ${data.primary_cold_wake_mac || "Ethernet"}\n` +
            `• Standby Wake: ${data.standby_wake_mac || "Wi-Fi"}\n\n` +
            `Your network socket and packet formatting are 100% operational.`);
    } else {
      alert(`❌ WoL Test Failed: ${data.detail || data.message}\n\nPlain-language fix: Ensure your host PC has an active network link and ports 9/7 are not blocked.`);
    }
  } catch (e) {
    alert(`WoL Test Error: ${e.message}\n\nPlain-language fix: Verify your connection to the WakeX Hub.`);
  }
}

// --- Navigation ---
function initNavigation() {
  const navItems = document.querySelectorAll(".nav-item");
  const bottomNavItems = document.querySelectorAll(".bottom-nav-item");
  const sections = document.querySelectorAll(".view-section");
  const sidebar = document.querySelector(".sidebar");
  const menuToggle = document.querySelector(".menu-toggle");
  const mobileMenuTrigger = document.getElementById("mobile-menu-trigger");
  const backdrop = document.getElementById("sidebar-backdrop");

  function closeSidebar() {
    if (sidebar) sidebar.classList.remove("open");
    if (backdrop) backdrop.classList.remove("active");
  }

  function openSidebar() {
    if (sidebar) sidebar.classList.add("open");
    if (backdrop) backdrop.classList.add("active");
  }

  function toggleSidebar() {
    if (sidebar && sidebar.classList.contains("open")) {
      closeSidebar();
    } else {
      openSidebar();
    }
  }

  function switchView(targetId) {
    navItems.forEach(n => {
      if (n.getAttribute("data-target") === targetId) {
        n.classList.add("active");
      } else {
        n.classList.remove("active");
      }
    });

    bottomNavItems.forEach(b => {
      if (b.getAttribute("data-target") === targetId) {
        b.classList.add("active");
      } else {
        b.classList.remove("active");
      }
    });

    sections.forEach(s => s.classList.remove("active"));
    const targetSection = document.getElementById(targetId);
    if (targetSection) targetSection.classList.add("active");

    closeSidebar();
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  navItems.forEach(item => {
    item.addEventListener("click", () => {
      const targetId = item.getAttribute("data-target");
      if (targetId) switchView(targetId);
    });
  });

  bottomNavItems.forEach(item => {
    item.addEventListener("click", () => {
      const targetId = item.getAttribute("data-target");
      if (targetId) switchView(targetId);
    });
  });

  if (menuToggle) {
    menuToggle.addEventListener("click", toggleSidebar);
  }

  if (mobileMenuTrigger) {
    mobileMenuTrigger.addEventListener("click", toggleSidebar);
  }

  if (backdrop) {
    backdrop.addEventListener("click", closeSidebar);
  }
}

// --- Live Telemetry WebSocket ---
function initWebSocket() {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${protocol}//${window.location.host}/ws/telemetry`;
  let socket = null;

  function connect() {
    socket = new WebSocket(wsUrl);

    socket.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        updateTelemetryUI(data);
      } catch (e) {
        console.error("Telemetry parse error", e);
      }
    };

    socket.onclose = () => {
      const delay = document.hidden ? 20000 : 3000;
      setTimeout(connect, delay);
    };
  }

  document.addEventListener("visibilitychange", () => {
    if (document.hidden) {
      console.log("[WakeX] App backgrounded: low-power mode active.");
    } else {
      console.log("[WakeX] App foregrounded: refreshing live state.");
      loadDevices();
      loadReadinessReport();
      if (!socket || socket.readyState === WebSocket.CLOSED) {
        connect();
      }
    }
  });

  connect();
}

function updateTelemetryUI(data) {
  if (data.status !== "online") return;

  const cpuVal = document.getElementById("stat-cpu");
  const cpuBar = document.getElementById("bar-cpu");
  if (cpuVal) cpuVal.textContent = `${data.cpu_percent}%`;
  if (cpuBar) cpuBar.style.width = `${Math.min(data.cpu_percent, 100)}%`;

  const ramVal = document.getElementById("stat-ram");
  const ramBar = document.getElementById("bar-ram");
  if (ramVal) ramVal.textContent = `${data.memory_percent}% (${data.memory_used_gb} GB)`;
  if (ramBar) ramBar.style.width = `${data.memory_percent}%`;

  const batVal = document.getElementById("stat-bat");
  const batBar = document.getElementById("bar-bat");
  const stateBadge = document.getElementById("stat-power-state");
  if (batVal) batVal.textContent = `${data.battery_percent}%`;
  if (batBar) batBar.style.width = `${data.battery_percent}%`;
  if (stateBadge) {
    stateBadge.textContent = data.power_plugged ? "⚡ AC Connected" : "🔋 On Battery";
  }

  const uptimeVal = document.getElementById("stat-uptime");
  if (uptimeVal) uptimeVal.textContent = data.uptime;
}

// --- Screen Snapshot ---
function loadScreenSnapshot() {
  const img = document.getElementById("screen-preview-img");
  const refreshBtn = document.getElementById("btn-refresh-screen");
  
  async function refresh() {
    if (!img) return;
    try {
      const res = await apiFetch(`/api/screen?t=${Date.now()}`);
      if (res.ok) {
        const blob = await res.blob();
        img.src = URL.createObjectURL(blob);
      }
    } catch (e) {
      console.warn("Screen snapshot error", e);
    }
  }

  if (refreshBtn) refreshBtn.addEventListener("click", refresh);
  refresh();
}

// ================= MULTI-DEVICE MANAGEMENT & TARGET ISOLATION =================

async function loadDevices() {
  try {
    const res = await apiFetch("/api/devices");
    const devices = await res.json();
    cachedDevices = devices;

    // Cache MAC addresses for Android native Wake-on-LAN
    if (window.AndroidWakeX && typeof window.AndroidWakeX.cacheMacs === "function") {
      const allMacs = devices.map(d => d.mac).filter(Boolean).join(",");
      window.AndroidWakeX.cacheMacs(allMacs);
    }

    if (!currentActiveDeviceId && devices.length > 0) {
      currentActiveDeviceId = devices[0].id;
    }

    renderDeviceDropdown(devices);
    renderActiveDeviceHeader();
    renderDevicesView(devices);
  } catch (e) {
    console.error("Failed loading devices", e);
  }
}

function renderDeviceDropdown(devices) {
  const selector = document.getElementById("quick-device-select");
  if (!selector) return;

  selector.innerHTML = "";
  devices.forEach(dev => {
    const opt = document.createElement("option");
    opt.value = dev.id;
    const isOnline = dev.status === "online";
    opt.textContent = `${isOnline ? "🟢" : "🔴"} ${dev.name} ${dev.is_current ? "(Host)" : ""}`;
    if (dev.id === currentActiveDeviceId) opt.selected = true;
    selector.appendChild(opt);
  });
}

function updatePowerDeckForDevice(dev) {
  if (!dev) return;
  const caps = dev.capabilities || {};
  
  // Sleep capability
  const sleepBtn = document.getElementById("power-btn-sleep");
  const sleepSub = document.getElementById("power-sub-sleep");
  if (sleepBtn) {
    if (caps.sleep === false) {
      sleepBtn.style.opacity = "0.45";
      sleepBtn.title = "Sleep is not supported on this device/hardware configuration";
      if (sleepSub) sleepSub.textContent = "Not supported";
    } else {
      sleepBtn.style.opacity = "1";
      sleepBtn.title = "";
      if (sleepSub) sleepSub.textContent = "Low-power standby";
    }
  }

  // Hibernate capability
  const hibBtn = document.getElementById("power-btn-hibernate");
  const hibSub = document.getElementById("power-sub-hibernate");
  if (hibBtn) {
    if (caps.hibernate === false) {
      hibBtn.style.opacity = "0.45";
      hibBtn.title = "Hibernate is disabled or unsupported (requires swap or hiberfil.sys)";
      if (hibSub) hibSub.textContent = "No swap / hiberfil";
    } else {
      hibBtn.style.opacity = "1";
      hibBtn.title = "";
      if (hibSub) hibSub.textContent = "0-Watt Cold Sleep (RTC Ready)";
    }
  }

  // Turn on capability
  const turnOnBtn = document.getElementById("power-btn-turnon");
  const turnOnSub = document.getElementById("power-sub-turnon");
  if (turnOnBtn) {
    if (!dev.mac) {
      turnOnBtn.style.opacity = "0.5";
      turnOnBtn.title = "Turn On requires a registered MAC address for Magic Packet broadcast";
      if (turnOnSub) turnOnSub.textContent = "No MAC configured";
    } else {
      turnOnBtn.style.opacity = "1";
      turnOnBtn.title = "";
      if (turnOnSub) turnOnSub.textContent = "Wake via Magic Packet";
    }
  }
}

function renderActiveDeviceHeader() {
  const activeDev = cachedDevices.find(d => d.id === currentActiveDeviceId) || cachedDevices[0];
  if (!activeDev) return;

  const nameEl = document.getElementById("dashboard-device-name");
  const metaEl = document.getElementById("dashboard-device-meta");
  const footerText = document.getElementById("sidebar-footer-text");

  if (nameEl) nameEl.textContent = activeDev.name;
  if (metaEl) {
    const roleBadge = activeDev.is_current ? "⭐ Host Machine (This PC)" : "📡 Remote Device";
    metaEl.textContent = `IP: ${activeDev.ip || "Unknown"} • MAC: ${activeDev.mac || "None"} • ${roleBadge}`;
  }
  if (footerText) {
    footerText.textContent = `${activeDev.name} • ${activeDev.status.toUpperCase()}`;
  }

  updatePowerDeckForDevice(activeDev);
}

function switchDashboardDevice(devId) {
  currentActiveDeviceId = devId;
  renderActiveDeviceHeader();
}

function renderDevicesView(devices) {
  const container = document.getElementById("devices-container");
  if (!container) return;

  container.innerHTML = "";
  if (!devices || devices.length === 0) {
    container.innerHTML = `
      <div class="empty-state-card" style="grid-column: 1 / -1; text-align: center; padding: 48px 20px; background: rgba(0,0,0,0.25); border-radius: 12px; border: 1px dashed var(--border-color);">
        <span style="font-size: 2.6rem; display: block; margin-bottom: 12px;">🖥️</span>
        <h3 style="color: #fff; margin-bottom: 8px;">No Devices Configured</h3>
        <p style="color: var(--text-secondary); font-size: 0.88rem; max-width: 440px; margin: 0 auto 16px;">
          This PC Hub will automatically appear once initialized. You can also pair secondary PCs or Linux servers running the WakeX agent.
        </p>
        <button class="btn-primary" onclick="openPairDeviceModal()" style="min-height: 48px;">➕ Pair Secondary PC</button>
      </div>
    `;
    return;
  }
  devices.forEach(dev => {
    const card = document.createElement("div");
    card.className = "device-card";
    const isOnline = dev.status === "online";
    const roleBadge = dev.is_current ? "⭐ Host Machine (This PC)" : "📡 Remote Computer";
    const icon = dev.type === "laptop" ? "💻" : (dev.type === "server" ? "🖧" : "🖥️");

    card.innerHTML = `
      <div>
        <div class="device-card-header" style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 12px;">
          <div>
            <div class="device-name-title" style="font-size: 1.15rem; font-weight: 700; display: flex; align-items: center; gap: 8px;">
              <span>${icon}</span>
              <span>${escapeHtml(dev.name)}</span>
            </div>
            <div style="font-size: 0.78rem; color: var(--accent-red); font-weight: 600; margin-top: 2px;">${roleBadge}</div>
          </div>
          <span class="device-status-pill ${isOnline ? 'online' : 'offline'}" style="display: inline-flex; align-items: center; gap: 6px; padding: 4px 10px; border-radius: 12px; font-size: 0.8rem; font-weight: 700; background: ${isOnline ? 'rgba(16,185,129,0.15)' : 'rgba(239,68,68,0.15)'}; color: ${isOnline ? 'var(--accent-green)' : 'var(--accent-red)'}; border: 1px solid ${isOnline ? 'var(--accent-green)' : 'var(--accent-red)'};">
            <span class="status-dot" style="background: ${isOnline ? 'var(--accent-green)' : 'var(--accent-red)'}; box-shadow: 0 0 6px ${isOnline ? 'var(--accent-green)' : 'var(--accent-red)'};"></span>
            ${isOnline ? 'Online & Ready' : 'Offline / Standby'}
          </span>
        </div>

        <div class="device-details-meta" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 8px; font-size: 0.82rem; background: rgba(0,0,0,0.25); padding: 10px 12px; border-radius: 8px; border: 1px solid var(--border-color);">
          <div><strong style="color: var(--text-secondary);">IP Address:</strong> <span style="font-family: monospace; color: #fff;">${dev.ip || "Not set"}</span></div>
          <div><strong style="color: var(--text-secondary);">MAC Address:</strong> <span style="font-family: monospace; color: #fff;">${dev.mac || "None"}</span></div>
          <div><strong style="color: var(--text-secondary);">Port:</strong> <span style="color: #fff;">${dev.port || 8000}</span></div>
          <div><strong style="color: var(--text-secondary);">Security:</strong> <span style="color: ${dev.auth_token || dev.is_current ? 'var(--accent-green)' : 'var(--accent-amber)'}; font-weight: 600;">${dev.is_current ? "⭐ Local Host Session" : (dev.auth_token ? "🔒 HMAC Key Armed" : "⚠️ WoL Only")}</span></div>
        </div>
      </div>

      <div class="device-card-actions">
        <button class="btn-small wake" onclick="wakeDevice('${dev.id}')" aria-label="Turn on ${escapeHtml(dev.name)} via Wake-on-LAN">
          <span>⚡</span> Turn On
        </button>
        <button class="btn-small" style="color: var(--accent-green);" onclick="currentActiveDeviceId='${dev.id}'; promptPowerAction('unlock')" aria-label="Wake display and dismiss lock for ${escapeHtml(dev.name)}">
          <span>🔓</span> Unlock
        </button>
        <button class="btn-small" onclick="openRenameModal('${dev.id}', '${escapeHtml(dev.name)}')" aria-label="Rename ${escapeHtml(dev.name)}">
          <span>✏️</span> Rename
        </button>
        ${!dev.is_current ? `
          <button class="btn-small delete" onclick="deleteDeviceConfirm('${dev.id}', '${escapeHtml(dev.name)}')" aria-label="Remove ${escapeHtml(dev.name)}">
            <span>🗑️</span> Remove
          </button>
        ` : ''}
      </div>
    `;
    container.appendChild(card);
  });
}

// --- Turn On (Wake-on-LAN) Action ---
async function wakeActiveDevice() {
  if (!currentActiveDeviceId) {
    alert("Please select a device first.");
    return;
  }
  wakeDevice(currentActiveDeviceId);
}

async function wakeDevice(devId) {
  const dev = cachedDevices.find(d => d.id === devId);
  const devName = dev ? dev.name : "Device";

  const btn = document.getElementById("btn-dashboard-turnon");
  if (btn) btn.innerHTML = `<span>⏳</span> Waking...`;

  // If running inside native Android App, also broadcast directly from phone's Wi-Fi interface
  if (window.AndroidWakeX && typeof window.AndroidWakeX.sendWoL === "function") {
    try {
      window.AndroidWakeX.sendWoL(dev ? (dev.mac || "") : "");
    } catch (err) {
      console.warn("Android native WoL call:", err);
    }
  }

  try {
    const res = await apiFetch(`/api/devices/${devId}/wake`, {
      method: "POST"
    });

    const data = await res.json();
    
    if (res.ok) {
      alert(`⚡ [TURN ON SIGNAL SENT]\n\nBroadcasted Wake-on-LAN Magic Packet to '${devName}'.\n\nTarget will power on if connected to AC or supported standby.`);
    } else {
      alert(`❌ Error sending Wake signal: ${data.detail || data.message}`);
    }
  } catch (e) {
    alert(`❌ Failed to send wake packet: ${e.message}`);
  } finally {
    if (btn) btn.innerHTML = `<span>⚡</span> Turn On PC`;
    setTimeout(loadDevices, 4000);
  }
}

// --- Rename Device Logic ---
function promptRenameActiveDevice() {
  if (!currentActiveDeviceId) return;
  const dev = cachedDevices.find(d => d.id === currentActiveDeviceId);
  if (dev) openRenameModal(dev.id, dev.name);
}

function openRenameModal(devId, currentName) {
  targetRenameDeviceId = devId;
  const modal = document.getElementById("rename-modal");
  const input = document.getElementById("rename-input");
  if (input) input.value = currentName;
  if (modal) modal.classList.add("open");
}

function closeRenameModal() {
  const modal = document.getElementById("rename-modal");
  if (modal) modal.classList.remove("open");
  targetRenameDeviceId = null;
}

async function submitDeviceRename() {
  const input = document.getElementById("rename-input");
  const newName = input ? input.value.trim() : "";
  if (!newName || !targetRenameDeviceId) return;

  try {
    const res = await apiFetch(`/api/devices/${targetRenameDeviceId}/rename`, {
      method: "POST",
      body: { new_name: newName }
    });
    const data = await res.json();
    if (res.ok) {
      closeRenameModal();
      loadDevices();
    } else {
      alert(`Error renaming device: ${data.detail || data.message}`);
    }
  } catch (e) {
    alert(`Rename failed: ${e.message}`);
  }
}

// --- Pair New Device Logic ---
function openPairDeviceModal() {
  const modal = document.getElementById("pair-modal");
  if (modal) modal.classList.add("open");
}

function closePairDeviceModal() {
  const modal = document.getElementById("pair-modal");
  if (modal) modal.classList.remove("open");
}

async function submitPairDevice() {
  const name = document.getElementById("pair-name").value.trim();
  const ip = document.getElementById("pair-ip").value.trim();
  const mac = document.getElementById("pair-mac").value.trim();
  const port = parseInt(document.getElementById("pair-port").value, 10) || 8001;
  const authToken = document.getElementById("pair-token") ? document.getElementById("pair-token").value.trim() : "";

  if (!name || !mac) {
    alert("Please provide both a Device Name and a MAC Address (for Turn On / WoL).");
    return;
  }

  try {
    const res = await apiFetch("/api/devices/pair", {
      method: "POST",
      body: { name, ip, mac, port, auth_token: authToken }
    });
    const data = await res.json();
    if (res.ok) {
      closePairDeviceModal();
      loadDevices();
      alert(`✅ Device '${name}' paired successfully!`);
    } else {
      alert(`Error pairing device: ${data.detail || data.message}`);
    }
  } catch (e) {
    alert(`Pairing failed: ${e.message}`);
  }
}

async function deleteDeviceConfirm(devId, devName) {
  if (!confirm(`Are you sure you want to remove '${devName}' from paired devices?`)) return;

  try {
    const res = await apiFetch(`/api/devices/${devId}`, {
      method: "DELETE"
    });
    if (res.ok) {
      loadDevices();
    } else {
      const data = await res.json();
      alert(`Error removing device: ${data.detail || data.message}`);
    }
  } catch (e) {
    alert(`Failed removing device: ${e.message}`);
  }
}

// ================= CRITICAL TARGET-ISOLATED POWER MODALS =================

function initPowerModals() {
  const modal = document.getElementById("power-modal");
  const confirmBtn = document.getElementById("modal-confirm-btn");
  const cancelBtn = document.getElementById("modal-cancel-btn");

  cancelBtn.addEventListener("click", () => {
    modal.classList.remove("open");
  });

  confirmBtn.addEventListener("click", () => {
    modal.classList.remove("open");
    executePowerAction(currentPowerAction);
  });
}

function promptPowerAction(action) {
  currentPowerAction = action;
  const modal = document.getElementById("power-modal");
  const title = document.getElementById("modal-title");
  const desc = document.getElementById("modal-desc");
  const confirmBtn = document.getElementById("modal-confirm-btn");

  const activeDev = cachedDevices.find(d => d.id === currentActiveDeviceId) || cachedDevices[0];
  const devName = activeDev ? activeDev.name : "Device";
  const isHost = activeDev ? activeDev.is_current : true;

  const targetNote = isHost 
    ? `⚠️ Target: [${devName}] (HOST MACHINE). This computer will execute the command.` 
    : `📡 Target: [${devName}] (REMOTE DEVICE). The Host will NOT execute this command.`;

  const actionMeta = {
    unlock: { 
      title: `Unlock Screen: ${devName}`, 
      desc: `Wakes the display, turns on monitors, and dismisses the lock screen curtain on '${devName}'.\n\n${targetNote}`, 
      btn: "🔓 Unlock Screen" 
    },
    lock: { 
      title: `Lock: ${devName}`, 
      desc: `Locks the workstation session on '${devName}'.\n\n${targetNote}`, 
      btn: "🔒 Lock Screen" 
    },

    shutdown: { 
      title: `Shutdown: ${devName}`, 
      desc: `Completely shuts down '${devName}'.\n\n${targetNote}`, 
      btn: "🛑 Shut Down" 
    },
    hibernate: { 
      title: `Hibernate: ${devName}`, 
      desc: `Enters 0-Watt Hibernate state on '${devName}'.\n\n${targetNote}`, 
      btn: "💤 Hibernate" 
    },
    sleep: { 
      title: `Sleep: ${devName}`, 
      desc: `Places '${devName}' into low-power idle sleep.\n\n${targetNote}`, 
      btn: "🌙 Sleep" 
    },
    restart: { 
      title: `Restart: ${devName}`, 
      desc: `Reboots the operating system on '${devName}'.\n\n${targetNote}`, 
      btn: "🔄 Restart" 
    }
  };

  const meta = actionMeta[action] || { title: `Confirm Action: ${devName}`, desc: targetNote, btn: "Confirm" };
  title.textContent = meta.title;
  desc.textContent = meta.desc;
  confirmBtn.textContent = meta.btn;

  modal.classList.add("open");
}

async function executePowerAction(action) {
  if (!currentActiveDeviceId) {
    alert("Please select a target device first.");
    return;
  }

  const activeDev = cachedDevices.find(d => d.id === currentActiveDeviceId) || { name: "Device" };

  try {
    // CRITICAL MULTI-DEVICE SAFETY:
    // Every power command is explicitly routed to the selected device ID.
    // If currentActiveDeviceId is Device B, Device A NEVER touches its own OS!
    const res = await apiFetch(`/api/devices/${currentActiveDeviceId}/power`, {
      method: "POST",
      body: {
        action: action,
        target_device_id: currentActiveDeviceId,
        delay_seconds: 0
      }
    });
    const result = await res.json();
    if (res.ok) {
      alert(`[POWER ACTION EXECUTED]\n\nTarget: ${activeDev.name}\nResult: ${result.message || JSON.stringify(result.remote_response || result)}`);
    } else {
      alert(`Target [${activeDev.name}] Error:\n${result.detail || result.message}`);
    }
  } catch (e) {
    alert(`Failed executing power action on ${activeDev.name}: ` + e.message);
  }
}

// ================= WORKSPACES LOGIC =================
let cachedWorkspaces = { active_profile: "work_shift", profiles: [] };
let installedAppsCache = [];
let currentModalApps = [];
let currentModalUrls = [];

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

async function loadWorkspaces() {
  try {
    const res = await apiFetch("/api/workspaces");
    const data = await res.json();
    cachedWorkspaces = data;
    
    // Update Quick Launcher dropdown on Dashboard
    const selector = document.getElementById("dashboard-workspace-select");
    if (selector) {
      selector.innerHTML = "";
      (data.profiles || []).forEach(p => {
        const opt = document.createElement("option");
        opt.value = p.id;
        const appCount = (p.applications || []).length;
        const urlCount = (p.urls || []).length;
        opt.textContent = `${p.name} (${appCount} apps, ${urlCount} tabs)`;
        if (p.id === data.active_profile) opt.selected = true;
        selector.appendChild(opt);
      });
    }

    // Render Workspaces View Cards
    const listContainer = document.getElementById("workspaces-list");
    if (listContainer) {
      listContainer.innerHTML = "";
      if (!data.profiles || data.profiles.length === 0) {
        listContainer.innerHTML = `
          <div class="card" style="grid-column: 1 / -1; text-align: center; padding: 36px 16px;">
            <p style="color: var(--text-secondary); margin-bottom: 14px;">No workspace profiles configured yet.</p>
            <button class="btn-primary" onclick="openCreateWorkspaceModal()">➕ Create First Workspace</button>
          </div>
        `;
        return;
      }

      data.profiles.forEach(p => {
        const card = document.createElement("div");
        card.className = "ws-card";

        const sched = p.schedule || {};
        const isSched = !!sched.enabled;
        const schedTime = sched.time || "09:00";
        const schedDays = (sched.days || []).join(", ");
        const schedBadge = isSched
          ? `<span class="ws-badge scheduled">⏰ Scheduled: ${schedDays} at ${schedTime}</span>`
          : `<span class="ws-badge manual">⏰ Manual Launch</span>`;

        // Render app tags
        const apps = p.applications || [];
        const appTagsHtml = apps.length > 0
          ? apps.map(a => {
              const name = typeof a === "object" ? (a.name || a.app_id) : a;
              return `<span class="ws-tag">🖥️ ${escapeHtml(name)}</span>`;
            }).join("")
          : `<span style="font-size: 0.8rem; color: var(--text-secondary);">No applications configured</span>`;

        // Render URL tags
        const urls = p.urls || [];
        const urlTagsHtml = urls.length > 0
          ? urls.map(u => {
              const cleanHost = u.replace(/^https?:\/\//, '').split('/')[0];
              return `<span class="ws-tag url-tag">🌐 ${escapeHtml(cleanHost || u)}</span>`;
            }).join("")
          : `<span style="font-size: 0.8rem; color: var(--text-secondary);">No URLs configured</span>`;

        card.innerHTML = `
          <div class="ws-card-header">
            <div>
              <div class="ws-title">💼 ${escapeHtml(p.name)}</div>
              <p class="ws-desc">${escapeHtml(p.description || "No description provided.")}</p>
            </div>
            <div>${schedBadge}</div>
          </div>

          <div style="margin-top: 4px;">
            <div class="ws-section-label">Start Menu Applications (${apps.length})</div>
            <div class="ws-tags-container">${appTagsHtml}</div>
          </div>

          <div style="margin-top: 4px;">
            <div class="ws-section-label">Web Tabs (${urls.length})</div>
            <div class="ws-tags-container">${urlTagsHtml}</div>
          </div>

          <div class="ws-actions-row">
            <button class="btn-primary" style="padding: 6px 14px; font-size: 0.85rem;" onclick="launchSpecificWorkspace('${p.id}')">🚀 Launch</button>
            <button class="btn-small" onclick="openEditWorkspaceModal('${p.id}')">✏️ Edit</button>
            <button class="btn-small delete" onclick="deleteWorkspace('${p.id}', '${escapeHtml(p.name)}')">🗑️ Delete</button>
          </div>
        `;
        listContainer.appendChild(card);
      });
    }

  } catch (e) {
    console.error("Failed loading workspaces", e);
  }
}

async function fetchInstalledApps(forceRefresh = false) {
  try {
    if (installedAppsCache.length > 0 && !forceRefresh) return installedAppsCache;
    const select = document.getElementById("ws-app-select");
    if (select) {
      select.innerHTML = '<option value="">⏳ Loading Start Menu applications...</option>';
    }
    const res = await apiFetch(`/api/apps/installed?refresh=${forceRefresh}`);
    const data = await res.json();
    installedAppsCache = data.apps || [];
    populateAppSelect(installedAppsCache);
    return installedAppsCache;
  } catch (e) {
    console.error("Failed fetching installed apps", e);
    return [];
  }
}

function populateAppSelect(apps) {
  const select = document.getElementById("ws-app-select");
  if (!select) return;
  select.innerHTML = '<option value="">-- Choose an application from Start Menu --</option>';
  apps.forEach(app => {
    const opt = document.createElement("option");
    opt.value = app.app_id;
    opt.textContent = app.name;
    opt.dataset.name = app.name;
    select.appendChild(opt);
  });
}

function filterInstalledApps(query) {
  const q = (query || "").toLowerCase().trim();
  const filtered = installedAppsCache.filter(a => a.name.toLowerCase().includes(q));
  populateAppSelect(filtered);
}

function renderModalAppsList() {
  const container = document.getElementById("ws-selected-apps");
  const countBadge = document.getElementById("ws-app-count-badge");
  if (!container) return;

  if (countBadge) countBadge.textContent = `${currentModalApps.length} selected`;

  if (currentModalApps.length === 0) {
    container.innerHTML = '<span style="font-size: 0.8rem; color: var(--text-secondary); padding: 4px;">No applications added yet.</span>';
    return;
  }

  container.innerHTML = currentModalApps.map((a, idx) => `
    <div class="ws-chip">
      <span>🖥️ ${escapeHtml(a.name)}</span>
      <button type="button" class="remove-chip-btn" onclick="removeSelectedApp(${idx})">✕</button>
    </div>
  `).join("");
}

function addSelectedApp() {
  const select = document.getElementById("ws-app-select");
  if (!select || !select.value) return;

  const appId = select.value;
  const opt = select.selectedOptions[0];
  const appName = opt ? (opt.dataset.name || opt.textContent) : appId;

  // Avoid duplicates
  if (currentModalApps.some(a => a.app_id === appId)) {
    return;
  }

  currentModalApps.push({ name: appName, app_id: appId });
  renderModalAppsList();
  select.value = "";
}

function removeSelectedApp(index) {
  currentModalApps.splice(index, 1);
  renderModalAppsList();
}

function renderModalUrlsList() {
  const container = document.getElementById("ws-selected-urls");
  const countBadge = document.getElementById("ws-url-count-badge");
  if (!container) return;

  if (countBadge) countBadge.textContent = `${currentModalUrls.length} tabs`;

  if (currentModalUrls.length === 0) {
    container.innerHTML = '<span style="font-size: 0.8rem; color: var(--text-secondary); padding: 4px;">No URLs added yet.</span>';
    return;
  }

  container.innerHTML = currentModalUrls.map((u, idx) => `
    <div class="ws-chip" style="width: 100%; justify-content: space-between;">
      <span style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 90%;">🌐 ${escapeHtml(u)}</span>
      <button type="button" class="remove-chip-btn" onclick="removeWorkspaceUrl(${idx})">✕</button>
    </div>
  `).join("");
}

function addWorkspaceUrl() {
  const input = document.getElementById("ws-url-input");
  if (!input || !input.value.trim()) return;

  let url = input.value.trim();
  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    url = "https://" + url;
  }

  if (!currentModalUrls.includes(url)) {
    currentModalUrls.push(url);
    renderModalUrlsList();
  }
  input.value = "";
}

function removeWorkspaceUrl(index) {
  currentModalUrls.splice(index, 1);
  renderModalUrlsList();
}

function toggleScheduleFields(enabled) {
  const panel = document.getElementById("ws-sched-panel");
  if (panel) panel.style.display = enabled ? "block" : "none";
}

function toggleDayBtn(btn) {
  btn.classList.toggle("active");
}

function openCreateWorkspaceModal() {
  document.getElementById("ws-modal-title").textContent = "➕ Create Workspace";
  document.getElementById("ws-modal-id").value = "";
  document.getElementById("ws-name").value = "";
  document.getElementById("ws-desc").value = "";
  document.getElementById("ws-app-search").value = "";
  document.getElementById("ws-url-input").value = "";

  currentModalApps = [];
  currentModalUrls = [];
  renderModalAppsList();
  renderModalUrlsList();

  const schedToggle = document.getElementById("ws-sched-enabled");
  if (schedToggle) {
    schedToggle.checked = false;
    toggleScheduleFields(false);
  }
  const schedTime = document.getElementById("ws-sched-time");
  if (schedTime) schedTime.value = "09:00";

  document.querySelectorAll("#ws-days-selector .ws-day-btn").forEach(btn => {
    const d = btn.dataset.day;
    btn.classList.toggle("active", ["Mon", "Tue", "Wed", "Thu", "Fri"].includes(d));
  });

  fetchInstalledApps();
  document.getElementById("workspace-modal").classList.add("open");
}

function openEditWorkspaceModal(profileId) {
  const profile = (cachedWorkspaces.profiles || []).find(p => p.id === profileId);
  if (!profile) return;

  document.getElementById("ws-modal-title").textContent = `✏️ Edit Workspace: ${profile.name}`;
  document.getElementById("ws-modal-id").value = profile.id;
  document.getElementById("ws-name").value = profile.name || "";
  document.getElementById("ws-desc").value = profile.description || "";
  document.getElementById("ws-app-search").value = "";
  document.getElementById("ws-url-input").value = "";

  currentModalApps = (profile.applications || []).map(a => {
    if (typeof a === "object") return { name: a.name || a.app_id, app_id: a.app_id };
    return { name: a, app_id: a };
  });
  renderModalAppsList();

  currentModalUrls = [...(profile.urls || [])];
  renderModalUrlsList();

  const sched = profile.schedule || {};
  const schedToggle = document.getElementById("ws-sched-enabled");
  if (schedToggle) {
    schedToggle.checked = !!sched.enabled;
    toggleScheduleFields(!!sched.enabled);
  }
  const schedTime = document.getElementById("ws-sched-time");
  if (schedTime) schedTime.value = sched.time || "09:00";

  const activeDays = sched.days || ["Mon", "Tue", "Wed", "Thu", "Fri"];
  document.querySelectorAll("#ws-days-selector .ws-day-btn").forEach(btn => {
    btn.classList.toggle("active", activeDays.includes(btn.dataset.day));
  });

  fetchInstalledApps();
  document.getElementById("workspace-modal").classList.add("open");
}

function closeWorkspaceModal() {
  document.getElementById("workspace-modal").classList.remove("open");
}

async function submitSaveWorkspace() {
  const name = document.getElementById("ws-name").value.trim();
  if (!name) {
    alert("Please enter a workspace name.");
    return;
  }

  const id = document.getElementById("ws-modal-id").value.trim() || undefined;
  const desc = document.getElementById("ws-desc").value.trim();

  const schedEnabled = document.getElementById("ws-sched-enabled").checked;
  const schedTime = document.getElementById("ws-sched-time").value || "09:00";
  const selectedDays = [];
  document.querySelectorAll("#ws-days-selector .ws-day-btn.active").forEach(btn => {
    selectedDays.push(btn.dataset.day);
  });

  const payload = {
    id: id,
    name: name,
    description: desc,
    applications: currentModalApps,
    urls: currentModalUrls,
    schedule: {
      enabled: schedEnabled,
      time: schedTime,
      days: selectedDays.length > 0 ? selectedDays : ["Mon", "Tue", "Wed", "Thu", "Fri"]
    }
  };

  try {
    const res = await apiFetch("/api/workspaces/profile", {
      method: "POST",
      body: payload
    });
    const data = await res.json();
    if (res.ok) {
      closeWorkspaceModal();
      loadWorkspaces();
    } else {
      alert("❌ " + (data.detail || "Failed to save workspace profile"));
    }
  } catch (e) {
    alert("❌ Error saving workspace: " + e.message);
  }
}

async function deleteWorkspace(profileId, profileName) {
  if (!confirm(`Are you sure you want to delete workspace profile "${profileName}"?`)) {
    return;
  }
  try {
    const res = await apiFetch(`/api/workspaces/${profileId}`, {
      method: "DELETE"
    });
    if (res.ok) {
      loadWorkspaces();
    } else {
      const data = await res.json();
      alert("❌ " + (data.detail || "Failed to delete workspace"));
    }
  } catch (e) {
    alert("❌ Error deleting workspace: " + e.message);
  }
}

async function launchSelectedWorkspace() {
  const selector = document.getElementById("dashboard-workspace-select");
  const profileId = selector ? selector.value : "work_shift";
  launchSpecificWorkspace(profileId);
}

async function launchSpecificWorkspace(profileId) {
  const btn = document.getElementById("btn-launch-workspace");
  if (btn) btn.textContent = "⏳ Launching...";

  try {
    const res = await apiFetch(`/api/workspaces/launch/${profileId}`, {
      method: "POST"
    });
    const data = await res.json();
    if (res.ok) {
      alert(`✅ Workspace '${data.profile_name}' launched!\nBrowser tabs opened: ${data.launched_urls.length}\nApplications: ${data.launched_apps.join(", ") || "None"}`);
    } else {
      alert("❌ " + (data.detail || data.message));
    }
  } catch (e) {
    alert("❌ Error launching workspace: " + e.message);
  } finally {
    if (btn) btn.innerHTML = `🚀 Launch Workspace`;
    setTimeout(loadScreenSnapshot, 2500);
  }
}


// ================= SCHEDULE LOGIC =================

async function loadSchedule() {
  try {
    const res = await apiFetch("/api/schedule");
    const data = await res.json();
    
    const timeInput = document.getElementById("schedule-time");
    const toggle = document.getElementById("schedule-enabled");
    if (timeInput) timeInput.value = data.time || "08:50";
    if (toggle) toggle.checked = !!data.enabled;

    const days = data.days || [];
    document.querySelectorAll(".day-checkbox").forEach(cb => {
      cb.checked = days.includes(cb.value);
    });
  } catch (e) {
    console.error("Failed loading schedule", e);
  }
}

async function saveSchedule() {
  const time = document.getElementById("schedule-time").value;
  const enabled = document.getElementById("schedule-enabled").checked;
  const days = [];
  document.querySelectorAll(".day-checkbox:checked").forEach(cb => {
    days.push(cb.value);
  });

  try {
    const res = await apiFetch("/api/schedule", {
      method: "POST",
      body: { enabled, time, days }
    });
    const data = await res.json();
    if (res.ok) {
      alert("✅ " + data.message);
    } else {
      alert("❌ " + (data.detail || data.message));
    }
  } catch (e) {
    alert("❌ Error saving schedule: " + e.message);
  }
}

// ================= IN-APP INTERACTIVE BOT =================

function initBotAssistant() {
  const toggleBtn = document.getElementById("bot-toggle-btn");
  const closeBtn = document.getElementById("bot-close-btn");
  const drawer = document.getElementById("bot-drawer");
  const sendBtn = document.getElementById("bot-send-btn");
  const input = document.getElementById("bot-input");

  if (toggleBtn && drawer) {
    toggleBtn.addEventListener("click", () => drawer.classList.toggle("open"));
  }
  if (closeBtn && drawer) {
    closeBtn.addEventListener("click", () => drawer.classList.remove("open"));
  }

  if (sendBtn && input) {
    sendBtn.addEventListener("click", () => sendBotMessage(input.value));
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter") sendBotMessage(input.value);
    });
  }

  fetchBotHistory();
}

async function fetchBotHistory() {
  try {
    const res = await apiFetch("/api/bot/history");
    const data = await res.json();
    const container = document.getElementById("bot-messages");
    if (!container) return;

    container.innerHTML = "";
    data.history.forEach(msg => appendMessageUI(msg.sender, msg.text, msg.timestamp));
    container.scrollTop = container.scrollHeight;
  } catch (e) {
    console.error("Bot history error", e);
  }
}

async function sendBotMessage(text) {
  if (!text || !text.trim()) return;
  const input = document.getElementById("bot-input");
  if (input) input.value = "";

  appendMessageUI("user", text, "Just now");

  try {
    const res = await apiFetch("/api/bot/chat", {
      method: "POST",
      body: { message: text }
    });
    const reply = await res.json();
    if (res.ok) {
      appendMessageUI("bot", reply.text, reply.timestamp);

      if (reply.action === "refresh_screen") {
        loadScreenSnapshot();
      } else if (reply.action === "workspace_launched") {
        setTimeout(loadScreenSnapshot, 2500);
      } else if (reply.action === "device_woken") {
        setTimeout(loadDevices, 4000);
      }
    } else {
      appendMessageUI("bot", "⚠️ " + (reply.detail || reply.message), "Now");
    }
  } catch (e) {
    appendMessageUI("bot", "⚠️ Sorry, I could not process that request.", "Now");
  }
}

function appendMessageUI(sender, text, time) {
  const container = document.getElementById("bot-messages");
  if (!container) return;

  const msgDiv = document.createElement("div");
  msgDiv.className = `bot-msg ${sender}`;
  let formatted = text.replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>").replace(/\n/g, "<br>");
  msgDiv.innerHTML = formatted;
  container.appendChild(msgDiv);
  container.scrollTop = container.scrollHeight;
}

function botQuickAction(command) {
  sendBotMessage(command);
}


// --- Theme Management (Black & Red Dark Mode vs Clean Light Mode) ---
function initTheme() {
  const savedTheme = localStorage.getItem("wakex_theme") || "dark";
  setTheme(savedTheme, false);
}

function setTheme(theme, save = true) {
  const isLight = theme === "light";
  if (isLight) {
    document.body.classList.add("light-theme");
    document.documentElement.classList.add("light-theme");
  } else {
    document.body.classList.remove("light-theme");
    document.documentElement.classList.remove("light-theme");
  }

  // Update theme toggle icons (moon for dark, sun for light)
  const desktopBtn = document.getElementById("theme-toggle-desktop");
  const mobileBtn = document.getElementById("theme-toggle-mobile");
  const icon = isLight ? "☀️" : "🌙";
  if (desktopBtn) desktopBtn.textContent = icon;
  if (mobileBtn) mobileBtn.textContent = icon;

  // Update Settings View Card buttons
  const darkBtn = document.getElementById("btn-theme-dark");
  const lightBtn = document.getElementById("btn-theme-light");
  if (darkBtn) darkBtn.classList.toggle("active", !isLight);
  if (lightBtn) lightBtn.classList.toggle("active", isLight);

  if (save) {
    localStorage.setItem("wakex_theme", theme);
  }
}

function toggleTheme() {
  const currentTheme = document.body.classList.contains("light-theme") ? "light" : "dark";
  const newTheme = currentTheme === "light" ? "dark" : "light";
  setTheme(newTheme, true);
}

// --- 3-Step Guided Onboarding ---
function checkOnboarding() {
  const onboarded = localStorage.getItem("wakex_onboarded");
  if (!onboarded) {
    showOnboarding();
  }
}

function showOnboarding() {
  nextOnboardingStep(1);
  const modal = document.getElementById("onboarding-modal");
  if (modal) modal.classList.add("open");
}

function nextOnboardingStep(step) {
  for (let s = 1; s <= 3; s++) {
    const el = document.getElementById(`onboarding-step-${s}`);
    if (el) el.style.display = s === step ? "block" : "none";
  }
  const counter = document.getElementById("onboarding-step-counter");
  if (counter) counter.textContent = `Step ${step} of 3`;
}

function completeOnboarding() {
  localStorage.setItem("wakex_onboarded", "true");
  const modal = document.getElementById("onboarding-modal");
  if (modal) modal.classList.remove("open");
}

function openAboutModal() {
  const modal = document.getElementById("about-modal");
  if (modal) modal.classList.add("open");
}

function closeAboutModal() {
  const modal = document.getElementById("about-modal");
  if (modal) modal.classList.remove("open");
}
