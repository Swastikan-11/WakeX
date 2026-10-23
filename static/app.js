// WakeX Hub - Core Frontend Logic (Target-Isolated Multi-Device Architecture)

let currentPowerAction = null;
let currentActiveDeviceId = null;
let cachedDevices = [];
let targetRenameDeviceId = null;

document.addEventListener("DOMContentLoaded", async () => {
  initTheme();
  initNavigation();
  initBotAssistant();
  initPowerModals();
  await initAuthentication();
  startAppServices();
});

// --- Cryptographic Web Crypto HMAC-SHA256 Signer ---
async function computeHmacSha256(secret, message) {
  const encoder = new TextEncoder();
  const keyData = encoder.encode(secret);
  const cryptoKey = await window.crypto.subtle.importKey(
    "raw", keyData, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sigBuffer = await window.crypto.subtle.sign("HMAC", cryptoKey, encoder.encode(message));
  return Array.from(new Uint8Array(sigBuffer))
    .map(b => b.toString(16).padStart(2, '0')).join('');
}

async function computeSha256(dataBytes) {
  const digest = await window.crypto.subtle.digest("SHA-256", dataBytes);
  return Array.from(new Uint8Array(digest))
    .map(b => b.toString(16).padStart(2, '0')).join('');
}

async function getAuthHeaders(method = "GET", path = "", bodyStr = "") {
  const headers = {
    "Content-Type": "application/json"
  };

  const localToken = localStorage.getItem("wakex_local_token");
  if (localToken) {
    headers["X-WakeX-Local-Token"] = localToken;
  }

  // Check SharedPreferences if running in native Android app
  if (window.AndroidWakeX && typeof window.AndroidWakeX.getClientId === "function") {
    const nativeId = window.AndroidWakeX.getClientId();
    const nativeSecret = window.AndroidWakeX.getClientSecret();
    if (nativeId && nativeSecret && !localStorage.getItem("wakex_client_id")) {
      localStorage.setItem("wakex_client_id", nativeId);
      localStorage.setItem("wakex_client_secret", nativeSecret);
    }
  }

  const clientId = localStorage.getItem("wakex_client_id");
  const clientSecret = localStorage.getItem("wakex_client_secret");

  if (clientId && clientSecret && window.crypto && window.crypto.subtle) {
    const ts = Math.floor(Date.now() / 1000).toString();
    const nonce = Array.from(window.crypto.getRandomValues(new Uint8Array(8)))
      .map(b => b.toString(16).padStart(2, '0')).join('');

    const bodyBytes = bodyStr ? new TextEncoder().encode(bodyStr) : new Uint8Array(0);
    const bodyHex = await computeSha256(bodyBytes);
    const message = `${method.toUpperCase()}:${path}:${ts}:${nonce}:${bodyHex}`;
    const sig = await computeHmacSha256(clientSecret, message);

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

  const res = await fetch(path, options);
  if (res.status === 401 && !path.startsWith("/api/auth/")) {
    showClientPairModal();
  }
  return res;
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
    return;
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

function showClientPairModal() {
  const modal = document.getElementById("client-pair-modal");
  if (modal) modal.classList.add("open");
}

function closeClientPairModal() {
  const modal = document.getElementById("client-pair-modal");
  if (modal) modal.classList.remove("open");
}

async function submitClientPairing() {
  const input = document.getElementById("client-pair-code");
  const code = input ? input.value.trim() : "";
  if (!code || code.length !== 6) {
    alert("Please enter a valid 6-digit pairing code.");
    return;
  }

  try {
    const res = await fetch("/api/auth/pair", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        pairing_code: code,
        client_name: navigator.userAgent.includes("Android") ? "Android Phone" : "Web Client"
      })
    });
    const data = await res.json();
    if (res.ok) {
      localStorage.setItem("wakex_client_id", data.client_id);
      localStorage.setItem("wakex_client_secret", data.client_secret);
      if (window.AndroidWakeX && typeof window.AndroidWakeX.saveCredentials === "function") {
        window.AndroidWakeX.saveCredentials(data.client_id, data.client_secret);
      }
      closeClientPairModal();
      alert("✅ Phone paired successfully with WakeX Hub!");
      startAppServices();
    } else {
      alert(`❌ Pairing Failed: ${data.detail || data.message}`);
    }
  } catch (e) {
    alert(`Pairing error: ${e.message}`);
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
      list.innerHTML = (data.checks || []).map(c => {
        const icon = c.status === "pass" ? "✅" : (c.status === "warning" ? "⚠️" : "ℹ️");
        const color = c.status === "pass" ? "var(--accent-green)" : (c.status === "warning" ? "var(--accent-amber)" : "var(--accent-cyan)");
        return `
          <div style="display: flex; align-items: flex-start; gap: 8px; font-size: 0.83rem; background: rgba(255,255,255,0.02); padding: 8px 10px; border-radius: 6px; border-left: 2px solid ${color};">
            <span>${icon}</span>
            <div>
              <strong style="color: #fff;">${escapeHtml(c.name)}:</strong>
              <span style="color: var(--text-secondary); margin-left: 4px;">${escapeHtml(c.detail)}</span>
            </div>
          </div>
        `;
      }).join("");
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
      alert(`⚡ [WOL SELF-TEST SUCCESS]\n\n${data.message}`);
    } else {
      alert(`❌ WoL Test Failed: ${data.detail || data.message}`);
    }
  } catch (e) {
    alert(`WoL Test Error: ${e.message}`);
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
      setTimeout(connect, 3000);
    };
  }

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
  devices.forEach(dev => {
    const card = document.createElement("div");
    card.className = "device-card";
    const isOnline = dev.status === "online";

    card.innerHTML = `
      <div>
        <div class="device-card-header">
          <div class="device-name-title">
            <span>💻</span>
            <span>${dev.name}</span>
          </div>
          <span class="device-status-pill ${isOnline ? 'online' : 'offline'}">
            <span class="status-dot" style="background: ${isOnline ? 'var(--accent-green)' : 'var(--accent-red)'}"></span>
            ${isOnline ? 'Online' : 'Offline / Sleeping'}
          </span>
        </div>

        <div class="device-details-meta">
          <div><strong>IP Address:</strong> ${dev.ip || "Not set"}</div>
          <div><strong>MAC Address:</strong> ${dev.mac || "Not set"}</div>
          <div><strong>Port:</strong> ${dev.port || 8001}</div>
          <div><strong>Role:</strong> ${dev.is_current ? "This Computer (Host Hub)" : "Remote Target"}</div>
          <div><strong>Agent Auth:</strong> ${dev.auth_token ? "🔒 Token Armed" : "⚠️ No Token (WoL only)"}</div>
        </div>
      </div>

      <div class="device-card-actions">
        <button class="btn-small wake" onclick="wakeDevice('${dev.id}')">
          <span>⚡</span> Turn On / Wake
        </button>
        <button class="btn-small" style="color: var(--accent-green);" onclick="currentActiveDeviceId='${dev.id}'; promptPowerAction('unlock')">
          <span>🔓</span> Unlock
        </button>
        <button class="btn-small" onclick="openRenameModal('${dev.id}', '${dev.name}')">
          <span>✏️</span> Rename
        </button>
        ${!dev.is_current ? `
          <button class="btn-small delete" onclick="deleteDeviceConfirm('${dev.id}', '${dev.name}')">
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
