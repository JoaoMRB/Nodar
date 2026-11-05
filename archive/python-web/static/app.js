const networkInfoEl = document.getElementById("network-info");
const devicesListEl = document.getElementById("devices-list");
const btnScan = document.getElementById("btn-scan");
const deepScanEl = document.getElementById("deep-scan");
const portScanEl = document.getElementById("port-scan");
const autoRefreshEl = document.getElementById("auto-refresh");
const refreshIntervalEl = document.getElementById("refresh-interval");
const statsEl = document.getElementById("stats");
const statDevices = document.getElementById("stat-devices");
const statMethod = document.getElementById("stat-method");
const statTime = document.getElementById("stat-time");
const deviceBadge = document.getElementById("device-badge");

let refreshTimer = null;
let isScanning = false;

async function loadNetworkInfo() {
  try {
    const res = await fetch("/api/network");
    const data = await res.json();

    if (data.error) {
      networkInfoEl.innerHTML = `<div class="info-card error-state">${data.error}</div>`;
      return;
    }

    networkInfoEl.innerHTML = `
      <div class="info-card">
        <div class="info-label">Teu IP</div>
        <div class="info-value">${data.ip}</div>
      </div>
      <div class="info-card">
        <div class="info-label">Rede</div>
        <div class="info-value">${data.network}</div>
      </div>
      <div class="info-card">
        <div class="info-label">Gateway</div>
        <div class="info-value">${data.gateway || "N/A"}</div>
      </div>
      <div class="info-card">
        <div class="info-label">Interface</div>
        <div class="info-value">${data.interface}</div>
      </div>
      <div class="info-card">
        <div class="info-label">Hostname</div>
        <div class="info-value">${data.hostname}</div>
      </div>
    `;
  } catch (err) {
    networkInfoEl.innerHTML = `<div class="info-card error-state">Erro ao carregar info da rede</div>`;
  }
}

function formatMethod(method) {
  const labels = {
    arp_scapy: "ARP (Scapy)",
    "arp_table+ping": "ARP + Ping",
  };
  return labels[method] || method;
}

function renderDevices(data) {
  if (data.error) {
    devicesListEl.innerHTML = `<div class="error-state">${data.error}</div>`;
    return;
  }

  const devices = data.devices || [];

  if (devices.length === 0) {
    devicesListEl.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">📭</div>
        <p>Nenhum dispositivo encontrado. Tenta com scan profundo ou executa como Administrador.</p>
      </div>
    `;
    return;
  }

  devicesListEl.innerHTML = devices.map((device) => {
    const portsHtml = device.open_ports?.length
      ? `<div class="ports">${device.open_ports.map((p) => `<span class="port-tag">${p}</span>`).join("")}</div>`
      : "";

    return `
      <div class="device-card ${device.is_local ? "local" : ""}">
        <div class="device-header">
          <span class="device-ip">${device.ip}</span>
          <span class="device-status ${device.is_local ? "local-badge" : ""}">
            ${device.is_local ? "Este PC" : "Online"}
          </span>
        </div>
        <div class="device-detail">
          <span class="detail-label">MAC</span>
          <span class="detail-value">${device.mac || "—"}</span>
        </div>
        <div class="device-detail">
          <span class="detail-label">Hostname</span>
          <span class="detail-value">${device.hostname || "—"}</span>
        </div>
        <div class="device-detail">
          <span class="detail-label">Fabricante</span>
          <span class="detail-value">${device.vendor || "Desconhecido"}</span>
        </div>
        ${portsHtml}
      </div>
    `;
  }).join("");
}

async function runScan() {
  if (isScanning) return;
  isScanning = true;
  btnScan.disabled = true;
  btnScan.classList.add("scanning");
  btnScan.innerHTML = '<span class="btn-icon">⏳</span> A analisar...';

  const params = new URLSearchParams();
  if (deepScanEl.checked) params.set("deep", "true");
  if (portScanEl.checked) params.set("ports", "true");

  try {
    const res = await fetch(`/api/scan?${params}`);
    const data = await res.json();

    renderDevices(data);

    statsEl.hidden = false;
    statDevices.textContent = data.device_count || 0;
    statMethod.textContent = formatMethod(data.scan_method);
    statTime.textContent = new Date().toLocaleTimeString("pt-PT");
    deviceBadge.textContent = data.device_count || 0;
  } catch (err) {
    devicesListEl.innerHTML = `<div class="error-state">Erro durante a analise: ${err.message}</div>`;
  } finally {
    isScanning = false;
    btnScan.disabled = false;
    btnScan.classList.remove("scanning");
    btnScan.innerHTML = '<span class="btn-icon">🔍</span> Analisar Rede';
  }
}

function setupAutoRefresh() {
  if (refreshTimer) {
    clearInterval(refreshTimer);
    refreshTimer = null;
  }

  if (autoRefreshEl.checked) {
    const seconds = parseInt(refreshIntervalEl.value, 10);
    refreshTimer = setInterval(runScan, seconds * 1000);
  }
}

btnScan.addEventListener("click", runScan);
autoRefreshEl.addEventListener("change", setupAutoRefresh);
refreshIntervalEl.addEventListener("change", setupAutoRefresh);

loadNetworkInfo();
