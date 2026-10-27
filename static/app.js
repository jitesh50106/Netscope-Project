/**
 * NetScope Enterprise Reconnaissance & Audit Dashboard
 */

document.addEventListener("DOMContentLoaded", () => {
  // DOM Elements
  const localIpDisplay = document.getElementById("local-ip-display");
  const targetInput = document.getElementById("target-input");
  const btnPresetLocal = document.getElementById("btn-preset-local");
  const btnPresetLoopback = document.getElementById("btn-preset-loopback");
  const portChips = document.querySelectorAll(".port-chip");
  const customPortsWrap = document.getElementById("custom-ports-wrap");
  const customPortsInput = document.getElementById("custom-ports-input");

  const optPing = document.getElementById("opt-ping");
  const optBanner = document.getElementById("opt-banner");
  const optDns = document.getElementById("opt-dns");
  const optThreads = document.getElementById("opt-threads");
  const optTimeout = document.getElementById("opt-timeout");
  const valThreads = document.getElementById("val-threads");
  const valTimeout = document.getElementById("val-timeout");

  const scanForm = document.getElementById("scan-form");
  const btnScan = document.getElementById("btn-scan");
  const btnCancel = document.getElementById("btn-cancel");

  // Metrics
  const statTargets = document.getElementById("stat-targets");
  const statHosts = document.getElementById("stat-hosts");
  const statPorts = document.getElementById("stat-ports");
  const statRisks = document.getElementById("stat-risks");
  const statGrade = document.getElementById("stat-grade");
  const statTime = document.getElementById("stat-time");

  // Progress & Status
  const progressBar = document.getElementById("progress-bar");
  const scanStatusText = document.getElementById("scan-status-text");
  const progressPercentage = document.getElementById("progress-percentage");

  // Results & Viewport
  const resultsViewport = document.getElementById("results-viewport");
  const emptyState = document.getElementById("empty-state");
  const hostCardsContainer = document.getElementById("host-cards-container");
  const filterSearch = document.getElementById("filter-search");
  const btnExportHtml = document.getElementById("btn-export-html");
  const btnExportCsv = document.getElementById("btn-export-csv");
  const btnExportJson = document.getElementById("btn-export-json");

  // Terminal
  const terminalOutput = document.getElementById("terminal-output");
  const btnClearLogs = document.getElementById("btn-clear-logs");
  const historyContainer = document.getElementById("history-container");
  const btnRefreshHistory = document.getElementById("btn-refresh-history");

  // State
  let currentJobId = null;
  let eventSource = null;
  let timerInterval = null;
  let scanStartTime = null;
  let selectedPortProfile = "top20";
  let networkInfo = null;
  let discoveredHosts = new Map(); // ip -> hostData

  // 1. Initialize Network Information
  async function fetchNetworkInfo() {
    try {
      const res = await fetch("/api/info");
      if (res.ok) {
        networkInfo = await res.json();
        localIpDisplay.textContent = `Host: ${networkInfo.local_ip} (${networkInfo.hostname})`;
        if (!targetInput.value) {
          targetInput.value = networkInfo.default_subnet || "127.0.0.1";
        }
      }
    } catch (err) {
      localIpDisplay.textContent = "Offline / Local Mode";
    }
  }

  fetchNetworkInfo();
  loadHistory();

  // 2. Preset Buttons
  btnPresetLocal.addEventListener("click", () => {
    if (networkInfo && networkInfo.default_subnet) {
      targetInput.value = networkInfo.default_subnet;
    } else {
      targetInput.value = "192.168.1.0/24";
    }
  });

  btnPresetLoopback.addEventListener("click", () => {
    targetInput.value = "127.0.0.1";
  });

  // 3. Port Profile Selector
  portChips.forEach(chip => {
    chip.addEventListener("click", () => {
      portChips.forEach(c => c.classList.remove("active"));
      chip.classList.add("active");
      selectedPortProfile = chip.dataset.profile;
      if (selectedPortProfile === "custom") {
        customPortsWrap.style.display = "block";
        customPortsInput.focus();
      } else {
        customPortsWrap.style.display = "none";
      }
    });
  });

  // 4. Sliders
  optThreads.addEventListener("input", (e) => {
    valThreads.textContent = e.target.value;
  });

  optTimeout.addEventListener("input", (e) => {
    valTimeout.textContent = `${e.target.value}s`;
  });

  // 5. Terminal Logger
  function logToConsole(message, type = "normal") {
    const line = document.createElement("div");
    line.className = `log-line ${type}-line`;
    const timeStr = new Date().toLocaleTimeString();
    line.textContent = `[${timeStr}] ${message}`;
    terminalOutput.appendChild(line);
    terminalOutput.scrollTop = terminalOutput.scrollHeight;
  }

  btnClearLogs.addEventListener("click", () => {
    terminalOutput.innerHTML = '<div class="log-line sys-line">[System] Console cleared.</div>';
  });

  // 6. Form Submission / Audit Execution
  scanForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const target = targetInput.value.trim();
    if (!target) return;

    resetScanUI();

    const payload = {
      target: target,
      port_selection: selectedPortProfile,
      custom_ports: selectedPortProfile === "custom" ? customPortsInput.value.trim() : null,
      ping_discovery: optPing.checked,
      banner_grab: optBanner.checked,
      resolve_dns: optDns.checked,
      timeout: parseFloat(optTimeout.value),
      threads: parseInt(optThreads.value, 10),
      max_hosts: 512
    };

    btnScan.disabled = true;
    btnCancel.disabled = false;
    scanStatusText.textContent = "Initializing audit job...";
    logToConsole(`Launching audit for target scope: ${target} [Profile: ${selectedPortProfile}]`, "accent");

    try {
      const response = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });

      if (!response.ok) {
        const err = await response.json();
        throw new Error(err.detail || "Failed to start scan");
      }

      const data = await response.json();
      currentJobId = data.job_id;

      scanStartTime = Date.now();
      timerInterval = setInterval(() => {
        const elapsed = ((Date.now() - scanStartTime) / 1000).toFixed(1);
        statTime.textContent = `${elapsed}s`;
      }, 100);

      connectEventStream(currentJobId);

    } catch (err) {
      logToConsole(`Error starting audit: ${err.message}`, "err");
      scanStatusText.textContent = `Failed: ${err.message}`;
      btnScan.disabled = false;
      btnCancel.disabled = true;
    }
  });

  // 7. SSE Live Stream Handler
  function connectEventStream(jobId) {
    if (eventSource) {
      eventSource.close();
    }

    eventSource = new EventSource(`/api/scan/${jobId}/stream`);

    eventSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        handleScanEvent(data);
      } catch (e) {}
    };

    eventSource.onerror = () => {};
  }

  function handleScanEvent(evt) {
    if (evt.percent !== undefined) {
      progressBar.style.width = `${evt.percent}%`;
      progressPercentage.textContent = `${Math.round(evt.percent)}%`;
    }

    if (evt.message) {
      const lineType = evt.type === "complete" ? "accent" 
                     : evt.type === "error" ? "err" 
                     : evt.type === "host_discovered" ? "warn" : "normal";
      logToConsole(evt.message, lineType);
      scanStatusText.textContent = evt.message;
    }

    if (evt.type === "host_discovered" && evt.payload) {
      const host = evt.payload;
      discoveredHosts.set(host.ip, host);
      statHosts.textContent = discoveredHosts.size;
      renderHostCards();
    }

    if (evt.type === "host_scanned" && evt.payload) {
      const host = evt.payload;
      discoveredHosts.set(host.ip, host);
      recalculateMetrics();
      renderHostCards();
    }

    if (evt.type === "complete") {
      finishScan(true);
      if (evt.payload) {
        statTargets.textContent = evt.payload.total_targets || discoveredHosts.size;
        statHosts.textContent = evt.payload.active_hosts_count || discoveredHosts.size;
        statPorts.textContent = evt.payload.total_open_ports || 0;
        statGrade.textContent = evt.payload.overall_posture_grade || "A";
      }
      recalculateMetrics();
      loadHistory();
    }

    if (evt.type === "cancelled" || evt.type === "error") {
      finishScan(false);
      loadHistory();
    }
  }

  // 8. Cancel Audit
  btnCancel.addEventListener("click", async () => {
    if (!currentJobId) return;
    try {
      await fetch(`/api/scan/${currentJobId}/cancel`, { method: "POST" });
      logToConsole("Abort signal transmitted by operator.", "warn");
      scanStatusText.textContent = "Cancelling audit...";
    } catch (e) {
      logToConsole(`Cancel failed: ${e.message}`, "err");
    }
  });

  function finishScan(success) {
    if (eventSource) {
      eventSource.close();
      eventSource = null;
    }
    if (timerInterval) {
      clearInterval(timerInterval);
      timerInterval = null;
    }

    btnScan.disabled = false;
    btnCancel.disabled = true;

    if (currentJobId) {
      btnExportHtml.disabled = false;
      btnExportCsv.disabled = false;
      btnExportJson.disabled = false;

      btnExportHtml.onclick = () => window.open(`/api/scan/${currentJobId}/export/html`, "_blank");
      btnExportCsv.onclick = () => window.open(`/api/scan/${currentJobId}/export/csv`, "_blank");
      btnExportJson.onclick = () => window.open(`/api/scan/${currentJobId}/export/json`, "_blank");
    }
  }

  function resetScanUI() {
    discoveredHosts.clear();
    emptyState.style.display = "none";
    hostCardsContainer.style.display = "flex";
    hostCardsContainer.innerHTML = "";

    statTargets.textContent = "0";
    statHosts.textContent = "0";
    statPorts.textContent = "0";
    statRisks.textContent = "0";
    statGrade.textContent = "—";
    statTime.textContent = "0.0s";

    progressBar.style.width = "0%";
    progressPercentage.textContent = "0%";
    btnExportHtml.disabled = true;
    btnExportCsv.disabled = true;
    btnExportJson.disabled = true;
  }

  // 9. Render Host Cards & Detailed Findings Table
  function renderHostCards() {
    const filterQuery = (filterSearch.value || "").toLowerCase().trim();
    hostCardsContainer.innerHTML = "";

    const hosts = Array.from(discoveredHosts.values());
    if (hosts.length === 0) {
      emptyState.style.display = "flex";
      hostCardsContainer.style.display = "none";
      return;
    }

    emptyState.style.display = "none";
    hostCardsContainer.style.display = "flex";

    hosts.forEach(host => {
      const ipMatch = host.ip.toLowerCase().includes(filterQuery);
      const hostMatch = (host.hostname || "").toLowerCase().includes(filterQuery);
      const osMatch = (host.os_guess || "").toLowerCase().includes(filterQuery);
      const portMatch = (host.open_ports || []).some(p => 
        p.port.toString().includes(filterQuery) || 
        p.service.toLowerCase().includes(filterQuery) ||
        (p.software || "").toLowerCase().includes(filterQuery) ||
        (p.banner || "").toLowerCase().includes(filterQuery) ||
        (p.risk_level || "").toLowerCase().includes(filterQuery)
      );

      if (filterQuery && !ipMatch && !hostMatch && !osMatch && !portMatch) {
        return;
      }

      const card = document.createElement("div");
      card.className = "host-card";

      // Badges
      let gradeClean = (host.security_grade || "A").replace("+", "-plus");
      let gradeBadge = `
        <div class="host-grade-badge grade-${gradeClean}">
          <span>GRADE: ${host.security_grade || 'A'}</span>
          <span style="font-size:0.68rem; opacity:0.85;">(${host.security_score || 100}/100)</span>
        </div>
      `;

      let osBadge = host.os_guess ? `<span class="pill pill-os">💻 ${escapeHtml(host.os_guess)}</span>` : "";
      let latencyBadge = host.latency_ms !== null && host.latency_ms !== undefined ? 
        `<span class="pill pill-latency">⚡ ${host.latency_ms.toFixed(1)}ms</span>` : "";
      let macBadge = host.mac_address ? 
        `<span class="pill pill-mac">🏷️ ${host.mac_address} ${host.mac_vendor ? `(${escapeHtml(host.mac_vendor)})` : ''}</span>` : "";

      // Ports Table
      let portsHtml = "";
      if (host.open_ports && host.open_ports.length > 0) {
        const rows = host.open_ports.map(p => {
          let riskClass = `risk-${p.risk_level || 'info'}`;
          let swDisplay = p.software ? 
            `<span class="sw-badge">${escapeHtml(p.software)} ${p.version ? escapeHtml(p.version) : ''}</span>` : 
            `<span style="color:#64748b">—</span>`;

          let remediationHtml = "";
          if (p.remediation) {
            remediationHtml = `
              <div class="remediation-row">
                <span class="remediation-tag">🛡️ Fix:</span> ${escapeHtml(p.remediation)}
              </div>
            `;
          }

          let bannerDisplay = p.banner ? 
            `<div class="banner-text" title="${escapeHtml(p.banner)}">${escapeHtml(p.banner)}</div>` : "";

          return `
            <tr>
              <td><span class="port-num">${p.port}/${p.protocol.toUpperCase()}</span></td>
              <td><strong>${escapeHtml(p.service)}</strong></td>
              <td>${swDisplay}</td>
              <td><span class="risk-badge ${riskClass}">${p.risk_level}</span></td>
              <td>
                <div><strong>${escapeHtml(p.risk_title || p.service)}</strong></div>
                ${bannerDisplay}
                ${remediationHtml}
              </td>
            </tr>
          `;
        }).join("");

        portsHtml = `
          <table class="ports-table">
            <thead>
              <tr>
                <th style="width: 100px;">PORT</th>
                <th style="width: 130px;">SERVICE</th>
                <th style="width: 160px;">SOFTWARE</th>
                <th style="width: 90px;">RISK</th>
                <th>SECURITY ADVISORY &amp; REMEDIATION</th>
              </tr>
            </thead>
            <tbody>${rows}</tbody>
          </table>
        `;
      } else {
        portsHtml = `<div style="font-size:0.75rem; color:#94a3b8; font-style:italic; padding:4px 0;">No open scanned ports identified.</div>`;
      }

      card.innerHTML = `
        <div class="host-card-header">
          <div class="host-id">
            <span class="host-ip">${escapeHtml(host.ip)}</span>
            ${host.hostname ? `<span class="host-hostname">(${escapeHtml(host.hostname)})</span>` : ''}
          </div>
          <div class="host-badges">
            ${gradeBadge}
            ${osBadge}
            ${latencyBadge}
            ${macBadge}
          </div>
        </div>
        ${portsHtml}
      `;

      hostCardsContainer.appendChild(card);
    });
  }

  filterSearch.addEventListener("input", renderHostCards);

  function recalculateMetrics() {
    let portCount = 0;
    let highRiskCount = 0;
    let totalScore = 0;
    let countedHosts = 0;

    discoveredHosts.forEach(h => {
      if (h.security_score !== undefined) {
        totalScore += h.security_score;
        countedHosts++;
      }
      if (h.open_ports) {
        portCount += h.open_ports.length;
        h.open_ports.forEach(p => {
          if (p.risk_level === "high" || p.risk_level === "warning") {
            highRiskCount++;
          }
        });
      }
    });

    statPorts.textContent = portCount;
    statRisks.textContent = highRiskCount;

    if (countedHosts > 0) {
      let avg = Math.round(totalScore / countedHosts);
      let g = avg >= 95 ? "A+" : avg >= 88 ? "A" : avg >= 75 ? "B" : avg >= 60 ? "C" : avg >= 45 ? "D" : "F";
      statGrade.textContent = `${g} (${avg})`;
    }
  }

  // 10. Audit History
  async function loadHistory() {
    try {
      const res = await fetch("/api/history");
      if (res.ok) {
        const history = await res.json();
        if (history.length === 0) {
          historyContainer.innerHTML = '<p class="empty-hint">No past audit sessions recorded.</p>';
          return;
        }

        historyContainer.innerHTML = history.slice(0, 5).map(item => `
          <div class="history-item" data-id="${item.job_id}">
            <div>
              <strong>${escapeHtml(item.target)}</strong>
              <span style="color:#64748b; font-size:0.7rem; margin-left:6px;">${item.started_at}</span>
            </div>
            <div>
              <span style="color:#00e676; margin-right:6px;">Grade: ${item.overall_grade || 'A'}</span>
              <span style="color:#00f0ff;">${item.open_ports} ports</span>
            </div>
          </div>
        `).join("");

        document.querySelectorAll(".history-item").forEach(el => {
          el.addEventListener("click", () => {
            loadPastScan(el.dataset.id);
          });
        });
      }
    } catch (e) {}
  }

  btnRefreshHistory.addEventListener("click", loadHistory);

  async function loadPastScan(jobId) {
    try {
      const res = await fetch(`/api/scan/${jobId}`);
      if (res.ok) {
        const report = await res.json();
        currentJobId = report.job_id;
        discoveredHosts.clear();
        (report.hosts || []).forEach(h => discoveredHosts.set(h.ip, h));
        
        statTargets.textContent = report.total_targets || discoveredHosts.size;
        statHosts.textContent = report.active_hosts_count || discoveredHosts.size;
        statPorts.textContent = report.total_open_ports || 0;
        statGrade.textContent = `${report.overall_posture_grade} (${report.average_security_score})`;
        statTime.textContent = `${report.duration_seconds}s`;
        progressBar.style.width = "100%";
        progressPercentage.textContent = "100%";
        scanStatusText.textContent = `Audit report loaded for ${report.target}`;

        recalculateMetrics();
        renderHostCards();
        finishScan(true);
        logToConsole(`Loaded audit session ${jobId} for scope: ${report.target}`, "accent");
      }
    } catch (e) {
      logToConsole(`Failed to load session: ${e.message}`, "err");
    }
  }

  function escapeHtml(str) {
    if (!str) return "";
    return str.replace(/[&<>"']/g, m => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[m]));
  }
});
