/**
 * SQL Injection Detection, Exploitation & Mitigation Platform
 * Frontend Interactive Controller
 */

document.addEventListener("DOMContentLoaded", () => {
  // Application State
  const state = {
    currentMode: "vulnerable", // "vulnerable" | "mitigated"
    currentScenario: "auth",   // "auth" | "search" | "profile"
    sastPresets: []
  };

  // DOM Elements
  const tabButtons = document.querySelectorAll(".tab-btn");
  const tabContents = document.querySelectorAll(".tab-content");
  
  const modeVulnBtn = document.getElementById("mode-vuln-btn");
  const modeMitigBtn = document.getElementById("mode-mitig-btn");
  const modeDescBadge = document.getElementById("mode-description-badge");

  const scenarioButtons = document.querySelectorAll(".scenario-btn");
  const scenarioForms = document.querySelectorAll(".scenario-form");

  const resetDbBtn = document.getElementById("reset-db-btn");
  const printReportBtn = document.getElementById("print-report-btn");

  // Diagnostics DOM
  const execStatusPill = document.getElementById("exec-status-pill");
  const execTimeLabel = document.getElementById("exec-time-label");
  const constructedSqlDisplay = document.getElementById("constructed-sql-display");
  const paramBindingBlock = document.getElementById("param-binding-block");
  const paramBindingDisplay = document.getElementById("param-binding-display");
  const tokenCountLabel = document.getElementById("token-count-label");
  const tokenStreamContainer = document.getElementById("token-stream-container");
  const recordCountLabel = document.getElementById("record-count-label");
  const dbErrorAlert = document.getElementById("db-error-alert");
  const dbTableHeaders = document.getElementById("db-table-headers");
  const dbTableBody = document.getElementById("db-table-body");
  const analysisText = document.getElementById("analysis-text");

  // SAST DOM
  const runSastBtn = document.getElementById("run-sast-btn");
  const presetsContainer = document.getElementById("presets-container");
  const sastCodeInput = document.getElementById("sast-code-input");
  const sastScore = document.getElementById("sast-score");
  const sastGrade = document.getElementById("sast-grade");
  const sastCriticalCount = document.getElementById("sast-critical-count");
  const sastSecureCount = document.getElementById("sast-secure-count");
  const sastFindingsList = document.getElementById("sast-findings-list");

  // Theory DOM
  const theorySqlInput = document.getElementById("theory-sql-input");
  const theoryTokenStream = document.getElementById("theory-token-stream");

  // ==========================================
  // 1. Tab Navigation
  // ==========================================
  tabButtons.forEach(btn => {
    btn.addEventListener("click", () => {
      const targetTabId = btn.getAttribute("data-tab");
      tabButtons.forEach(b => b.classList.remove("active"));
      tabContents.forEach(c => c.classList.remove("active"));

      btn.classList.add("active");
      const activeContent = document.getElementById(targetTabId);
      if (activeContent) activeContent.classList.add("active");

      if (targetTabId === "tab-theory") {
        updateTheoryTokens(theorySqlInput.value);
      }
    });
  });

  // ==========================================
  // 2. Mode Toggle (Vulnerable vs Mitigated)
  // ==========================================
  modeVulnBtn.addEventListener("click", () => {
    state.currentMode = "vulnerable";
    modeVulnBtn.classList.add("active");
    modeMitigBtn.classList.remove("active");
    modeDescBadge.className = "mode-desc-pill vuln-desc";
    modeDescBadge.innerHTML = "⚠️ WARNING: Raw string concatenation active. Vulnerable to syntax manipulation.";
    paramBindingBlock.style.display = "none";
  });

  modeMitigBtn.addEventListener("click", () => {
    state.currentMode = "mitigated";
    modeMitigBtn.classList.add("active");
    modeVulnBtn.classList.remove("active");
    modeDescBadge.className = "mode-desc-pill mitig-desc";
    modeDescBadge.innerHTML = "🛡️ SECURE: Prepared statements active. Query syntax pre-compiled; parameters bound separately.";
    paramBindingBlock.style.display = "block";
  });

  // ==========================================
  // 3. Scenario Selection
  // ==========================================
  scenarioButtons.forEach(btn => {
    btn.addEventListener("click", () => {
      scenarioButtons.forEach(b => b.classList.remove("active"));
      scenarioForms.forEach(f => f.classList.remove("active"));

      btn.classList.add("active");
      state.currentScenario = btn.getAttribute("data-scenario");
      const targetForm = document.getElementById(`form-${state.currentScenario}`);
      if (targetForm) targetForm.classList.add("active");
    });
  });

  // ==========================================
  // 4. Sample Payloads Quick-Fill Chips
  // ==========================================
  document.querySelectorAll(".btn-chip").forEach(chip => {
    chip.addEventListener("click", () => {
      if (state.currentScenario === "auth") {
        const u = chip.getAttribute("data-user");
        const p = chip.getAttribute("data-pwd");
        if (u !== null) document.getElementById("auth-username").value = u;
        if (p !== null) document.getElementById("auth-password").value = p;
      } else if (state.currentScenario === "search") {
        const kw = chip.getAttribute("data-kw");
        if (kw !== null) document.getElementById("search-keyword").value = kw;
      } else if (state.currentScenario === "profile") {
        const id = chip.getAttribute("data-id");
        if (id !== null) document.getElementById("profile-user-id").value = id;
      }
    });
  });

  // ==========================================
  // 5. Form Submissions (API Dispatch)
  // ==========================================
  document.getElementById("form-auth").addEventListener("submit", async (e) => {
    e.preventDefault();
    const username = document.getElementById("auth-username").value;
    const password = document.getElementById("auth-password").value;
    await executeLabRequest("/api/lab/login", { username, password, mode: state.currentMode });
  });

  document.getElementById("form-search").addEventListener("submit", async (e) => {
    e.preventDefault();
    const keyword = document.getElementById("search-keyword").value;
    await executeLabRequest("/api/lab/search", { keyword, mode: state.currentMode });
  });

  document.getElementById("form-profile").addEventListener("submit", async (e) => {
    e.preventDefault();
    const user_id = document.getElementById("profile-user-id").value;
    await executeLabRequest("/api/lab/profile", { user_id, mode: state.currentMode });
  });

  async function executeLabRequest(endpoint, payload) {
    execStatusPill.className = "status-pill status-ready";
    execStatusPill.textContent = "EXECUTING...";

    try {
      const response = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });

      if (!response.ok) {
        throw new Error(`Server returned HTTP ${response.status}`);
      }

      const data = await response.json();
      renderExecutionResults(data);
    } catch (err) {
      execStatusPill.className = "status-pill status-error";
      execStatusPill.textContent = "FAILED";
      dbErrorAlert.style.display = "block";
      dbErrorAlert.textContent = `Client Exception: ${err.message}`;
    }
  }

  function renderExecutionResults(data) {
    const exec = data.execution;
    const analysis = data.query_analysis;

    // Status pill
    if (exec.status === "SUCCESS" || exec.status === "COMPLETED") {
      execStatusPill.className = "status-pill status-success";
      execStatusPill.textContent = exec.status;
    } else if (exec.status === "NO_RECORDS_FOUND") {
      execStatusPill.className = "status-pill status-ready";
      execStatusPill.textContent = "0 ROWS";
    } else {
      execStatusPill.className = "status-pill status-error";
      execStatusPill.textContent = exec.status;
    }

    // Execution time
    execTimeLabel.textContent = `${exec.execution_time_ms} ms`;

    // Constructed query / template
    if (exec.mode === "MITIGATED") {
      constructedSqlDisplay.textContent = exec.query_template || "N/A";
      paramBindingBlock.style.display = "block";
      paramBindingDisplay.textContent = JSON.stringify(exec.bound_parameters || {}, null, 2);
    } else {
      constructedSqlDisplay.textContent = exec.constructed_query || "N/A";
      paramBindingBlock.style.display = "none";
    }

    // Database error display
    if (exec.database_error) {
      dbErrorAlert.style.display = "block";
      dbErrorAlert.textContent = `Database Feedback: ${exec.database_error}`;
    } else {
      dbErrorAlert.style.display = "none";
    }

    // Render Records Table
    renderRecordsTable(exec.records || []);

    // Token Stream
    const tokens = (exec.mode === "MITIGATED")
      ? analysis.mitigated_mode.token_stream
      : analysis.vulnerable_mode.token_stream;
    renderTokenBadges(tokens, tokenStreamContainer, tokenCountLabel);

    // Security Analysis Text
    let analysisHtml = "";
    if (exec.mode === "MITIGATED") {
      analysisHtml = `
        <strong>${exec.security_analysis.defense_standard}</strong><br>
        <em>Status: ${exec.security_analysis.mitigation_level}</em><br>
        ${exec.security_analysis.explanation}
      `;
    } else {
      analysisHtml = `
        <strong>${exec.security_analysis.cwe_id}</strong> (Risk: ${exec.security_analysis.risk_level})<br>
        ${exec.security_analysis.vulnerability_root_cause}
      `;
      if (analysis.vulnerable_mode.grammar_mutations_detected?.length > 0) {
        analysisHtml += `<br><span style="color:#f87171;">⚠️ Syntactic Mutations Detected: ${analysis.vulnerable_mode.grammar_mutations_detected.join(", ")}</span>`;
      }
    }
    analysisText.innerHTML = analysisHtml;
  }

  function renderRecordsTable(records) {
    recordCountLabel.textContent = `${records.length} Record${records.length === 1 ? '' : 's'}`;
    dbTableHeaders.innerHTML = "";
    dbTableBody.innerHTML = "";

    if (!records || records.length === 0) {
      dbTableHeaders.innerHTML = "<th>Result</th>";
      dbTableBody.innerHTML = "<tr><td>No records returned for this query.</td></tr>";
      return;
    }

    const keys = Object.keys(records[0]);
    keys.forEach(k => {
      const th = document.createElement("th");
      th.textContent = k;
      dbTableHeaders.appendChild(th);
    });

    records.forEach(row => {
      const tr = document.createElement("tr");
      keys.forEach(k => {
        const td = document.createElement("td");
        td.textContent = (row[k] !== null && row[k] !== undefined) ? String(row[k]) : "NULL";
        tr.appendChild(td);
      });
      dbTableBody.appendChild(tr);
    });
  }

  function renderTokenBadges(tokens, container, countLabel) {
    container.innerHTML = "";
    if (countLabel) countLabel.textContent = `${tokens ? tokens.length : 0} Tokens`;

    if (!tokens || tokens.length === 0) {
      container.innerHTML = "<span class='placeholder-text'>No tokens identified.</span>";
      return;
    }

    tokens.forEach(t => {
      const span = document.createElement("span");
      span.className = `token-badge badge-${t.type} ${t.is_injection_sensitive ? 'token-anomaly' : ''}`;
      span.textContent = `${t.value}`;
      span.title = `Type: ${t.type}`;
      container.appendChild(span);
    });
  }

  // ==========================================
  // 6. Theory Interactive Tokenizer
  // ==========================================
  let theoryDebounce = null;
  theorySqlInput.addEventListener("input", () => {
    clearTimeout(theoryDebounce);
    theoryDebounce = setTimeout(() => {
      updateTheoryTokens(theorySqlInput.value);
    }, 250);
  });

  async function updateTheoryTokens(sql) {
    if (!sql.trim()) {
      theoryTokenStream.innerHTML = "<span class='placeholder-text'>Type SQL above to tokenize...</span>";
      return;
    }
    try {
      const res = await fetch("/api/lab/tokenize", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sql })
      });
      if (res.ok) {
        const data = await res.json();
        renderTokenBadges(data.tokens, theoryTokenStream, null);
      }
    } catch (e) {
      console.error("Tokenize error:", e);
    }
  }

  // ==========================================
  // 7. SAST Code Scanner & Presets
  // ==========================================
  async function loadSastPresets() {
    try {
      const res = await fetch("/api/sast/presets");
      if (res.ok) {
        const data = await res.json();
        state.sastPresets = data.presets;
        renderPresetsButtons();
        if (state.sastPresets.length > 0) {
          sastCodeInput.value = state.sastPresets[0].code;
        }
      }
    } catch (e) {
      console.error("Failed to load presets:", e);
    }
  }

  function renderPresetsButtons() {
    presetsContainer.innerHTML = "";
    state.sastPresets.forEach((p, idx) => {
      const btn = document.createElement("button");
      btn.className = "preset-chip";
      btn.textContent = p.title;
      btn.addEventListener("click", () => {
        sastCodeInput.value = p.code;
      });
      presetsContainer.appendChild(btn);
    });
  }

  runSastBtn.addEventListener("click", async () => {
    const code = sastCodeInput.value;
    if (!code.trim()) {
      alert("Please enter Python code to scan.");
      return;
    }

    runSastBtn.textContent = "Scanning...";
    runSastBtn.disabled = true;

    try {
      const res = await fetch("/api/sast/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code })
      });

      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      renderSastResults(data);
    } catch (e) {
      alert(`SAST Scan Failed: ${e.message}`);
    } finally {
      runSastBtn.textContent = "⚡ Run AST Security Audit";
      runSastBtn.disabled = false;
    }
  });

  function renderSastResults(data) {
    if (data.status === "SYNTAX_ERROR") {
      sastFindingsList.innerHTML = `<div class="alert-box alert-error">${data.error_message}</div>`;
      sastScore.textContent = "ERR";
      sastGrade.textContent = "SYNTAX";
      sastCriticalCount.textContent = "!";
      sastSecureCount.textContent = "0";
      return;
    }

    const s = data.summary;
    sastScore.textContent = `${s.safety_score}/100`;
    sastGrade.textContent = s.grade;
    sastCriticalCount.textContent = s.critical_vulnerabilities;
    sastSecureCount.textContent = s.secure_patterns;

    sastFindingsList.innerHTML = "";
    if (data.findings.length === 0) {
      sastFindingsList.innerHTML = "<p class='placeholder-text'>No database execute() calls detected in this code block.</p>";
      return;
    }

    data.findings.forEach(f => {
      const item = document.createElement("div");
      item.className = `finding-item severity-${f.severity}`;
      
      item.innerHTML = `
        <div class="finding-top">
          <span class="finding-title">Line ${f.line_number}: ${f.vulnerability_type}</span>
          <span class="badge ${f.is_secure ? 'badge-success' : 'badge-cwe'}">${f.severity}</span>
        </div>
        <div class="finding-details">${f.details}</div>
        <div class="finding-code"><code>${escapeHtml(f.code_snippet)}</code></div>
        <div class="finding-remediation">
          <strong>Remediation:</strong> ${f.remediation_guidance}
          ${f.recommended_patch ? `<br><code>${escapeHtml(f.recommended_patch)}</code>` : ''}
        </div>
      `;
      sastFindingsList.appendChild(item);
    });
  }

  function escapeHtml(str) {
    if (!str) return "";
    return str
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  // ==========================================
  // 8. Database Reset & Print Actions
  // ==========================================
  resetDbBtn.addEventListener("click", async () => {
    if (!confirm("Reset database to initial sample records?")) return;
    try {
      const res = await fetch("/api/db/reset", { method: "POST" });
      const data = await res.json();
      alert(data.message || "Database reset successfully!");
    } catch (e) {
      alert(`Reset failed: ${e.message}`);
    }
  });

  printReportBtn.addEventListener("click", () => {
    window.print();
  });

  // Initialization
  loadSastPresets();
});
