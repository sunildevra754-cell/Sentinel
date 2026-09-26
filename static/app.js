// Sentinel Frontend Real-Time Controller & Speech Engine

let selectedModelId = "model_fraud";
let modelsData = [];
let driftChart = null;
let voiceAlertsEnabled = true;
let lastSpokenIncidentId = null;

// Initialize Lucide icons and Chart on load
document.addEventListener("DOMContentLoaded", () => {
  if (window.lucide) {
    lucide.createIcons();
  }
  initDriftChart();
  fetchInitialData();
  
  // Start real-time polling loop
  setInterval(pollRealTimeTelemetry, 1500);
});

function initDriftChart() {
  const ctx = document.getElementById("driftChart").getContext("2d");
  driftChart = new Chart(ctx, {
    type: "bar",
    data: {
      labels: ["amount", "velocity", "location", "device", "account_age", "foreign_ip", "failed_att", "merchant_risk"],
      datasets: [
        {
          label: "Feature PSI Drift",
          data: [0.01, 0.02, 0.01, 0.01, 0.02, 0.01, 0.01, 0.02],
          backgroundColor: "rgba(0, 240, 255, 0.6)",
          borderColor: "#00f0ff",
          borderWidth: 1.5,
          borderRadius: 4
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: { duration: 500 },
      scales: {
        y: {
          beginAtZero: true,
          max: 0.6,
          grid: { color: "rgba(255, 255, 255, 0.05)" },
          ticks: { color: "#94a3b8", font: { family: "JetBrains Mono", size: 10 } }
        },
        x: {
          grid: { display: false },
          ticks: { color: "#94a3b8", font: { family: "Outfit", size: 10 } }
        }
      },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: "rgba(7, 9, 19, 0.95)",
          titleFont: { family: "Outfit", size: 12 },
          bodyFont: { family: "JetBrains Mono", size: 12 },
          borderColor: "rgba(0, 240, 255, 0.3)",
          borderWidth: 1
        }
      }
    }
  });
}

async function fetchInitialData() {
  await pollRealTimeTelemetry();
  await fetchAuditChain();
  await fetchIncidents();
}

async function pollRealTimeTelemetry() {
  try {
    // 1. Fetch Fleet Models Summary
    const resModels = await fetch("/api/models");
    if (resModels.ok) {
      modelsData = await resModels.json();
      renderModelTabs(modelsData);
      updateFleetStats(modelsData);
    }

    // 2. Fetch Selected Model Deep Telemetry
    const resDetail = await fetch(`/api/models/${selectedModelId}`);
    if (resDetail.ok) {
      const detail = await resDetail.json();
      renderModelTelemetry(detail);
    }

    // 3. Update Audit chain and Incidents periodically
    await fetchIncidents();
  } catch (err) {
    console.error("Telemetry polling error:", err);
  }
}

function renderModelTabs(models) {
  const container = document.getElementById("model-tabs-container");
  container.innerHTML = "";

  models.forEach(m => {
    const isSelected = m.model_id === selectedModelId;
    const isHealthy = m.trust_score >= 80;
    const isWarning = m.trust_score >= 50 && m.trust_score < 80;
    
    let badgeColor = "var(--status-healthy)";
    let badgeBg = "rgba(16, 185, 129, 0.15)";
    if (m.trust_score < 50) {
      badgeColor = "var(--status-critical)";
      badgeBg = "rgba(239, 68, 68, 0.15)";
    } else if (isWarning) {
      badgeColor = "var(--status-warning)";
      badgeBg = "rgba(245, 158, 11, 0.15)";
    }

    const card = document.createElement("div");
    card.className = `glass-panel model-tab-card ${isSelected ? "active" : ""}`;
    card.onclick = () => selectModel(m.model_id);

    card.innerHTML = `
      <div class="tab-header">
        <div>
          <div class="model-name">${m.name}</div>
          <div class="model-domain">${m.domain} • Ver: ${m.active_version}</div>
        </div>
        <div class="model-score-badge" style="background: ${badgeBg}; color: ${badgeColor}; border: 1px solid ${badgeColor};">
          ${m.trust_score.toFixed(1)}%
        </div>
      </div>
      <div style="display: flex; justify-content: space-between; align-items: center; font-size: 12px; margin-top: 8px;">
        <span class="tag-badge ${m.status.includes('QUARANTINED') ? 'tag-blocked' : (isWarning ? 'tag-throttled' : 'tag-approved')}">
          ${m.status}
        </span>
        <span style="color: var(--text-muted);">Risk Tier: <strong style="color: ${badgeColor};">${m.risk_tier}</strong></span>
      </div>
    `;
    container.appendChild(card);
  });
}

function selectModel(modelId) {
  selectedModelId = modelId;
  document.getElementById("sandbox-target-model").value = modelId;
  pollRealTimeTelemetry();
}

function updateFleetStats(models) {
  if (!models || models.length === 0) return;
  const avgTrust = (models.reduce((acc, m) => acc + m.trust_score, 0) / models.length).toFixed(1);
  const scoreElem = document.getElementById("fleet-trust-score");
  scoreElem.innerText = `${avgTrust}%`;
  
  if (avgTrust >= 80) {
    scoreElem.style.color = "var(--status-healthy)";
  } else if (avgTrust >= 50) {
    scoreElem.style.color = "var(--status-warning)";
  } else {
    scoreElem.style.color = "var(--status-critical)";
  }
}

function renderModelTelemetry(detail) {
  const trustScore = detail.trust_score;
  const scoreElem = document.getElementById("selected-trust-score");
  scoreElem.innerText = trustScore.toFixed(1);

  // SVG Gauge Fill update (Circumference ~ 565.48)
  const maxDash = 565.48;
  const offset = maxDash - (trustScore / 100) * maxDash;
  const circleFill = document.getElementById("gauge-circle-fill");
  circleFill.style.strokeDashoffset = offset;

  // Colors based on trust
  let color = "var(--status-healthy)";
  let statusText = "HEALTHY • BASELINE VERIFIED";
  let bannerBg = "rgba(16, 185, 129, 0.15)";

  if (detail.is_quarantined || detail.status.includes("QUARANTINED")) {
    color = "var(--status-critical)";
    statusText = "🚨 QUARANTINED • ROLLED BACK TO SAFE CHECKPOINT";
    bannerBg = "rgba(239, 68, 68, 0.2)";
  } else if (trustScore < 50) {
    color = "var(--status-critical)";
    statusText = "CRITICAL INTEGRITY DRIFT DETECTED";
    bannerBg = "rgba(239, 68, 68, 0.2)";
  } else if (trustScore < 80) {
    color = "var(--status-warning)";
    statusText = "⚠️ WARNING • CONFIDENCE THROTTLING ACTIVE";
    bannerBg = "rgba(245, 158, 11, 0.2)";
  }

  scoreElem.style.color = color;
  circleFill.style.stroke = color;

  const banner = document.getElementById("model-status-banner");
  banner.innerText = statusText;
  banner.style.color = color;
  banner.style.background = bannerBg;
  banner.style.borderColor = color;

  // Throttling & Graduated Response
  const throttleStatus = document.getElementById("throttling-status-text");
  const throttleFill = document.getElementById("throttling-meter-fill");
  const throttleVal = document.getElementById("throttle-threshold-val");
  
  throttleStatus.innerText = detail.throttling_level;
  const threshPct = Math.round(detail.auto_approval_threshold * 100);
  throttleVal.innerText = `${threshPct}%`;
  throttleFill.style.width = `${threshPct}%`;

  if (threshPct > 80) {
    throttleFill.style.background = "linear-gradient(90deg, #f59e0b, #ef4444)";
    throttleStatus.style.color = "var(--status-critical)";
  } else if (threshPct > 60) {
    throttleFill.style.background = "linear-gradient(90deg, #10b981, #f59e0b)";
    throttleStatus.style.color = "var(--status-warning)";
  } else {
    throttleFill.style.background = "var(--status-healthy)";
    throttleStatus.style.color = "var(--accent-cyan)";
  }

  // SHAP summary
  const shapElem = document.getElementById("shap-summary-text");
  if (detail.drift_metrics && detail.drift_metrics.max_psi >= 0.10) {
    const feat = detail.drift_metrics.max_drifting_feature;
    const psi = detail.drift_metrics.max_psi;
    shapElem.innerHTML = `<strong style="color: ${color};">ALERT:</strong> Feature <code>${feat}</code> shifted significantly (PSI: ${psi}). Attribution weights warped compared to clean baseline.`;
  } else {
    shapElem.innerText = "Model feature importance weights match verified baseline distribution within 99.4% confidence.";
  }

  // Update Feature Drift PSI Chart
  updateDriftChartData(detail.drift_metrics);

  // Update Live Stream Table
  renderStreamTable(detail.recent_transactions);

  // Attack status banner
  const attackBanner = document.getElementById("attack-active-banner");
  if (detail.attack_status && detail.attack_status.is_active) {
    attackBanner.style.display = "block";
    document.getElementById("sandbox-inject-btn").disabled = true;
    document.getElementById("sandbox-inject-btn").style.opacity = "0.5";
  } else {
    attackBanner.style.display = "none";
    document.getElementById("sandbox-inject-btn").disabled = false;
    document.getElementById("sandbox-inject-btn").style.opacity = "1";
  }

  // Honeypot stat top update
  const honeypotStat = document.getElementById("honeypot-stat");
  if (detail.honeypot_hit_count > 0) {
    honeypotStat.innerText = `🚨 ${detail.honeypot_hit_count} PROBE HITS`;
    honeypotStat.style.color = "var(--status-critical)";
  } else {
    honeypotStat.innerText = "ARMED (0 HITS)";
    honeypotStat.style.color = "var(--status-healthy)";
  }
}

function updateDriftChartData(driftMetrics) {
  if (!driftChart || !driftMetrics || !driftMetrics.features) return;
  const feats = Object.keys(driftMetrics.features);
  if (feats.length === 0) return;

  const psiVals = feats.map(f => driftMetrics.features[f].psi || 0.0);
  const colors = psiVals.map(v => {
    if (v >= 0.25) return "#ef4444"; // Severe
    if (v >= 0.10) return "#f59e0b"; // Warning
    return "rgba(0, 240, 255, 0.7)"; // Normal
  });

  driftChart.data.labels = feats;
  driftChart.data.datasets[0].data = psiVals;
  driftChart.data.datasets[0].backgroundColor = colors;
  driftChart.data.datasets[0].borderColor = colors;
  driftChart.update("none");
}

function renderStreamTable(transactions) {
  const tbody = document.getElementById("stream-table-body");
  if (!transactions || transactions.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">Waiting for incoming traffic stream...</td></tr>`;
    return;
  }

  tbody.innerHTML = "";
  // Show most recent on top
  const reversed = [...transactions].reverse();

  reversed.slice(0, 10).forEach(tx => {
    const row = document.createElement("tr");
    const isBlocked = tx.decision.includes("BLOCKED") || tx.raw_prediction === 1;
    const isThrottled = tx.throttling_action.includes("THROTTLE") || tx.decision.includes("MANUAL_REVIEW") || tx.decision.includes("STEP_UP");
    const isHoneypot = tx.honeypot_triggered;

    let decisionBadge = `<span class="tag-badge tag-approved">Approved</span>`;
    if (isHoneypot) {
      decisionBadge = `<span class="tag-badge tag-honeypot">🚨 CANARY PROBE</span>`;
    } else if (isBlocked) {
      decisionBadge = `<span class="tag-badge tag-blocked">Blocked</span>`;
    } else if (isThrottled) {
      decisionBadge = `<span class="tag-badge tag-throttled">Throttled (Step-Up)</span>`;
    }

    let integrityFlag = `<span style="color: var(--status-healthy); font-size: 11px;">VERIFIED</span>`;
    if (isHoneypot) {
      integrityFlag = `<strong style="color: #ec4899; font-size: 11px;">CANARY HIT: ${tx.canary_name}</strong>`;
    } else if (tx.leak_correlated) {
      integrityFlag = `<strong style="color: var(--status-critical); font-size: 11px;">DARKWEB LEAK MATCH</strong>`;
    }

    // Format sample key inputs
    const inputs = tx.inputs || {};
    let featSummary = "";
    if (inputs.amount !== undefined) {
      featSummary = `$${inputs.amount} | Vel: ${inputs.transaction_velocity_1h} | LocMismatch: ${inputs.location_mismatch_score}`;
    } else if (inputs.annual_income !== undefined) {
      featSummary = `Income: $${inputs.annual_income} | DTI: ${inputs.debt_to_income_ratio} | Bureau: ${inputs.credit_bureau_score}`;
    }

    const timeFormatted = new Date(tx.timestamp).toLocaleTimeString();

    row.innerHTML = `
      <td style="color: var(--text-muted);">${timeFormatted}</td>
      <td style="font-size: 11px; color: var(--text-secondary);">${featSummary}</td>
      <td style="font-weight: 700; color: ${tx.risk_score > 0.5 ? 'var(--status-critical)' : 'var(--status-healthy)'};">${(tx.risk_score * 100).toFixed(0)}%</td>
      <td>${decisionBadge}</td>
      <td>${integrityFlag}</td>
    `;
    tbody.appendChild(row);
  });
}

// ----------------- VERNACULAR & TTS VOICE ALERTS -----------------

async function fetchIncidents() {
  try {
    const res = await fetch("/api/incidents?limit=10");
    if (!res.ok) return;
    const incidents = await res.json();
    renderIncidentsFeed(incidents);
    
    // Check if new critical incident occurred to speak it aloud!
    if (incidents.length > 0 && voiceAlertsEnabled) {
      const latest = incidents[0];
      if (latest.id !== lastSpokenIncidentId) {
        lastSpokenIncidentId = latest.id;
        speakAlertAudio(latest.hindi_alert || latest.english_alert);
      }
    }
  } catch (e) {
    console.debug("Fetch incidents error:", e);
  }
}

function renderIncidentsFeed(incidents) {
  const container = document.getElementById("alerts-feed-container");
  if (!incidents || incidents.length === 0) {
    container.innerHTML = `
      <div class="alert-card" style="border-left-color: var(--status-healthy);">
        <div class="alert-title" style="color: var(--status-healthy);">System Baseline Verified</div>
        <div class="alert-english">All protected models are operating within clean baseline integrity parameters.</div>
        <div class="alert-hindi">सभी एआई मॉडल सुरक्षित और सामान्य रूप से कार्य कर रहे हैं।</div>
      </div>
    `;
    return;
  }

  container.innerHTML = "";
  incidents.forEach(inc => {
    const isCritical = inc.severity === "CRITICAL";
    const card = document.createElement("div");
    card.className = `alert-card ${isCritical ? "critical" : "warning"}`;

    const timeStr = new Date(inc.timestamp).toLocaleTimeString();

    card.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: flex-start;">
        <div class="alert-title" style="color: ${isCritical ? 'var(--status-critical)' : 'var(--status-warning)'};">
          ${inc.incident_type} (${inc.severity})
        </div>
        <button class="btn btn-outline" style="padding: 2px 8px; font-size: 10px;" onclick="speakCustomText('${escapeQuotes(inc.hindi_alert)}')">
          <i data-lucide="volume-2" style="width: 12px; height: 12px;"></i> Speak
        </button>
      </div>
      <div class="alert-english">${inc.english_alert}</div>
      <div class="alert-hindi">${inc.hindi_alert}</div>
      ${inc.shap_summary ? `<div style="font-size: 11px; color: var(--accent-cyan); margin-top: 6px;"><strong>SHAP Reason:</strong> ${inc.shap_summary}</div>` : ''}
      <div class="alert-meta">
        <span>Model: <strong>${inc.model_id}</strong> | PSI: <strong>${inc.drift_score_psi ? inc.drift_score_psi.toFixed(3) : 'N/A'}</strong></span>
        <span>${timeStr}</span>
      </div>
    `;
    container.appendChild(card);
  });

  if (window.lucide) lucide.createIcons();
}

function escapeQuotes(str) {
  if (!str) return "";
  return str.replace(/'/g, "\\'").replace(/"/g, '&quot;');
}

function speakAlertAudio(text) {
  if (!voiceAlertsEnabled || !('speechSynthesis' in window)) return;
  try {
    window.speechSynthesis.cancel(); // Stop ongoing speech
    const utterance = new SpeechSynthesisUtterance(text);
    utterance.rate = 1.0;
    utterance.pitch = 1.0;
    
    // Pick Hindi or English voice if available
    const voices = window.speechSynthesis.getVoices();
    const hiVoice = voices.find(v => v.lang.includes("hi") || v.lang.includes("IN"));
    if (hiVoice) {
      utterance.voice = hiVoice;
    }
    window.speechSynthesis.speak(utterance);
  } catch (e) {
    console.debug("TTS audio error:", e);
  }
}

function speakCustomText(text) {
  speakAlertAudio(text);
}

function toggleVoiceAlerts() {
  voiceAlertsEnabled = !voiceAlertsEnabled;
  const label = document.getElementById("tts-label");
  const icon = document.getElementById("tts-icon");
  if (voiceAlertsEnabled) {
    label.innerText = "Voice Alerts: ON";
    icon.setAttribute("data-lucide", "volume-2");
    speakAlertAudio("Voice alerts activated.");
  } else {
    label.innerText = "Voice Alerts: OFF";
    icon.setAttribute("data-lucide", "volume-x");
    if ('speechSynthesis' in window) window.speechSynthesis.cancel();
  }
  if (window.lucide) lucide.createIcons();
}

// ----------------- AUDIT HASH CHAIN EXPLORER -----------------

async function fetchAuditChain() {
  try {
    const res = await fetch("/api/audit-trail?limit=25");
    if (!res.ok) return;
    const blocks = await res.json();
    renderAuditChain(blocks);
  } catch (e) {
    console.debug("Fetch audit chain error:", e);
  }
}

function renderAuditChain(blocks) {
  const container = document.getElementById("audit-chain-container");
  if (!blocks || blocks.length === 0) {
    container.innerHTML = `<p style="color: var(--text-muted); font-size: 12px;">Genesis block initializing...</p>`;
    return;
  }

  container.innerHTML = "";
  blocks.forEach(b => {
    const blockElem = document.createElement("div");
    blockElem.className = "chain-block";
    const timeStr = new Date(b.timestamp).toLocaleTimeString();

    blockElem.innerHTML = `
      <div class="chain-block-header">
        <span style="font-weight: 700; color: #fff;">Block #${b.id} • ${b.event_type}</span>
        <span style="color: var(--text-muted);">${timeStr}</span>
      </div>
      <div style="font-size: 11px; color: var(--text-secondary); margin-bottom: 6px;">
        Model: <code>${b.model_id}</code> | Action: <code>${b.details.action || b.details.event || 'SYSTEM_EVENT'}</code>
      </div>
      <div style="display: flex; flex-direction: column; gap: 4px;">
        <div><span style="font-size: 10px; color: var(--text-muted);">PREV HASH:</span> <span class="hash-code">${b.prev_hash.substring(0, 24)}...</span></div>
        <div><span style="font-size: 10px; color: var(--text-muted);">BLOCK HASH:</span> <span class="hash-code" style="color: #10b981;">${b.current_hash.substring(0, 24)}...</span></div>
      </div>
    `;
    container.appendChild(blockElem);
  });
}

async function verifyAuditChain() {
  try {
    const res = await fetch("/api/audit-trail/verify");
    const data = await res.json();
    const badge = document.getElementById("audit-chain-badge");
    
    if (data.integrity_verified) {
      badge.innerText = `SHA-256 VERIFIED (${data.total_blocks_checked} BLOCKS 100% INTACT)`;
      badge.style.color = "var(--status-healthy)";
      alert(`✅ Cryptographic Audit Integrity Verified!\n\nAll ${data.total_blocks_checked} blocks in the SHA-256 hash-chain are mathematically intact. Zero tampering detected.`);
    } else {
      badge.innerText = `TAMPERING DETECTED!`;
      badge.style.color = "var(--status-critical)";
      alert(`❌ Chain Tampering Detected!\n\n${data.status_message}`);
    }
  } catch (e) {
    alert("Verification failed: " + e);
  }
}

// ----------------- INTERACTIVE SANDBOX CONTROLS -----------------

function updateIntensityDisplay(val) {
  document.getElementById("intensity-val-text").innerText = `${Math.round(val * 100)}%`;
}

async function launchSandboxAttack() {
  const modelId = document.getElementById("sandbox-target-model").value;
  const attackType = document.getElementById("sandbox-attack-type").value;
  const intensity = parseFloat(document.getElementById("sandbox-intensity").value);

  try {
    const res = await fetch("/api/attacks/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model_id: modelId,
        attack_type: attackType,
        intensity: intensity
      })
    });
    const data = await res.json();
    if (data.success) {
      pollRealTimeTelemetry();
      fetchAuditChain();
      speakAlertAudio("Poisoning attack launched on " + modelId);
    }
  } catch (e) {
    alert("Attack launch error: " + e);
  }
}

async function stopSandboxAttack() {
  const modelId = document.getElementById("sandbox-target-model").value;
  try {
    await fetch(`/api/attacks/stop?model_id=${modelId}`, { method: "POST" });
    pollRealTimeTelemetry();
    fetchAuditChain();
  } catch (e) {
    console.error(e);
  }
}

async function manualRollback() {
  const modelId = document.getElementById("sandbox-target-model").value;
  try {
    const res = await fetch(`/api/models/${modelId}/rollback`, { method: "POST" });
    const data = await res.json();
    if (data.success) {
      pollRealTimeTelemetry();
      fetchAuditChain();
      speakAlertAudio("Emergency rollback executed. Model restored to safe checkpoint.");
      alert(`🛡️ Emergency Rollback Successful!\n\n${data.message}`);
    }
  } catch (e) {
    alert("Rollback error: " + e);
  }
}

async function resetAllModels() {
  try {
    for (const m of ["model_fraud", "model_kyc"]) {
      await fetch(`/api/models/${m}/reset`, { method: "POST" });
    }
    pollRealTimeTelemetry();
    fetchAuditChain();
    speakAlertAudio("System reset to healthy baseline.");
  } catch (e) {
    console.error(e);
  }
}

async function triggerAutoDemo() {
  try {
    const res = await fetch("/api/demo/auto-run", { method: "POST" });
    const data = await res.json();
    if (data.success) {
      speakAlertAudio("Exhibition Demo story started. Observe the real-time AI integrity defense in action.");
      alert("✨ 1-Click Exhibition Demo Story Started!\n\nSentinel is now stepping through the live attack injection, real-time drift detection, SHAP explanation, confidence throttling, and auto-rollback. Watch the live dashboard!");
    }
  } catch (e) {
    alert("Demo error: " + e);
  }
}
