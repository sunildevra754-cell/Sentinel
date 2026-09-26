import streamlit as st
import pandas as pd
import numpy as np
import time
from datetime import datetime, timezone
import json

from backend.config import MODEL_FRAUD_ID, MODEL_KYC_ID, MODEL_METADATA
from backend.models.train_models import train_all_models
from backend.models.model_registry import model_registry
from backend.attack_simulator.simulator import attack_simulator, ATTACK_TYPES
from backend.storage.database import init_db, get_db_connection
from backend.storage.audit_chain import get_audit_trail, verify_chain_integrity, record_audit_event
from backend.engine.vernacular import translate_alert

# Streamlit Page Config
st.set_page_config(
    page_title="Sentinel — AI Model Integrity & Trust Layer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS styling for dark mode
st.markdown("""
<style>
    .main { background-color: #070913; }
    .stMetric { background: rgba(18, 24, 43, 0.7); padding: 12px; border-radius: 10px; border: 1px solid rgba(255, 255, 255, 0.08); }
    .alert-box { padding: 14px; border-radius: 8px; margin-bottom: 10px; }
    .alert-crit { background: rgba(239, 68, 68, 0.15); border-left: 4px solid #ef4444; }
    .alert-warn { background: rgba(245, 158, 11, 0.15); border-left: 4px solid #f59e0b; }
    .alert-info { background: rgba(0, 240, 255, 0.1); border-left: 4px solid #00f0ff; }
</style>
""", unsafe_allow_html=True)

# Initialize models once
@st.cache_resource
def setup_sentinel():
    init_db()
    try:
        model_registry.initialize_models()
    except Exception:
        train_all_models()
        model_registry.initialize_models()
    return True

setup_sentinel()

# Header
st.title("🛡️ SENTINEL — AI Model Integrity & Trust Layer")
st.caption("Real-Time Poisoning Detection • SHAP Explainability • Vernacular Hindi Alerts • SHA-256 Audit Chain")

# Sidebar - Controls & Status
with st.sidebar:
    st.header("⚡ Sentinel Control Hub")
    
    # Audit Integrity Check
    is_valid, chain_msg, count = verify_chain_integrity()
    if is_valid:
        st.success(f"🔒 SHA-256 Chain: {count} Blocks Verified")
    else:
        st.error(f"🚨 Tampering: {chain_msg}")
        
    st.markdown("---")
    st.subheader("🎯 Active Target Model")
    selected_model_id = st.selectbox(
        "Select Model to Inspect:",
        options=[MODEL_FRAUD_ID, MODEL_KYC_ID],
        format_func=lambda x: MODEL_METADATA[x]["name"]
    )
    
    st.markdown("---")
    st.subheader("🧪 Exhibition Attack Sandbox")
    attack_type = st.selectbox(
        "Attack Vector:",
        options=list(ATTACK_TYPES.keys()),
        format_func=lambda x: ATTACK_TYPES[x]["name"]
    )
    intensity = st.slider("Attack Intensity:", 0.2, 1.0, 0.75, 0.05)
    
    col_atk1, col_atk2 = st.columns(2)
    with col_atk1:
        if st.button("🚀 Inject Attack", use_container_width=True, type="primary"):
            attack_simulator.start_attack(selected_model_id, attack_type, intensity)
            record_audit_event("ATTACK_SIMULATION_TRIGGERED", selected_model_id, {
                "attack_type": attack_type,
                "intensity": intensity
            })
            st.warning(f"Attack '{attack_type}' injected!")
            st.rerun()

    with col_atk2:
        if st.button("⏹️ Stop Attack", use_container_width=True):
            attack_simulator.stop_attack(selected_model_id)
            st.info("Attack stopped.")
            st.rerun()

    st.markdown("---")
    if st.button("🛡️ Emergency Rollback to Checkpoint", use_container_width=True):
        model = model_registry.get_model(selected_model_id)
        if model:
            model._trigger_auto_quarantine(is_attack_active=False)
            st.success("Rolled back to safe clean checkpoint!")
            st.rerun()

    if st.button("🔄 Reset Fleet to Healthy", use_container_width=True):
        for m in [MODEL_FRAUD_ID, MODEL_KYC_ID]:
            attack_simulator.stop_attack(m)
            model_registry.get_model(m).manual_reset_to_healthy()
        st.success("All models reset to verified clean state.")
        st.rerun()

# Model Object
managed_model = model_registry.get_model(selected_model_id)
is_attack = attack_simulator.is_attack_active(selected_model_id)

# Simulate 1 live step on load or rerun
sample = attack_simulator.generate_next_sample(selected_model_id)
latest_tx = managed_model.predict(sample, is_attack_active=is_attack)

# Fleet Summary Top Cards
st.subheader("🌐 Cross-Model Risk Matrix & Fleet Telemetry")
col1, col2, col3, col4 = st.columns(4)

summaries = model_registry.get_all_models_summary()
fraud_sum = next(s for s in summaries if s["model_id"] == MODEL_FRAUD_ID)
kyc_sum = next(s for s in summaries if s["model_id"] == MODEL_KYC_ID)

with col1:
    st.metric("Model 1: Payment Fraud Trust", f"{fraud_sum['trust_score']}%", delta=f"{fraud_sum['status']}")
with col2:
    st.metric("Model 2: KYC Underwriting Trust", f"{kyc_sum['trust_score']}%", delta=f"{kyc_sum['status']}")
with col3:
    st.metric("Graduated Throttling", f"{managed_model.trust_engine.throttling_level}")
with col4:
    st.metric("Adversarial Honeypots", f"{len(managed_model.honeypot_triggers)} Hits Detected")

st.markdown("---")

# Main Tabs
tab_monitor, tab_explain, tab_vernacular, tab_audit = st.tabs([
    "📊 Live Telemetry & PSI Drift",
    "🧠 SHAP Explainability",
    "🇮🇳 Vernacular Bilingual Alerts",
    "⛓️ SHA-256 Audit Trail"
])

with tab_monitor:
    col_t1, col_t2 = st.columns([1, 2])
    
    with col_t1:
        st.subheader("Model Status & Trust Gauge")
        trust_val = managed_model.trust_engine.current_score
        
        if trust_val >= 80:
            st.success(f"🟢 **HEALTHY** • Trust Score: **{trust_val}%**")
        elif trust_val >= 50:
            st.warning(f"🟡 **WARNING / THROTTLED** • Trust Score: **{trust_val}%**")
        else:
            st.error(f"🔴 **QUARANTINED & ROLLED BACK** • Trust Score: **{trust_val}%**")
            
        st.write(f"**Active Checkpoint Version:** `{managed_model.active_version}`")
        st.write(f"**Throttled Auto-Approval Threshold:** `{int(managed_model.trust_engine.auto_approval_threshold * 100)}%`")
        
        if is_attack:
            st.error("⚠️ **ATTACK SIMULATION ACTIVE**")

    with col_t2:
        st.subheader("Feature-Level PSI Drift Analysis")
        drift_data = managed_model.last_drift_result.get("features", {})
        if drift_data:
            df_drift = pd.DataFrame([
                {"Feature": k, "PSI": v.get("psi", 0), "Status": v.get("status", "OK")}
                for k, v in drift_data.items()
            ]).set_index("Feature")
            st.bar_chart(df_drift["PSI"])
        else:
            st.info("Accumulating live stream for statistical drift calculation...")

    st.subheader("📡 Live Incoming Inference Stream")
    tx_list = list(managed_model.recent_transactions)[-8:]
    if tx_list:
        df_tx = pd.DataFrame([{
            "Time": tx["timestamp"].split("T")[1][:8],
            "Risk Probability": f"{int(tx['risk_score'] * 100)}%",
            "Sentinel Decision": tx["decision"],
            "Throttling Action": tx["throttling_action"],
            "Honeypot Triggered": "🚨 CANARY PROBE" if tx["honeypot_triggered"] else "Safe"
        } for tx in reversed(tx_list)])
        st.dataframe(df_tx, use_container_width=True)

with tab_explain:
    st.subheader("SHAP Feature Attributions & Plain-Language Summary")
    st.info(f"💡 **Executive SHAP Summary:** {managed_model.last_explanation}")
    st.write(f"**Latest Transaction Attribution:** {latest_tx.get('shap_summary', 'Normal baseline')}")
    st.json(latest_tx.get("inputs", {}))

with tab_vernacular:
    st.subheader("Bilingual Alert Feed (English + Hindi)")
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT 5")
    incidents = cursor.fetchall()
    conn.close()

    if incidents:
        for inc in incidents:
            css_class = "alert-crit" if inc["severity"] == "CRITICAL" else "alert-warn"
            st.markdown(f"""
            <div class="alert-box {css_class}">
                <div style="font-weight: bold; font-size: 14px;">🚨 {inc['incident_type']} ({inc['severity']}) - {inc['timestamp'][:19]}</div>
                <div style="margin-top: 4px; color: #fff;"><strong>EN:</strong> {inc['english_alert']}</div>
                <div style="margin-top: 4px; color: #fbbf24; font-size: 15px;"><strong>HI (हिंदी):</strong> {inc['hindi_alert']}</div>
                <div style="margin-top: 4px; font-size: 12px; color: #94a3b8;"><strong>Action Taken:</strong> {inc['action_taken']}</div>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.success("No security incidents detected. System operating normally.")

with tab_audit:
    st.subheader("Immutable SHA-256 Hash-Chain Explorer")
    audit_blocks = get_audit_trail(limit=10)
    for b in audit_blocks:
        with st.expander(f"Block #{b['id']} — {b['event_type']} ({b['timestamp'][:19]})"):
            st.code(f"PREV HASH:    {b['prev_hash']}\nCURRENT HASH: {b['current_hash']}", language="bash")
            st.json(b["details"])
