import asyncio
import logging
from contextlib import asynccontextmanager
from typing import Dict, Any, Optional, List
from fastapi import FastAPI, HTTPException, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from backend.config import (
    BASE_DIR,
    MODEL_FRAUD_ID,
    MODEL_KYC_ID,
    MODEL_METADATA
)
from backend.models.train_models import train_all_models
from backend.models.model_registry import model_registry
from backend.attack_simulator.simulator import attack_simulator, ATTACK_TYPES
from backend.storage.database import init_db, get_db_connection
from backend.storage.audit_chain import get_audit_trail, verify_chain_integrity, record_audit_event
from backend.engine.vernacular import translate_alert

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("sentinel.api")

# Background simulation runner state
SIMULATION_STATE = {
    "is_running": True,
    "interval_seconds": 1.5,
    "demo_auto_playing": False,
    "demo_step": 0
}

async def background_traffic_loop():
    """Continuously feeds live simulated traffic into both models for real-time monitoring."""
    logger.info("Starting background real-time transaction traffic generator...")
    while True:
        try:
            if SIMULATION_STATE["is_running"]:
                for model_id in [MODEL_FRAUD_ID, MODEL_KYC_ID]:
                    model = model_registry.get_model(model_id)
                    if model:
                        is_attack = attack_simulator.is_attack_active(model_id)
                        sample = attack_simulator.generate_next_sample(model_id)
                        model.predict(sample, is_attack_active=is_attack)
        except Exception as e:
            logger.error("Background simulation step error: %s", e)
            
        await asyncio.sleep(SIMULATION_STATE["interval_seconds"])

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initializes DB, models, and starts background stream loop on startup."""
    init_db()
    # Check if models exist, otherwise train them
    fraud_chk = BASE_DIR / "data" / "checkpoints" / f"{MODEL_FRAUD_ID}_clean_v1.joblib"
    if not fraud_chk.exists():
        logger.info("No existing model checkpoints found. Training baseline models now...")
        train_all_models()

    model_registry.initialize_models()
    
    # Launch background traffic simulation task
    task = asyncio.create_task(background_traffic_loop())
    yield
    task.cancel()

app = FastAPI(
    title="Sentinel - AI Model Integrity & Trust Layer",
    description="Real-Time Model Drift, Adversarial Poisoning Detection, Vernacular Alerts, and Auto-Rollback Platform.",
    version="2.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

# ----------------- REQUEST SCHEMAS -----------------
class PredictRequest(BaseModel):
    features: Optional[Dict[str, Any]] = None

class AttackStartRequest(BaseModel):
    model_id: str = MODEL_FRAUD_ID
    attack_type: str = "GRADUAL_POISONING"
    intensity: float = 0.70

class SimulationConfig(BaseModel):
    is_running: bool
    interval_seconds: float = 1.5

# ----------------- API ENDPOINTS -----------------

@app.get("/api/status")
def get_system_status():
    """System health and global telemetry overview."""
    is_valid, chain_msg, block_count = verify_chain_integrity()
    return {
        "sentinel_status": "ONLINE",
        "simulation_running": SIMULATION_STATE["is_running"],
        "simulation_interval": SIMULATION_STATE["interval_seconds"],
        "demo_auto_playing": SIMULATION_STATE["demo_auto_playing"],
        "audit_chain_valid": is_valid,
        "audit_chain_blocks": block_count,
        "audit_message": chain_msg,
        "models_monitored": len(model_registry.models)
    }

@app.get("/api/models")
def list_models_comparison():
    """Cross-model trust score comparison & organizational risk surface."""
    return model_registry.get_all_models_summary()

@app.get("/api/models/{model_id}")
def get_model_details(model_id: str):
    """Detailed telemetry and diagnostics for a specific model."""
    model = model_registry.get_model(model_id)
    if not model:
        raise HTTPException(status_code=404, detail="Model not found")

    attack_info = attack_simulator.get_attack_status(model_id)
    return {
        "model_id": model.model_id,
        "name": model.meta["name"],
        "domain": model.meta["domain"],
        "active_version": model.active_version,
        "status": model.status,
        "trust_score": model.trust_engine.current_score,
        "throttling_level": model.trust_engine.throttling_level,
        "auto_approval_threshold": model.trust_engine.auto_approval_threshold,
        "is_quarantined": model.is_quarantined,
        "is_rolled_back": model.is_rolled_back,
        "drift_metrics": model.last_drift_result,
        "last_explanation": model.last_explanation,
        "last_alert": model.last_alert_payload,
        "attack_status": attack_info,
        "recent_transactions": list(model.recent_transactions)[-12:],
        "honeypot_hit_count": len(model.honeypot_triggers),
        "recent_honeypots": list(model.honeypot_triggers)[-5:]
    }

@app.post("/api/models/{model_id}/predict")
def run_model_prediction(model_id: str, req: PredictRequest):
    """Inference endpoint for a specific model."""
    model = model_registry.get_model(model_id)
    if not model:
        raise HTTPException(status_code=404, detail="Model not found")

    is_attack = attack_simulator.is_attack_active(model_id)
    sample = req.features if req.features else attack_simulator.generate_next_sample(model_id)
    result = model.predict(sample, is_attack_active=is_attack)
    return result

@app.post("/api/models/{model_id}/rollback")
def rollback_model_endpoint(model_id: str):
    """Manual operator trigger for quarantine and rollback."""
    model = model_registry.get_model(model_id)
    if not model:
        raise HTTPException(status_code=404, detail="Model not found")

    model._trigger_auto_quarantine(is_attack_active=attack_simulator.is_attack_active(model_id))
    return {
        "success": True,
        "message": f"Model {model_id} successfully quarantined and rolled back to verified safe checkpoint.",
        "status": model.status,
        "active_version": model.active_version
    }

@app.post("/api/models/{model_id}/reset")
def reset_model_endpoint(model_id: str):
    """Resets model health back to clean baseline state."""
    model = model_registry.get_model(model_id)
    if not model:
        raise HTTPException(status_code=404, detail="Model not found")

    attack_simulator.stop_attack(model_id)
    model.manual_reset_to_healthy()
    return {
        "success": True,
        "message": f"Model {model_id} reset to healthy clean state.",
        "trust_score": model.trust_engine.current_score,
        "status": model.status
    }

# ----------------- ATTACK SIMULATOR ENDPOINTS -----------------

@app.get("/api/attacks/catalog")
def get_attack_types_catalog():
    """Catalog of all supported synthetic attack vectors for the Exhibition Sandbox."""
    return ATTACK_TYPES

@app.post("/api/attacks/start")
def start_attack_simulation(req: AttackStartRequest):
    """Launches an interactive attack in the sandbox."""
    model = model_registry.get_model(req.model_id)
    if not model:
        raise HTTPException(status_code=404, detail="Target model not found")

    attack_state = attack_simulator.start_attack(req.model_id, req.attack_type, req.intensity)
    
    # Record attack launch in audit trail
    record_audit_event("ATTACK_SIMULATION_TRIGGERED", req.model_id, {
        "attack_type": req.attack_type,
        "intensity": req.intensity,
        "triggered_by": "EXHIBITION_SANDBOX_USER"
    })

    return {
        "success": True,
        "message": f"Attack '{req.attack_type}' successfully launched against {req.model_id}.",
        "attack_state": attack_state
    }

@app.post("/api/attacks/stop")
def stop_attack_simulation(model_id: str = Query(MODEL_FRAUD_ID)):
    """Stops the attack simulation on the target model."""
    attack_state = attack_simulator.stop_attack(model_id)
    return {
        "success": True,
        "message": f"Attack stopped on {model_id}.",
        "attack_state": attack_state
    }

# ----------------- AUDIT & INCIDENTS ENDPOINTS -----------------

@app.get("/api/incidents")
def get_incidents_log(limit: int = 25):
    """Retrieves all security incidents with bilingual explanations."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT id, timestamp, model_id, incident_type, severity, drift_score_psi,
           trust_score_at_event, english_alert, hindi_alert, shap_summary,
           leak_correlated, leak_details, action_taken
    FROM incidents
    ORDER BY id DESC
    LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    
    return [dict(r) for r in rows]

@app.get("/api/audit-trail")
def get_audit_trail_logs(limit: int = 40):
    """Retrieves immutable SHA-256 hash-chain records."""
    return get_audit_trail(limit)

@app.get("/api/audit-trail/verify")
def verify_audit_trail_endpoint():
    """Cryptographically verifies tamper-resistance across the entire hash chain."""
    is_valid, msg, count = verify_chain_integrity()
    return {
        "integrity_verified": is_valid,
        "total_blocks_checked": count,
        "status_message": msg
    }

# ----------------- THREAT INTEL ENDPOINTS -----------------

@app.get("/api/threat-intel")
def get_threat_intel_feed():
    """Simulated Dark Web breach feeds and compromised indicator lists."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT id, timestamp, leak_source, target_system, compromised_indicators_json, severity
    FROM threat_intel_leaks
    ORDER BY id DESC
    """)
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

# ----------------- SIMULATION & ONE-CLICK AUTO-DEMO -----------------

@app.post("/api/simulation/config")
def set_simulation_config(config: SimulationConfig):
    """Toggles background real-time traffic generation speed."""
    SIMULATION_STATE["is_running"] = config.is_running
    SIMULATION_STATE["interval_seconds"] = max(0.5, min(5.0, config.interval_seconds))
    return {"success": True, "state": SIMULATION_STATE}

@app.post("/api/demo/auto-run")
async def run_auto_exhibition_demo(background_tasks: BackgroundTasks):
    """
    Executes the seamless 7-step narrative automatically for exhibition judging!
    Step 1: Reset both models to Healthy (Trust 98%)
    Step 2: Launch Gradual Poisoning Attack on Model 1
    Step 3: Watch Drift spike & Trust score drop to Throttled range (Warning + Vernacular alert)
    Step 4: Honeypot & Dark web credential correlation trigger
    Step 5: Trust score drops < 50 -> Auto-Quarantine & Safe Checkpoint Rollback triggers
    Step 6: Dashboard shows 'Rolled back to safe checkpoint' & Hash-chain updated
    """
    async def execute_demo_story():
        SIMULATION_STATE["demo_auto_playing"] = True
        logger.info("=== AUTO EXHIBITION DEMO STORY STARTED ===")
        
        # Step 1: Clean Baseline
        for m in [MODEL_FRAUD_ID, MODEL_KYC_ID]:
            model_registry.get_model(m).manual_reset_to_healthy()
            attack_simulator.stop_attack(m)
        await asyncio.sleep(3.0)

        # Step 2: Launch Attack on Model 1
        attack_simulator.start_attack(MODEL_FRAUD_ID, "GRADUAL_POISONING", intensity=0.85)
        await asyncio.sleep(5.0)

        # Step 3: Inject Canary Honeypot Probe
        attack_simulator.start_attack(MODEL_FRAUD_ID, "ADVERSARIAL_CANARY_PROBING", intensity=0.95)
        await asyncio.sleep(6.0)

        # Model will naturally drop below 50, auto-quarantine, and rollback!
        await asyncio.sleep(4.0)
        attack_simulator.stop_attack(MODEL_FRAUD_ID)
        SIMULATION_STATE["demo_auto_playing"] = False
        logger.info("=== AUTO EXHIBITION DEMO STORY COMPLETED ===")

    background_tasks.add_task(execute_demo_story)
    return {"success": True, "message": "Auto Exhibition Demo story started. Watch the live dashboard!"}

# ----------------- STATIC UI SERVING -----------------
static_dir = BASE_DIR / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

@app.get("/")
def serve_index():
    index_file = BASE_DIR / "static" / "index.html"
    if index_file.exists():
        return FileResponse(str(index_file))
    return JSONResponse({"message": "Sentinel API active. Access /docs for API schema."})
