import time
import random
import logging
from typing import Dict, Any, Optional
from datetime import datetime, timezone

from backend.config import MODEL_FRAUD_ID, MODEL_KYC_ID
from backend.models.data_generator import generate_live_sample

logger = logging.getLogger("sentinel.simulator")

ATTACK_TYPES = {
    "GRADUAL_POISONING": {
        "name": "Gradual Decision Boundary Poisoning",
        "description": "Gradually injects skewed feedback distributions to silently shift the classifier decision boundary.",
        "default_intensity": 0.65
    },
    "STEALTH_BACKDOOR": {
        "name": "Stealth Trigger Backdoor Injection",
        "description": "Plants backdoor trigger combinations allowing fraudulent transactions to pass undetected.",
        "default_intensity": 0.80
    },
    "ADVERSARIAL_CANARY_PROBING": {
        "name": "Adversarial Perimeter Probing (Honeypot Trigger)",
        "description": "Sweeps input boundaries and triggers seeded canary honeypot signatures.",
        "default_intensity": 0.90
    },
    "COVARIATE_SHIFT_SURGE": {
        "name": "High-Velocity Covariate Distribution Shift",
        "description": "Rapidly surges key feature distributions, causing acute Population Stability Index (PSI) spikes.",
        "default_intensity": 0.75
    }
}

class AttackSimulator:
    def __init__(self):
        self.active_attacks: Dict[str, Dict[str, Any]] = {
            MODEL_FRAUD_ID: {
                "is_active": False,
                "attack_type": "GRADUAL_POISONING",
                "intensity": 0.65,
                "started_at": None,
                "injected_count": 0,
                "step": 0
            },
            MODEL_KYC_ID: {
                "is_active": False,
                "attack_type": "GRADUAL_POISONING",
                "intensity": 0.65,
                "started_at": None,
                "injected_count": 0,
                "step": 0
            }
        }

    def start_attack(self, model_id: str, attack_type: str = "GRADUAL_POISONING", intensity: float = 0.65) -> Dict[str, Any]:
        """Launches an attack on the specified target model."""
        if model_id not in self.active_attacks:
            model_id = MODEL_FRAUD_ID

        if attack_type not in ATTACK_TYPES:
            attack_type = "GRADUAL_POISONING"

        self.active_attacks[model_id] = {
            "is_active": True,
            "attack_type": attack_type,
            "attack_name": ATTACK_TYPES[attack_type]["name"],
            "intensity": min(1.0, max(0.1, float(intensity))),
            "started_at": datetime.now(timezone.utc).isoformat(),
            "injected_count": 0,
            "step": 0
        }
        logger.warning("ATTACK SIMULATION LAUNCHED on %s: %s (Intensity: %.2f)",
                       model_id, attack_type, intensity)
        return self.active_attacks[model_id]

    def stop_attack(self, model_id: str) -> Dict[str, Any]:
        """Stops the active attack on the specified model."""
        if model_id in self.active_attacks:
            self.active_attacks[model_id]["is_active"] = False
            self.active_attacks[model_id]["stopped_at"] = datetime.now(timezone.utc).isoformat()
        logger.info("Attack simulation stopped on %s.", model_id)
        return self.active_attacks.get(model_id, {})

    def is_attack_active(self, model_id: str) -> bool:
        return self.active_attacks.get(model_id, {}).get("is_active", False)

    def get_attack_status(self, model_id: str) -> Dict[str, Any]:
        return self.active_attacks.get(model_id, {})

    def generate_next_sample(self, model_id: str) -> Dict[str, Any]:
        """Generates the next live stream transaction (clean or poisoned)."""
        attack_info = self.active_attacks.get(model_id, {})
        is_active = attack_info.get("is_active", False)
        attack_type = attack_info.get("attack_type", "GRADUAL_POISONING")
        intensity = attack_info.get("intensity", 0.65)

        if not is_active:
            # 98% clean traffic, 2% organic noise
            return generate_live_sample(model_id, is_attack=False)

        attack_info["injected_count"] += 1
        attack_info["step"] += 1
        step = attack_info["step"]

        # Gradual progression: start subtler and ramp up
        progress_factor = min(1.0, 0.3 + (step / 15.0) * 0.7)
        effective_intensity = intensity * progress_factor

        if attack_type == "ADVERSARIAL_CANARY_PROBING":
            # 50% chance of injecting direct honeypot canary
            sample = generate_live_sample(model_id, is_attack=True, attack_intensity=effective_intensity)
            if model_id == MODEL_FRAUD_ID:
                sample["amount"] = 1337.42
                sample["foreign_ip_flag"] = 1
            else:
                sample["annual_income"] = 777777
                sample["inquiry_velocity_6m"] = 11
            return sample

        # Standard poisoned sample
        return generate_live_sample(model_id, is_attack=True, attack_intensity=effective_intensity)

# Singleton attack simulator instance
attack_simulator = AttackSimulator()
