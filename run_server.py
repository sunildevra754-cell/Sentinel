import os
import sys
import uvicorn
from pathlib import Path

# Add current project root to sys.path
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from backend.models.train_models import train_all_models
from backend.storage.database import init_db
from backend.config import CHECKPOINTS_DIR, MODEL_FRAUD_ID

def main():
    print("=" * 60)
    print("🛡️  SENTINEL — AI Model Integrity & Trust Layer")
    print("=" * 60)
    
    # 1. Initialize SQLite database
    print("[1/3] Initializing SQLite database and audit log...")
    init_db()

    # 2. Check if baseline models exist
    fraud_chk = CHECKPOINTS_DIR / f"{MODEL_FRAUD_ID}_clean_v1.joblib"
    if not fraud_chk.exists():
        print("[2/3] Training clean baseline classifiers (Fraud & KYC)...")
        train_all_models()
    else:
        print("[2/3] Verified model checkpoints loaded from storage.")

    # 3. Start FastAPI + Live Web Dashboard
    print("[3/3] Starting Sentinel Engine at http://127.0.0.1:8000 ...")
    print("\n👉 Open your browser at: http://127.0.0.1:8000")
    print("👉 Swagger API Docs available at: http://127.0.0.1:8000/docs")
    print("👉 For Streamlit app, run: streamlit run app_streamlit.py")
    print("=" * 60 + "\n")
    
    uvicorn.run("backend.app:app", host="127.0.0.1", port=8000, reload=False)

if __name__ == "__main__":
    main()
