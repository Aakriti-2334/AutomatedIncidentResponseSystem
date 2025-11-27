import pandas as pd
import time
import joblib

# -----------------------------
#  IMPORT MODELS
# -----------------------------
# Base ML models
log_reg_model      = joblib.load("models/log_reg.pkl")
svm_model          = joblib.load("models/svm.pkl")
rf_model           = joblib.load("models/random_forest.pkl")
mlp_model          = joblib.load("models/mlp.pkl")

# Ensemble/Confidence module
from ensemble import compute_ensemble_score

# Zero Trust Scoring Engine
from zero_trust_engine import zero_trust_score

# Mitigation modules
from mitigation import rate_limit, block_ip, quarantine_host

# Preprocessing
from preprocess import preprocess_features


# -----------------------------
#  LIVE DATA COLLECTION
# -----------------------------
def collect_live_csv(path="live_data/latest.csv"):
    """
    Reads the most recent CSV exported by your Traffic Aggregator.
    """
    return pd.read_csv(path)


# -----------------------------
#  BASE MODEL INFERENCE
# -----------------------------
def run_base_models(features):
    preds = {}

    preds["log_reg"] = log_reg_model.predict_proba(features)[:,1]
    preds["svm"]     = svm_model.predict_proba(features)[:,1]
    preds["rf"]      = rf_model.predict_proba(features)[:,1]
    preds["mlp"]     = mlp_model.predict_proba(features)[:,1]

    return preds


# -----------------------------
#  ZERO TRUST DECISION + MITIGATION
# -----------------------------
def mitigation_handler(zero_trust_score_val, row):
    """
    Applies your threshold logic.
    """
    if zero_trust_score_val < 0.30:
        print("⚠️ Malicious traffic detected → Blocking IP")
        block_ip(row["src_ip"])

    elif 0.30 <= zero_trust_score_val < 0.60:
        print("⚠️ Suspicious traffic → Rate-limiting")
        rate_limit(row["src_ip"])

    else:
        print("✅ Clean traffic → No mitigation action")


# -----------------------------
#  MAIN CONTROLLER LOOP
# -----------------------------
def controller_loop():
    print("AIRS Controller Running...")

    while True:
        try:
            # 1. Fetch incoming live traffic batch
            df = collect_live_csv()

            # 2. Preprocess
            features = preprocess_features(df)

            # 3. Base-model predictions
            base_preds = run_base_models(features)

            # 4. Ensemble confidence
            ensemble_scores = compute_ensemble_score(base_preds)

            # 5. Zero-Trust scoring
            zt_scores = zero_trust_score(df, ensemble_scores)

            # 6. Apply mitigation per row
            for idx, row in df.iterrows():
                mitigation_handler(zt_scores[idx], row)

        except Exception as e:
            print(f"[Error] {str(e)}")

        time.sleep(1)  # throttle loop


if __name__ == "__main__":
    controller_loop()
