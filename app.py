import base64
import os
import sys
import joblib
import pandas as pd
import requests
import streamlit as st
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.sequence import pad_sequences

# Ensure project root is in Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from src.extractor import extract_lexical_features, get_live_cyberops_iocs

# Page configuration
st.set_page_config(
    page_title="Real-Time Phishing & Malicious URL Analyzer",
    page_icon="🛡️",
    layout="wide",
)


@st.cache_resource
def load_ai_models():
    xgb = joblib.load("models/xgb_model.pkl")
    cnn = load_model("models/dl_cnn_model.keras")
    tokenizer = joblib.load("models/char_tokenizer.pkl")
    return xgb, cnn, tokenizer


def analyze_email_social_engineering(email_text: str) -> dict:
    """Detect social engineering urgency & deception cues in email text."""
    if not email_text.strip():
        return {"score": 0.0, "matched_words": []}

    cues = [
        "urgent", "immediately", "verify", "suspended", "unauthorized",
        "password", "click below", "confirm your account", "security alert",
        "limited time", "update your payment", "won", "prize", "locked",
    ]
    text_lower = email_text.lower()
    matched = [word for word in cues if word in text_lower]
    exclamations = email_text.count("!")
    raw_score = min((len(matched) * 0.22) + (exclamations * 0.05), 1.0)
    return {"score": round(raw_score, 2), "matched_words": matched}


def query_virustotal(url: str, api_key: str) -> dict:
    """Check URL reputation against VirusTotal v3 API."""
    if not api_key:
        return {"status": "no_key"}
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": api_key.strip()}
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=10,
        )
        if resp.status_code == 200:
            stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
            return {
                "status": "ok",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "total": sum(stats.values()),
            }
        elif resp.status_code == 404:
            return {"status": "not_found"}
        else:
            return {"status": "error", "code": resp.status_code}
    except Exception as e:
        return {"status": "error", "msg": str(e)}


# Load trained models
try:
    xgb_model, cnn_model, char_tokenizer = load_ai_models()
except Exception as e:
    st.error(f"Error loading models from models/ folder: {e}")
    st.stop()

# Sidebar for Threat Intel API Key
with st.sidebar:
    st.header("Threat Intelligence Settings")
    vt_api_key = st.text_input(
        "VirusTotal API Key (Optional)",
        type="password",
        help="Get a free API key from virustotal.com",
    )
    st.markdown("---")
    st.markdown("**System Architecture:**")
    st.markdown("- **ML Track:** XGBoost (16 Lexical & Entropy IoCs)")
    st.markdown("- **DL Track:** 1D-CNN (Character-Level Sequence)")
    st.markdown("- **CyberOps:** Live WHOIS + SSL + VirusTotal")

# Main Dashboard UI
st.title("Real-Time Phishing & Malicious URL Analyzer")
st.markdown("Hybrid **Machine Learning + Deep Learning + CyberOps Threat Intelligence** Engine")

col_in1, col_in2 = st.columns([1.2, 1])
with col_in1:
    target_url = st.text_input(
        "Enter Target URL to Analyze:",
        placeholder="https://example.com/login",
    )
with col_in2:
    email_body = st.text_area(
        "Paste Accompanying Email Text (Optional - NLP Check):",
        height=100,
        placeholder="Urgent: Your account has been suspended. Click here to verify...",
    )

if st.button("Analyze Threat", type="primary"):
    if not target_url.strip():
        st.warning("Please enter a URL first.")
    else:
        url_clean = target_url.strip()
        if not url_clean.startswith(("http://", "https://")):
            url_clean = "http://" + url_clean

        with st.spinner("Running Hybrid AI Models & Live CyberOps Checks..."):
            # 1. ML Prediction (XGBoost)
            lex_features = extract_lexical_features(url_clean)
            df_lex = pd.DataFrame([lex_features])
            p_ml = float(xgb_model.predict_proba(df_lex)[0][1])

            # 2. DL Prediction (1D-CNN)
            seq = char_tokenizer.texts_to_sequences([url_clean])
            padded_seq = pad_sequences(seq, maxlen=150, padding="post", truncating="post")
            p_dl = float(cnn_model.predict(padded_seq, verbose=0)[0][0])

            # 3. Email NLP Score
            nlp_res = analyze_email_social_engineering(email_body)

            # 4. Base AI Score
            if email_body.strip():
                ai_score = (0.4 * p_ml) + (0.4 * p_dl) + (0.2 * nlp_res["score"])
            else:
                ai_score = (0.5 * p_ml) + (0.5 * p_dl)

            # 5. Live CyberOps IoCs (WHOIS & SSL)
            live_iocs = get_live_cyberops_iocs(url_clean)

            # 6. VirusTotal Check
            vt_res = query_virustotal(url_clean, vt_api_key)

            # 7. CyberOps Trust Calibration (Reduces False Positives on Established Domains)
            hybrid_score = ai_score
            age = live_iocs["domain_age_days"]
            ssl_ok = live_iocs["ssl_valid"]
            calibrated_note = ""

            if age >= 1825 and ssl_ok:  # Established domain (> 5 years) with valid SSL
                hybrid_score = ai_score * 0.25
                calibrated_note = "CyberOps Trust Calibration applied: Established domain (>5 years) + Valid SSL reduced false-positive lexical risk."
            elif age >= 365 and ssl_ok:  # Mature domain (> 1 year) with valid SSL
                hybrid_score = ai_score * 0.50
                calibrated_note = "CyberOps Trust Calibration applied: Mature domain (>1 year) + Valid SSL calibrated risk score."

            # Override if VirusTotal confirms active malicious detections
            if vt_res.get("status") == "ok" and vt_res.get("malicious", 0) >= 2:
                hybrid_score = max(hybrid_score, 0.85)
                calibrated_note = "Threat Intel Override: Multiple VirusTotal engines flagged this URL as malicious."

        st.markdown("---")
        # Verdict Banner
        if hybrid_score >= 0.70:
            st.error(f"HIGH RISK — MALICIOUS / PHISHING DETECTED (Threat Score: {hybrid_score * 100:.1f}%)")
        elif hybrid_score >= 0.40:
            st.warning(f"SUSPICIOUS — PROCEED WITH CAUTION (Threat Score: {hybrid_score * 100:.1f}%)")
        else:
            st.success(f"SAFE — BENIGN URL (Threat Score: {hybrid_score * 100:.1f}%)")

        if calibrated_note:
            st.caption(calibrated_note)

        # Metrics Row
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("XGBoost (ML) Risk", f"{p_ml * 100:.1f}%")
        m2.metric("1D-CNN (DL) Risk", f"{p_dl * 100:.1f}%")
        m3.metric(
            "Domain Age (WHOIS)",
            f"{live_iocs['domain_age_days']} days" if live_iocs["domain_age_days"] >= 0 else "Hidden / N/A",
        )
        m4.metric(
            "SSL Certificate",
            f"Valid ({live_iocs['ssl_issuer']})" if live_iocs["ssl_valid"] else "Invalid / None",
        )

        # VirusTotal & NLP Details
        c1, c2 = st.columns(2)
        with c1:
            st.subheader("VirusTotal Threat Intelligence")
            if vt_res["status"] == "no_key":
                st.info("Enter your free VirusTotal API Key in the left sidebar to compare against 90+ security vendors.")
            elif vt_res["status"] == "ok":
                st.write(f"**Malicious Detections:** {vt_res['malicious']} / {vt_res['total']} engines")
                st.write(f"**Suspicious Detections:** {vt_res['suspicious']}")
                if hybrid_score >= 0.70 and vt_res["malicious"] == 0:
                    st.warning("Zero-Day Alert: AI flagged this URL before VirusTotal engines listed it!")
            elif vt_res["status"] == "not_found":
                st.warning("URL not yet indexed in VirusTotal database (Potential Zero-Day).")
            else:
                st.error("Could not fetch VirusTotal report.")

        with c2:
            st.subheader("Extracted Lexical & NLP Indicators (IoCs)")
            st.write(f"**URL Entropy:** `{lex_features['url_entropy']}` | **Hostname Entropy:** `{lex_features['hostname_entropy']}`")
            st.write(f"**URL Length:** `{lex_features['url_length']}` chars | **Dots:** `{lex_features['count_dots']}` | **Hyphens:** `{lex_features['count_hyphens']}`")
            if email_body.strip():
                st.write(f"**Email Social Engineering Risk:** `{nlp_res['score'] * 100:.0f}%` — Matched Cues: `{nlp_res['matched_words']}`")
