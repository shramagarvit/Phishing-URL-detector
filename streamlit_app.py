import streamlit as st
import pickle
import os
import numpy as np
import pandas as pd
from features import extract_features

# Set Page Config with dark mode and styling considerations
st.set_page_config(
    page_title="AegisThreat AI — Phishing URL Scanner",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="collapsed"
)

# Custom Styling for premium aesthetics
st.markdown("""
<style>
    .main {
        background-color: #0d1117;
        color: #c9d1d9;
    }
    h1, h2, h3 {
        color: #58a6ff !important;
        font-family: 'Outfit', sans-serif;
    }
    .stTextInput>div>div>input {
        background-color: #161b22;
        color: #ffffff;
        border: 1px solid #30363d;
        border-radius: 8px;
    }
    .stButton>button {
        background: linear-gradient(135deg, #1f6feb 0%, #094cb5 100%);
        color: white;
        border: none;
        border-radius: 8px;
        padding: 8px 24px;
        font-weight: bold;
        transition: transform 0.2s ease-in-out;
    }
    .stButton>button:hover {
        transform: scale(1.02);
        color: #ffffff;
    }
    .flag-card {
        padding: 15px;
        border-radius: 8px;
        background-color: #161b22;
        border-left: 5px solid #d29922;
        margin-bottom: 10px;
    }
    .flag-high {
        border-left-color: #f85149;
    }
    .flag-medium {
        border-left-color: #d29922;
    }
    .flag-low {
        border-left-color: #388bfd;
    }
</style>
""", unsafe_allow_html=True)

# Application Header
st.title("🛡️ AegisThreat AI")
st.subheader("Live Phishing URL Threat Scanner & Diagnostics")
st.markdown("---")

# Model Loader
@st.cache_resource
def load_ml_pipeline():
    MODEL_PATH = "model.pkl"
    SCALER_PATH = "scaler.pkl"
    FEATURES_COLUMNS_PATH = "features_columns.pkl"
    
    if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH) and os.path.exists(FEATURES_COLUMNS_PATH):
        with open(MODEL_PATH, "rb") as f:
            model = pickle.load(f)
        with open(SCALER_PATH, "rb") as f:
            scaler = pickle.load(f)
        with open(FEATURES_COLUMNS_PATH, "rb") as f:
            feature_columns = pickle.load(f)
        return model, scaler, feature_columns
    return None, None, None

model, scaler, feature_columns = load_ml_pipeline()

if model is None:
    st.error("⚠️ Machine learning models are not found! Please make sure 'model.pkl', 'scaler.pkl', and 'features_columns.pkl' are committed to the repository.")
else:
    # URL Scanner Console
    st.write("### 💻 Real-Time URL Analysis Panel")
    url_input = st.text_input("Enter URL Target Address:", placeholder="e.g., https://paypal-resolution-center-login.xyz")

    if st.button("EXECUTE SCATTER ANALYSIS 🚀", use_container_width=True):
        if not url_input.strip():
            st.warning("Please enter a valid URL to analyze.")
        else:
            with st.spinner("Analyzing lexical structures, checking brand keywords, and predicting threat vectors..."):
                try:
                    # 1. Feature Extraction
                    features_dict, meta = extract_features(url_input)
                    
                    # 2. Vectorize & Scale
                    X_vector = [features_dict[col] for col in feature_columns]
                    X_scaled = scaler.transform([X_vector])
                    
                    # 3. Model Inference
                    pred_class = model.predict(X_scaled)[0] # 0 = Legit, 1 = Phishing
                    probabilities = model.predict_proba(X_scaled)[0]
                    phish_prob = float(probabilities[1])
                    
                    verdict = "Phishing" if pred_class == 1 else "Legitimate"
                    risk_score = phish_prob * 100
                    
                    st.markdown("---")
                    st.write("### 📊 Classification Summary")
                    
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        if verdict == "Phishing":
                            st.metric(label="Verdict Status", value="🚨 PHISHING", delta="- Dangerous", delta_color="inverse")
                        else:
                            st.metric(label="Verdict Status", value="✅ SECURE", delta="Legitimate")
                            
                    with col2:
                        st.metric(label="Threat Risk Score", value=f"{risk_score:.1f}%")
                        
                    with col3:
                        st.metric(label="Estimated Domain Age", value=f"{int(features_dict['domain_age_days'])} Days")
                        
                    # Explanation Banner
                    if verdict == "Phishing":
                        st.error(
                            f"**Threat Warning:** This URL is flagged as **Phishing** with a {risk_score:.1f}% confidence. "
                            f"It resembles brand spoofing target: **{meta['matched_brand'] or 'None'}** on an unverified domain."
                        )
                    else:
                        st.success(
                            f"**Verification:** This URL is flagged as **Legitimate** and verified safe. "
                            f"Lexical analysis yields a low threat risk score of {risk_score:.1f}%."
                        )
                        
                    # Diagnostics Details
                    with st.expander("🛠️ Advanced Diagnostics & Extracted Features"):
                        st.write("Below are the 33 extracted features fed into the Random Forest Classifier:")
                        df_feats = pd.DataFrame([features_dict]).T.rename(columns={0: "Feature Value"})
                        st.dataframe(df_feats, use_container_width=True)
                        
                        st.write("#### Lexical Meta Context:")
                        st.json(meta)
                        
                except Exception as ex:
                    st.error(f"Analysis engine interrupted: {str(ex)}")

st.markdown("---")
st.markdown("<p style='text-align: center; color: #8b949e; font-size: 11px;'>© 2026 AegisThreat AI. ALL RIGHTS SECURED.</p>", unsafe_allow_html=True)
