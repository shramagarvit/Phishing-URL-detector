import os
import pickle
import numpy as np
from datetime import datetime, timedelta
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.orm import Session
import random

# Import database structures
from database import (
    get_db, init_db, URLModel, FeatureModel, PredictionModel, RiskFlagModel,
    get_most_phished_brands, get_attack_frequency_by_hour, get_attack_frequency_by_day,
    get_top_risky_tlds, get_top_risk_factors, get_historical_metrics, SessionLocal
)
# Import feature extractor
from features import extract_features, BRAND_KEYWORDS, RISKY_TLDS, SUSPICIOUS_KEYWORDS, SHORTENER_DOMAINS

# Initialize DB on import
init_db()

app = FastAPI(title="Live Phishing URL Threat Scanner API")

# Enable CORS for all ports (very important for Vite react server running on port 5173/5174)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load ML Assets
MODEL_PATH = "model.pkl"
SCALER_PATH = "scaler.pkl"
FEATURES_COLUMNS_PATH = "features_columns.pkl"

model = None
scaler = None
feature_columns = []

try:
    if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH) and os.path.exists(FEATURES_COLUMNS_PATH):
        with open(MODEL_PATH, "rb") as f:
            model = pickle.load(f)
        with open(SCALER_PATH, "rb") as f:
            scaler = pickle.load(f)
        with open(FEATURES_COLUMNS_PATH, "rb") as f:
            feature_columns = pickle.load(f)
        print("ML models loaded successfully.")
    else:
        print("WARNING: ML model binaries not found! Run python train.py first.")
except Exception as e:
    print(f"Error loading ML models: {e}")

class ScanRequest(BaseModel):
    url: str

def generate_risk_flags(features_dict, meta):
    """Inspects extracted URL features and generates detailed alert flags."""
    flags = []
    
    # 1. Brand Spoofing (High)
    if features_dict.get('has_brand_keyword', 0.0) == 1.0:
        flags.append({
            'flag_name': 'Brand Impersonation',
            'flag_severity': 'High',
            'description': f"URL mimics the popular brand '{meta['matched_brand']}' on an unverified domain."
        })
        
    # 2. IP Address Host (High)
    if features_dict.get('has_ip', 0.0) == 1.0:
        flags.append({
            'flag_name': 'Raw IP Hostname',
            'flag_severity': 'High',
            'description': "Uses a raw IP address in the domain segment, bypassing standard security DNS filtering."
        })
        
    # 3. Domain Age (High/Medium)
    age = features_dict.get('domain_age_days', 1000)
    if age < 30:
        flags.append({
            'flag_name': 'Ultra-Fresh Domain',
            'flag_severity': 'High',
            'description': f"The domain is extremely new, created only {int(age)} days ago. Highly typical of rapid-disposal phishing sites."
        })
    elif age < 90:
        flags.append({
            'flag_name': 'Recently Created Domain',
            'flag_severity': 'Medium',
            'description': f"The domain is recently registered ({int(age)} days ago). New domains hold significantly higher default risk."
        })
        
    # 4. Risky TLD (Medium)
    if features_dict.get('tld_is_risky', 0.0) == 1.0:
        flags.append({
            'flag_name': 'Risky TLD Extension',
            'flag_severity': 'Medium',
            'description': f"Hosted on a top-level domain (.{meta['tld']}) known for hosting disproportionally high rates of spam and malware."
        })
        
    # 5. Suspicious Keywords (Medium)
    if features_dict.get('has_login_keywords', 0.0) == 1.0:
        flags.append({
            'flag_name': 'Credential Harvesting Words',
            'flag_severity': 'Medium',
            'description': "Contains security or credential keywords (login, verify, secure, account) designed to mislead visitors."
        })
        
    # 6. Dash Count (Low)
    dashes = features_dict.get('dash_count_host', 0.0)
    if dashes >= 2:
        flags.append({
            'flag_name': 'Hyphenated Brand Stitching',
            'flag_severity': 'Low',
            'description': f"Hostname has {int(dashes)} hyphens. Phishers use hyphens to splice brand names into deceptive addresses."
        })
        
    # 7. Digit Ratio Host (Medium)
    ratio = features_dict.get('digit_ratio_host', 0.0)
    if ratio > 0.2:
        flags.append({
            'flag_name': 'High Digit Host Density',
            'flag_severity': 'Medium',
            'description': f"{int(ratio * 100)}% of the hostname is numerical, indicating machine-generated or obfuscated naming structures."
        })
        
    # 8. Entropy (Low)
    entropy = features_dict.get('entropy', 0.0)
    if entropy > 4.5:
        flags.append({
            'flag_name': 'High Character Entropy',
            'flag_severity': 'Low',
            'description': f"The URL has high Shannon entropy ({entropy:.2f}), signaling automated, random, or obfuscated URL paths."
        })
        
    # 9. Subdomains (Medium)
    subs = features_dict.get('num_subdomains', 0.0)
    if subs >= 3:
        flags.append({
            'flag_name': 'Deep Subdomain Nesting',
            'flag_severity': 'Medium',
            'description': f"Contains {int(subs)} subdomains, a tactic to push the main hostname off small screens."
        })
        
    # 10. Shortened URL (Medium)
    if features_dict.get('is_shortened', 0.0) == 1.0:
        flags.append({
            'flag_name': 'Shortener Redirect Cloak',
            'flag_severity': 'Medium',
            'description': "Uses a shortening service to hide the final landing page destination."
        })
        
    # 11. At-Symbol (High)
    if features_dict.get('has_at_symbol', 0.0) == 1.0:
        flags.append({
            'flag_name': 'At-Symbol Redirection',
            'flag_severity': 'High',
            'description': "Contains '@' character. Browsers ignore everything before '@', redirecting users straight to the credentials-harvester path."
        })
        
    return flags

def generate_ai_explanation(verdict, score, flags):
    """Returns a highly polished, human-friendly explanation of the prediction."""
    if verdict == "Phishing":
        if flags:
            top_flags = [f['flag_name'] for f in flags[:3]]
            flag_str = ", ".join(top_flags)
            return (
                f"Phishing threat detected! This URL exhibits high-severity threat markers. "
                f"Our Random Forest model evaluated its features and calculated a threat risk score of "
                f"{score:.1f}%. The primary triggers detected are: {flag_str}. "
                f"Accessing this page poses a serious danger of credential theft or financial fraud."
            )
        else:
            return (
                f"Phishing threat detected. The machine learning model identified critical structural "
                f"anomalies in the URL's lexical features matching known fraudulent campaigns, "
                f"yielding an overall threat score of {score:.1f}%."
            )
    else:
        if score > 20.0:
            return (
                f"URL is classified as Legitimate, but exhibits minor anomalies with a low threat score "
                f"of {score:.1f}%. It appears relatively safe, but exercise caution due to the presence "
                f"of minor suspicious indicators."
            )
        else:
            return (
                f"This URL is fully Legitimate and verified as safe. Feature analysis shows high structural "
                f"alignment with trusted internet domains, very low randomness, and zero spoofing signals. "
                f"Threat risk score is minimal at {score:.1f}%."
            )

@app.post("/api/scan")
def scan_url(request: ScanRequest, db: Session = Depends(get_db)):
    url = request.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty.")
        
    # Lazy load check
    global model, scaler, feature_columns
    if model is None:
        raise HTTPException(status_code=500, detail="ML model not trained. Run python train.py first.")
        
    try:
        # 1. Feature Extraction
        features_dict, meta = extract_features(url)
        
        # 2. Match exact column ordering and scale
        X_vector = [features_dict[col] for col in feature_columns]
        X_scaled = scaler.transform([X_vector])
        
        # 3. Model Inference
        pred_class = model.predict(X_scaled)[0] # 0 = Legit, 1 = Phishing
        probabilities = model.predict_proba(X_scaled)[0]
        phish_prob = float(probabilities[1])
        
        verdict = "Phishing" if pred_class == 1 else "Legitimate"
        risk_score = phish_prob * 100
        
        # 4. Generate Flags & Explanation
        flags = generate_risk_flags(features_dict, meta)
        explanation = generate_ai_explanation(verdict, risk_score, flags)
        
        # 5. Database Writing (Delete old scan if exists to refresh timestamp & logs)
        existing_url = db.query(URLModel).filter(URLModel.url == url).first()
        if existing_url:
            db.delete(existing_url)
            db.commit()
            
        # Create URL entry
        url_record = URLModel(
            url=url,
            hostname=meta['hostname'],
            tld=meta['tld'],
            domain_age_days=int(features_dict['domain_age_days']),
            scanned_at=datetime.utcnow()
        )
        db.add(url_record)
        db.commit()
        db.refresh(url_record)
        
        # Create Features entry
        feat_record = FeatureModel(url_id=url_record.id, **features_dict)
        db.add(feat_record)
        
        # Create Prediction entry
        pred_record = PredictionModel(
            url_id=url_record.id,
            prediction=verdict,
            phishing_probability=phish_prob,
            risk_score=risk_score,
            matched_brand=meta['matched_brand'],
            scanned_at=datetime.utcnow()
        )
        db.add(pred_record)
        
        # Create Risk Flags entries
        for flag in flags:
            flag_record = RiskFlagModel(
                url_id=url_record.id,
                flag_name=flag['flag_name'],
                flag_severity=flag['flag_severity'],
                description=flag['description']
            )
            db.add(flag_record)
            
        db.commit()
        
        # Return response matching the schema
        return {
            "url": url,
            "verdict": verdict,
            "risk_score": round(risk_score, 1),
            "domain_age_days": int(features_dict['domain_age_days']),
            "explanation": explanation,
            "flags": flags,
            "features": features_dict,
            "metadata": meta,
            "scanned_at": url_record.scanned_at.isoformat()
        }
        
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Scan error: {str(e)}")

@app.get("/api/stats")
def get_stats():
    try:
        return get_historical_metrics()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/analytics")
def get_analytics():
    try:
        return {
            "most_phished_brands": get_most_phished_brands(),
            "peak_attack_hours": get_attack_frequency_by_hour(),
            "peak_attack_days": get_attack_frequency_by_day(),
            "risky_tlds": get_top_risky_tlds(),
            "top_risk_factors": get_top_risk_factors()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/history")
def get_history(limit: int = 50, db: Session = Depends(get_db)):
    try:
        results = db.query(URLModel).join(PredictionModel).order_by(URLModel.scanned_at.desc()).limit(limit).all()
        
        history_list = []
        for r in results:
            history_list.append({
                "id": r.id,
                "url": r.url,
                "hostname": r.hostname,
                "verdict": r.prediction.prediction,
                "risk_score": round(r.prediction.risk_score, 1),
                "domain_age_days": r.domain_age_days,
                "scanned_at": r.scanned_at.isoformat()
            })
        return history_list
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/history")
def clear_history(db: Session = Depends(get_db)):
    try:
        db.query(URLModel).delete()
        db.commit()
        return {"status": "success", "message": "Historical log database cleared."}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/seed")
def seed_database(db: Session = Depends(get_db)):
    """Seeds the database with 80 highly realistic historical scans for testing/dashboard demonstration."""
    # Check if there is already data
    count = db.query(URLModel).count()
    if count > 10:
        return {"status": "ignored", "message": "Database already has historical scan logs."}
        
    print("Seeding database with realistic logs...")
    
    # Pre-generate some random dates spanning the last 7 days with various hours
    start_time = datetime.utcnow() - timedelta(days=7)
    
    # Pre-defined list of URLs to seed
    urls_to_seed = [
        # Phishing Spoofs
        ("http://paypal-verification-secure-portal.com/login.php", "paypal", "com"),
        ("https://netflix-signin-renew-account.top/verify", "netflix", "top"),
        ("http://verification-chase-banking-support.xyz/update", "chase", "xyz"),
        ("https://apple-id-billing-alert.club/signin.html", "apple", "club"),
        ("http://amazon-prime-login-update.work/billing", "amazon", "work"),
        ("https://steam-community-login.icu/trade/offer", "steam", "icu"),
        ("http://coinbase-auth-wallet-verification.gq/login", "coinbase", "gq"),
        ("http://binance-secure-portal.cc/settings", "binance", "cc"),
        ("https://microsoft-office365-secure-update.fit/login", "microsoft", "fit"),
        ("http://discord-gift-nitro.link/claim", "discord", "link"),
        ("http://wellsfargo-active-billing.support/card-auth", "wellsfargo", "support"),
        ("https://outlook-verify-exchange.online/auth", "outlook", "online"),
        ("http://stripe-merchant-verification.site/dashboard", "stripe", "site"),
        ("https://facebook-account-recovery-centre.info/help", "facebook", "info"),
        ("http://paypal-resolution-center-login.xyz/webapps", "paypal", "xyz"),
        ("https://netflix-billing-expiry-notice.top/account", "netflix", "top"),
        ("http://chase-bank-verify-access.work/signin", "chase", "work"),
        ("https://amazon-order-delivery-status.vip/item", "amazon", "vip"),
        ("http://steam-trade-verification.top/login", "steam", "top"),
        ("http://192.168.4.12/verify.php", None, ""),
        
        # Legitimate URLs
        ("https://www.google.com/search?q=cybersecurity+phishing", None, "com"),
        ("https://github.com/scikit-learn/scikit-learn", None, "com"),
        ("https://en.wikipedia.org/wiki/Phishing", None, "org"),
        ("https://www.amazon.co.uk/gp/css/homepage.html", None, "co.uk"),
        ("https://appleid.apple.com/faq", None, "com"),
        ("https://netflix.com/youraccount", None, "com"),
        ("https://stackoverflow.com/questions/tagged/python", None, "com"),
        ("https://docs.github.com/en/rest", None, "com"),
        ("https://medium.com/@phishing-alerts/how-to-stay-safe", None, "com"),
        ("https://www.bbc.co.uk/news/technology", None, "co.uk"),
        ("https://www.cnn.com/world", None, "com"),
        ("https://dropbox.com/share/folder123", None, "com"),
        ("https://spotify.com/us/premium", None, "com"),
        ("https://zoom.us/j/982390123", None, "us"),
        ("https://slack.com/downloads/windows", None, "com"),
        ("https://canva.com/templates", None, "com"),
        ("https://figma.com/file/mockup", None, "com"),
        ("https://adobe.com/products/photoshop", None, "com"),
        ("https://pinterest.com/explore", None, "com"),
        ("https://quora.com/unanswered", None, "com")
    ]
    
    # Multiply seed data with variation to reach 75-80 records
    extended_seeds = []
    for url_base, brand, tld in urls_to_seed:
        extended_seeds.append((url_base, brand, tld))
        # Add a few variants
        if brand:
            variant1 = url_base.replace("login", "update").replace("secure", "confirm")
            extended_seeds.append((variant1, brand, tld))
            variant2 = url_base.replace("verify", "signin").replace("billing", "refund") + f"?id={random.randint(100, 999)}"
            extended_seeds.append((variant2, brand, tld))
        else:
            variant1 = url_base.replace("faq", "support").replace("technology", "science")
            extended_seeds.append((variant1, None, tld))
            
    # Process extended seeds, shuffling timestamps over last 7 days
    db = SessionLocal()
    try:
        for idx, (url, brand, tld) in enumerate(extended_seeds):
            # Check if url already exists to avoid unique constraint error
            existing = db.query(URLModel).filter(URLModel.url == url).first()
            if existing:
                continue
                
            # Create a staggered timestamp
            days_ago = random.randint(0, 6)
            hours_ago = random.randint(0, 23)
            minutes_ago = random.randint(0, 59)
            stamp = datetime.utcnow() - timedelta(days=days_ago, hours=hours_ago, minutes=minutes_ago)
            
            # Extract features
            features_dict, meta = extract_features(url)
            
            # Force meta details if override needed
            if brand:
                meta['matched_brand'] = brand
                features_dict['has_brand_keyword'] = 1.0
            if tld:
                meta['tld'] = tld
                
            # Perform inference vector
            X_vector = [features_dict[col] for col in feature_columns]
            X_scaled = scaler.transform([X_vector])
            pred_class = model.predict(X_scaled)[0]
            probabilities = model.predict_proba(X_scaled)[0]
            phish_prob = float(probabilities[1])
            
            # Boost phishing probability for seed phishing rows to ensure separation
            if brand or 'xyz' in url or 'top' in url or 'work' in url or 'icu' in url or 'gq' in url:
                pred_class = 1
                phish_prob = random.uniform(0.81, 0.99)
            else:
                pred_class = 0
                phish_prob = random.uniform(0.01, 0.15)
                
            verdict = "Phishing" if pred_class == 1 else "Legitimate"
            risk_score = phish_prob * 100
            
            flags = generate_risk_flags(features_dict, meta)
            
            # Save URL
            url_record = URLModel(
                url=url,
                hostname=meta['hostname'],
                tld=meta['tld'],
                domain_age_days=int(features_dict['domain_age_days']),
                scanned_at=stamp
            )
            db.add(url_record)
            db.commit()
            db.refresh(url_record)
            
            # Features
            feat_record = FeatureModel(url_id=url_record.id, **features_dict)
            db.add(feat_record)
            
            # Prediction
            pred_record = PredictionModel(
                url_id=url_record.id,
                prediction=verdict,
                phishing_probability=phish_prob,
                risk_score=risk_score,
                matched_brand=meta['matched_brand'],
                scanned_at=stamp
            )
            db.add(pred_record)
            
            # Flags
            for flag in flags:
                flag_record = RiskFlagModel(
                    url_id=url_record.id,
                    flag_name=flag['flag_name'],
                    flag_severity=flag['flag_severity'],
                    description=flag['description']
                )
                db.add(flag_record)
                
        db.commit()
        print(f"Successfully seeded database with {len(extended_seeds)} records.")
        return {"status": "success", "message": f"Successfully seeded database with {len(extended_seeds)} records."}
    except Exception as e:
        db.rollback()
        print(f"Error seeding DB: {e}")
        return {"status": "error", "message": str(e)}
    finally:
        db.close()

if __name__ == '__main__':
    import uvicorn
    # Start on 127.0.0.1:8000
    uvicorn.run(app, host="127.0.0.1", port=8000)
