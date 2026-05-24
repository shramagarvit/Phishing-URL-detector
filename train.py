import os
import random
import pickle
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score

# Import feature extractor from features.py
from features import extract_features, BRAND_KEYWORDS, RISKY_TLDS, SUSPICIOUS_KEYWORDS, SHORTENER_DOMAINS

# Base lists for generating synthetic URLs
LEGITIMATE_DOMAINS = [
    'google.com', 'youtube.com', 'wikipedia.org', 'amazon.com', 'github.com', 
    'apple.com', 'microsoft.com', 'netflix.com', 'linkedin.com', 'stackoverflow.com',
    'reddit.com', 'medium.com', 'nytimes.com', 'bbc.co.uk', 'cnn.com', 'imdb.com',
    'dropbox.com', 'spotify.com', 'zoom.us', 'slack.com', 'trello.com', 
    'canva.com', 'figma.com', 'adobe.com', 'pinterest.com', 'quora.com',
    'salesforce.com', 'hubspot.com', 'mailchimp.com', 'shopify.com', 'wordpress.org',
    'w3schools.com', 'geeksforgeeks.org', 'coursera.org', 'udemy.com'
]

LEGITIMATE_PATHS = [
    '', '/', '/index.html', '/home', '/about', '/contact', '/privacy', 
    '/terms', '/pricing', '/faq', '/docs', '/blog', '/news', '/help', 
    '/wiki/Main_Page', '/search?q=machine+learning', '/profile/settings', 
    '/dashboard/main', '/products/item-12345', '/feed', '/explore',
    '/resources/api/v1/users', '/downloads/pdf/report2026.pdf', '/assets/js/app.js'
]

PHISHING_DOMAINS_SUFFIXES = [
    'security-check.com', 'verify-account.net', 'login-portal.org', 'secure-update.club',
    'billing-update.top', 'support-help.xyz', 'safety-service.work', 'recovery-portal.icu',
    'client-login.fit', 'account-validation.gq', 'online-banking.vip', 'webapps-login.cc',
    'verification-status.live', 'confirmation-code.support', 'reset-session.info',
    'access-control.online', 'identity-secure.site', 'server-update.run', 'database-repair.net'
]

def generate_legitimate_url():
    domain = random.choice(LEGITIMATE_DOMAINS)
    path = random.choice(LEGITIMATE_PATHS)
    protocol = random.choice(['https://', 'https://www.'])
    return f"{protocol}{domain}{path}"

def generate_phishing_url():
    protocol = random.choice(['http://', 'https://', 'http://www.'])
    
    # 1. Choose a target brand to spoof
    brand = random.choice(BRAND_KEYWORDS)
    
    # 2. Pick a phishing pattern
    pattern_type = random.randint(1, 5)
    
    hostname = ""
    if pattern_type == 1:
        # Concatenation: paypal-security-check.com
        suffix = random.choice(PHISHING_DOMAINS_SUFFIXES)
        hostname = f"{brand}-{suffix}"
    elif pattern_type == 2:
        # Double domain: brand.com.login-verification.xyz
        risky_tld = random.choice(RISKY_TLDS)
        hostname = f"{brand}.com.verify-{random.randint(100, 999)}.{risky_tld}"
    elif pattern_type == 3:
        # Subdomains: secure-login.brand.com-update.top
        risky_tld = random.choice(RISKY_TLDS)
        hostname = f"secure-login-{brand}.com-verify-account.{risky_tld}"
    elif pattern_type == 4:
        # IP address structure (highly suspicious)
        ip = f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
        hostname = ip
    else:
        # Shortened lookalike: bit.ly/brand-login
        shortener = random.choice(SHORTENER_DOMAINS)
        # Create it as a sub-domain or a path
        hostname = f"{brand}-login-portal.{random.choice(RISKY_TLDS)}"

    # Generate path with suspicious keywords
    path_keywords = random.sample(SUSPICIOUS_KEYWORDS, random.randint(1, 3))
    path_str = "/" + "-".join(path_keywords)
    if random.choice([True, False]):
        path_str += random.choice(['.php', '.html', '/secure', '/login'])
        
    # Generate long numeric query strings
    query_str = ""
    if random.choice([True, False]):
        query_str = f"?id={random.randint(100000, 999999)}&token=" + "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=15))
        
    return f"{protocol}{hostname}{path_str}{query_str}"

def prepare_dataset(size=5000):
    print(f"Generating {size} URLs for ML dataset training...")
    half_size = size // 2
    
    urls = []
    labels = []
    
    # Generate legitimate
    for _ in range(half_size):
        urls.append(generate_legitimate_url())
        labels.append(0) # 0 for Legitimate
        
    # Generate phishing
    for _ in range(half_size):
        urls.append(generate_phishing_url())
        labels.append(1) # 1 for Phishing
        
    # Convert to features
    print("Extracting features from generated URLs...")
    feature_list = []
    for i, url in enumerate(urls):
        if (i + 1) % 1000 == 0:
            print(f"Processed {i+1}/{size} URLs...")
        feats, _ = extract_features(url)
        feature_list.append(feats)
        
    df = pd.DataFrame(feature_list)
    df['label'] = labels
    df['url'] = urls
    
    return df

def train_model():
    print("Initializing Phishing Detector ML Pipeline...")
    
    # 1. Generate or load data
    df = prepare_dataset(5000)
    
    # 2. Extract features and target
    X = df.drop(columns=['label', 'url'])
    y = df['label']
    
    # 3. Train Test Split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    # Save the order of features to ensure API inference extracts them in the identical order!
    feature_cols = list(X.columns)
    print(f"Features list ({len(feature_cols)} dimensions): {feature_cols}")
    
    # 4. Standard Scaler
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # 5. Random Forest Training
    print("Training Random Forest Classifier...")
    model = RandomForestClassifier(
        n_estimators=150, 
        max_depth=16, 
        min_samples_split=4, 
        min_samples_leaf=2, 
        random_state=42, 
        n_jobs=-1
    )
    model.fit(X_train_scaled, y_train)
    
    # 6. Evaluation
    y_pred = model.predict(X_test_scaled)
    acc = accuracy_score(y_test, y_pred)
    print(f"\n==========================================")
    print(f"Model Training Summary")
    print(f"==========================================")
    print(f"Validation Accuracy: {acc * 100:.2f}%")
    print(f"\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
    
    # Feature Importance Analysis
    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1]
    print("\nTop 10 Most Predictive Features:")
    for f in range(10):
        print(f"{f + 1}. {feature_cols[indices[f]]}: {importances[indices[f]]:.4f}")
    print(f"==========================================\n")
    
    # 7. Save model, scaler and feature column order to workspace files
    print("Serializing ML artifacts (model.pkl, scaler.pkl)...")
    with open('model.pkl', 'wb') as f:
        pickle.dump(model, f)
        
    with open('scaler.pkl', 'wb') as f:
        pickle.dump(scaler, f)
        
    with open('features_columns.pkl', 'wb') as f:
        pickle.dump(feature_cols, f)
        
    print("ML pipeline training successfully completed! Assets saved.")

if __name__ == '__main__':
    train_model()
