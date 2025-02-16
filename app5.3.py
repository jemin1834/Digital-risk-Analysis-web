import streamlit as st
import pandas as pd
import requests
import re
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import pickle

# Load dataset
data_file = "merged_security_data.csv"
df = pd.read_csv(data_file)

# Load pre-trained phishing model
def load_model():
    with open("phishing_model.pkl", "rb") as f:
        return pickle.load(f)

# Extract features from URL
def extract_features(url):
    parsed_url = urlparse(url)
    url_length = len(url)
    https = 1 if parsed_url.scheme == "https" else 0
    num_subdomains = len(parsed_url.netloc.split(".")) - 1
    ip_address = 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", parsed_url.netloc) else 0
    features = [ip_address, url_length, https, num_subdomains]
    vulnerabilities = []
    
    if url_length > 75:
        vulnerabilities.append("🔗 Long URL detected (might be obfuscated)")
    if https == 0:
        vulnerabilities.append("🚨 Non-secure URL (HTTP detected)")
    
    return features, vulnerabilities

# Detect SQL Injection patterns
def detect_sql_injection(url):
    sql_patterns = ["' OR 1=1 --", "' OR 'a'='a", "' UNION SELECT", "admin' --", "' DROP TABLE", "' SELECT * FROM users"]
    for pattern in sql_patterns:
        if pattern.lower() in url.lower():
            return True, "⚠️ Possible SQL Injection detected!"
    return False, "✅ No SQL Injection patterns found."

# Check against OWASP Top 10 security risks
def check_owasp_top_10(url):
    risks = []
    if "javascript:" in url.lower():
        risks.append("⚠️ Potential XSS (Cross-Site Scripting) attack detected!")
    if any(keyword in url.lower() for keyword in ["wp-admin", "admin-login", "user=", "pass="]):
        risks.append("⚠️ Possible Broken Authentication detected!")
    if "file://" in url.lower() or "../" in url.lower():
        risks.append("⚠️ Path Traversal detected!")
    return risks if risks else ["✅ No OWASP Top 10 vulnerabilities detected!"]

# Check if URL matches known vulnerabilities
def check_known_vulnerabilities(url):
    matched = df[df['url'].str.contains(url, case=False, na=False)]
    if not matched.empty:
        return [f"⚠️ Known Vulnerability Found: {row['vulnerability']}" for _, row in matched.iterrows()]
    return ["✅ No known vulnerabilities detected!"]

# Predict if URL is phishing
def predict_url(url, model):
    features, vulnerabilities = extract_features(url)
    prediction = model.predict([features])
    sql_injection, sql_message = detect_sql_injection(url)
    owasp_risks = check_owasp_top_10(url)
    known_vulns = check_known_vulnerabilities(url)
    
    return {
        'Phishing Prediction': '🛑 Phishing' if prediction[0] == 1 else '✅ Legitimate',
        'Vulnerabilities': vulnerabilities,
        'SQL Injection': sql_message,
        'OWASP Risks': owasp_risks,
        'Known Vulnerabilities': known_vulns
    }

# Streamlit UI
st.set_page_config(page_title="Phishing & Security Risk Detector", page_icon="🔍")
st.title("🔍 Phishing & Security Risk Detector")
url_input = st.text_input("Enter URL:", placeholder="https://example.com")

if st.button("Check URL"):
    if url_input:
        model = load_model()
        result = predict_url(url_input, model)
        
        st.subheader("Prediction Result:")
        st.success(f"Phishing Prediction: {result['Phishing Prediction']}")
        st.info(f"SQL Injection: {result['SQL Injection']}")
        
        if result['Vulnerabilities']:
            st.warning("⚠️ Detected Vulnerabilities:")
            for v in result['Vulnerabilities']:
                st.warning(v)
        
        if result['OWASP Risks']:
            st.warning("⚠️ OWASP Top 10 Risks:")
            for risk in result['OWASP Risks']:
                st.warning(risk)
        
        if result['Known Vulnerabilities']:
            st.warning("⚠️ Known Vulnerabilities:")
            for vuln in result['Known Vulnerabilities']:
                st.warning(vuln)
    else:
        st.error("Please enter a valid URL.")
