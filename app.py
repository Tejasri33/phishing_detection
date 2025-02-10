from flask import Flask, request, jsonify
from flask_cors import CORS  # Import CORS
import pandas as pd
import joblib
from urllib.parse import urlparse
import tldextract
import re
import whois
import datetime
import socket
import ssl
import os  # Import os for PORT handling

app = Flask(__name__)
CORS(app)  # Enable CORS for all requests

# Load the trained phishing detection model
model = joblib.load("phishing_model.pkl")

# Function to extract features from a given URL
def extract_features(url):
    features = {}
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    ext = tldextract.extract(domain)

    # URL Features
    features["length_url"] = len(url)
    features["length_hostname"] = len(domain)
    features["nb_dots"] = domain.count(".")
    features["nb_hyphens"] = domain.count("-")
    features["nb_at"] = url.count("@")
    features["nb_qm"] = url.count("?")
    features["nb_and"] = url.count("&")
    features["nb_or"] = url.count("|")
    features["nb_eq"] = url.count("=")
    features["nb_slash"] = url.count("/")
    features["nb_www"] = url.count("www")
    features["nb_com"] = url.count(".com")

    # SSL Certificate Check
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as secure_sock:
                cert = secure_sock.getpeercert()
                issuer = dict(x[0] for x in cert['issuer'])
                features["valid_ssl"] = True
                features["trusted_issuer"] = "Let's Encrypt" in issuer.get("organizationName", "")
    except:
        features["valid_ssl"] = False
        features["trusted_issuer"] = False

    # WHOIS Data (Domain Age)
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date if domain_info.creation_date else datetime.datetime.now()
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        features["domain_age"] = (datetime.datetime.now() - creation_date).days
        features["is_new_domain"] = features["domain_age"] < 180
    except:
        features["domain_age"] = 0
        features["is_new_domain"] = True

    # Phishing Keywords
    features["phish_hints"] = bool(re.search(r"(verify|account|secure|login|bank)", url, re.IGNORECASE))

    return features

# API Endpoint to check phishing
@app.route("/check", methods=["POST"])
def check_phishing():
    data = request.json
    url = data.get("url")

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    features = extract_features(url)
    df_features = pd.DataFrame([features])
    prediction = model.predict(df_features)[0]
    result = "Phishing" if prediction == 1 else "Legitimate"

    return jsonify({"url": url, "result": result})

# Home Route (To Check If API is Running)
@app.route("/", methods=["GET"])
def home():
    return jsonify({"message": "Phishing Detection API is running!"})

# Run Flask App
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))  # Use Render-assigned port
    app.run(host="0.0.0.0", port=port, debug=True)
