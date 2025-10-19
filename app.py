# app.py
from flask import Flask, request, render_template, send_from_directory
import joblib
import os
import re
import numpy as np
import pandas as pd
from urllib.parse import urlparse
from sklearn.exceptions import NotFittedError
import warnings

# ----------------- SUPPRESS XGBOOST WARNINGS -----------------
warnings.filterwarnings("ignore", category=UserWarning, module="xgboost")
# ----------------- CONFIG -----------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, "models")

# expected model filenames (change if needed)
XSS_MODEL_FILE = os.path.join(MODELS_DIR, "xss_model.pkl")
XSS_VECTORIZER_FILE = os.path.join(MODELS_DIR, "xss_vectorizer.pkl")

URL_XGB_MODEL_FILE = os.path.join(MODELS_DIR, "xgboost_gpu_model.pkl")
URL_RF_MODEL_FILE = os.path.join(MODELS_DIR, "random_forest_gpu_model.pkl")
LABEL_ENCODER_FILE = os.path.join(MODELS_DIR, "label_encoder.pkl")

# Trusted domains used for false-positive correction
TRUSTED_DOMAINS = [
    'google.com', 'youtube.com', 'microsoft.com', 'apple.com',
    'amazon.com', 'wikipedia.org', 'facebook.com', 'instagram.com',
    'linkedin.com', 'yahoo.com'
]

# ----------------- FLASK APP -----------------
app = Flask(__name__, template_folder="templates")

# ----------------- LOAD XSS -----------------
xss_model = None
xss_vectorizer = None
try:
    if os.path.exists(XSS_MODEL_FILE):
        xss_model = joblib.load(XSS_MODEL_FILE)
    if os.path.exists(XSS_VECTORIZER_FILE):
        xss_vectorizer = joblib.load(XSS_VECTORIZER_FILE)
    print("✅ XSS model/vectorizer load attempt finished")
except Exception as e:
    print("❌ Error loading XSS model/vectorizer:", e)

# ----------------- LOAD URL MODELS/ENCODER -----------------
url_model = None
url_rf_model = None
label_encoder = None
# Prefer XGBoost model (if present). If not, try RF.
try:
    if os.path.exists(URL_XGB_MODEL_FILE):
        url_model = joblib.load(URL_XGB_MODEL_FILE)
        print("✅ Loaded XGBoost URL model")
    elif os.path.exists(URL_RF_MODEL_FILE):
        url_model = joblib.load(URL_RF_MODEL_FILE)
        print("✅ Loaded RandomForest URL model")
    else:
        print("⚠️ No URL model .pkl found in models/ (expected xgboost_gpu_model.pkl or random_forest_gpu_model.pkl)")

    if os.path.exists(LABEL_ENCODER_FILE):
        label_encoder = joblib.load(LABEL_ENCODER_FILE)
        print("✅ Loaded label encoder")
    else:
        print("⚠️ No label_encoder.pkl found. Will use fallback labels.")
except Exception as e:
    print("❌ Error loading URL model/encoder:", e)

# ----------------- URL feature helpers (same logic as training) -----------------
def calculate_entropy(s: str) -> float:
    if not s:
        return 0.0
    probs = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * np.log2(p) for p in probs if p > 0)

def extract_url_features_list(urls):
    feats = []
    for url in urls:
        p = urlparse(url)
        feats.append({
            "length": len(url),
            "num_dots": url.count('.'),
            "num_hyphens": url.count('-'),
            "num_digits": sum(c.isdigit() for c in url),
            "num_slashes": url.count('/'),
            "entropy": calculate_entropy(url),
            "has_ip": int(bool(re.search(r'\d+\.\d+\.\d+\.\d+', url))),
            "suspicious_tld": int(any(t in url.lower() for t in ['.tk','.ml','.ga','.cf','.cc','.pw'])),
            "phish_keywords": sum(k in url.lower() for k in
                                  ['secure','account','update','bank','paypal','login','verify']),
            "domain_len": len(p.netloc),
            "path_len": len(p.path),
        })
    return pd.DataFrame(feats)

def safe_label_from_prediction(pred_int):
    # Try to use loaded label encoder; otherwise fallback
    if label_encoder is not None:
        try:
            lab = label_encoder.inverse_transform([pred_int])[0]
            return lab
        except Exception:
            pass
    # fallback mapping used in training: 0 -> 'safe', 1 -> 'not_safe'
    return 'not_safe' if int(pred_int) == 1 else 'safe'

# ----------------- common helper to format result -----------------
def get_result(prediction, user_input):
    css_class = "safe"
    if "Attack" in prediction or "Malicious" in prediction or "not_safe" in prediction:
        css_class = "danger"
    elif "error" in prediction.lower() or "not loaded" in prediction.lower():
        css_class = "error"
    elif "No" in prediction and "provided" in prediction:
        css_class = "warning"
    return {"prediction": prediction, "user_input": user_input, "css_class": css_class}

# ----------------- ROUTES -----------------
@app.route("/", methods=["GET"])
def home():
    return render_template("index.html", url_result=None, xss_result=None)

@app.route("/predict_xss", methods=["POST"])
def predict_xss():
    user_input = request.form.get("xss_input", "").strip()
    if not user_input:
        prediction_text = "No XSS input provided."
    elif xss_model is None or xss_vectorizer is None:
        prediction_text = "XSS model not loaded."
    else:
        try:
            vect = xss_vectorizer.transform([user_input])
            pred = xss_model.predict(vect)[0]
            prediction_text = "XSS Attack Detected!" if int(pred) == 1 else "Safe Input"
        except NotFittedError:
            prediction_text = "XSS vectorizer is not fitted. Retrain and save it properly."
        except Exception as e:
            prediction_text = f"XSS Prediction error: {str(e)}"

    result = get_result(prediction_text, user_input)
    return render_template("index.html", xss_result=result, url_result=None)

@app.route("/predict_url", methods=["POST"])
def predict_url():
    user_input = request.form.get("url_input", "").strip()
    if not user_input:
        prediction_text = "No URL provided."

    # ---------------- Quick HTTPS/HTTP check ----------------
    elif user_input.startswith("https://"):
        prediction_text = "✅ Safe (HTTPS detected)"
    elif user_input.startswith("http://"):
        prediction_text = "⚠️ Potentially Unsafe (HTTP detected)"

    elif url_model is None:
        prediction_text = "URL model not loaded."
    else:
        try:
            # Build features identical to training
            feats = extract_url_features_list([user_input])
            # Models saved with joblib usually expect numpy / pandas inputs used at training.
            # XGBoost accepts pandas DataFrame / numpy array for predict_proba/predict.
            pred_int = None
            # if model has predict_proba (XGBoost), use threshold 0.4 as in training
            if hasattr(url_model, "predict_proba"):
                proba = url_model.predict_proba(feats)[:, 1]
                pred_int = int((proba[0] > 0.4).astype(int))
            else:
                # try direct predict
                raw = url_model.predict(feats)
                # raw could be array-like with ints
                pred_int = int(np.asarray(raw)[0])

            label = safe_label_from_prediction(pred_int)

            # False Positive Correction for trusted domains
            corrected = False
            if label == 'not_safe':
                for domain in TRUSTED_DOMAINS:
                    if domain in user_input.lower():
                        corrected = True
                        label = 'safe'
                        break
            if corrected:
                prediction_text = f"False Positive corrected → {label}"
            else:
                prediction_text = "Malicious URL Detected!" if label == 'not_safe' else "Safe URL"

        except NotFittedError:
            prediction_text = "URL model/vectorizer is not fitted. Retrain and save it properly."
        except Exception as e:
            prediction_text = f"URL Prediction error: {str(e)}"

    result = get_result(prediction_text, user_input)
    return render_template("index.html", url_result=result, xss_result=None)

# Serve style.css (if in project root)
@app.route("/style.css")
def css():
    return send_from_directory(BASE_DIR, "style.css")

if __name__ == "__main__":
    # ensure models directory exists (helpful message)
    if not os.path.isdir(MODELS_DIR):
        print(f"⚠️ Models folder not found at: {MODELS_DIR}. Create it and place your .pkl files inside.")
    app.run(debug=True, port=5000)