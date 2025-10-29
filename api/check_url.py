from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import pandas as pd
import pickle
from urllib.parse import urlparse
import Utils
from api.API import get_prediction

router = APIRouter()

# --- Load the trained LightGBM model ---
with open("/home/bragadeesh/Desktop/phising/Phishing-be/api/lightgbm_classifier.pkl", "rb") as file:
    clf = pickle.load(file)


# --- Pydantic Model ---
class URLCheckRequest(BaseModel):
    url: str
    timestamp: int
    user_agent: str
    referrer: str
    tab_id: int
    screen_resolution: str


# --- Safe Firestore Store ---
def safe_store_predictions(url, prediction):
    try:
        Utils.store_predictions_in_firestore(url, prediction)
        print(f"✅ Safely stored prediction for {url}")
    except Exception as e:
        print(f"⚠️ Firestore storage failed for {url}: {e}")


# --- Extract basic URL features (can extend later) ---
def extract_features(url):
    parsed = urlparse(url)

    try:
        features = {
            "length_url": len(url),
            "length_hostname": len(parsed.netloc),
            "ip": 0 if not parsed.netloc.replace('.', '').isdigit() else 1,
            "nb_dots": url.count('.'),
            "nb_qm": url.count('?'),
            "nb_eq": url.count('='),
            "nb_slash": url.count('/'),
            "nb_www": 1 if "www" in url else 0,
            "ratio_digits_url": sum(c.isdigit() for c in url) / len(url),
            "ratio_digits_host": (
                sum(c.isdigit() for c in parsed.netloc) / len(parsed.netloc)
                if parsed.netloc else 0
            ),
            "tld_in_subdomain": 0,
            "prefix_suffix": 1 if '-' in parsed.netloc else 0,
            "shortest_word_host": min(map(len, parsed.netloc.split('.'))) if '.' in parsed.netloc else len(parsed.netloc),
            "longest_words_raw": max(map(len, url.split('/'))) if '/' in url else len(url),
            "longest_word_path": max(map(len, parsed.path.split('/'))) if parsed.path else 0,
            "phish_hints": 0,
            "nb_hyperlinks": 0,
            "ratio_intHyperlinks": 0,
            "empty_title": 0,
            "domain_in_title": 0,
            "domain_age": 0,
            "google_index": 1,
            "page_rank": 0,
        }

        return pd.DataFrame([features])

    except Exception as e:
        print(f"Feature extraction error: {e}")
        raise HTTPException(status_code=400, detail="Feature extraction failed")


# --- API Endpoint ---
@router.post("/api/check-url")
async def check_url(request: URLCheckRequest):
    try:
        url = request.url
        print(f"🔍 Checking URL: {url}")

        # Get prediction using the API module
        prediction = get_prediction(url, clf)
        print("🎯 Predicted Result:", prediction)

        # Store prediction safely (only if SCORE <= 110)
        if prediction.get("SCORE", 999) <= 110:
            safe_store_predictions(url, prediction)

        # Return result as JSON
        return {"prediction": prediction}

    except Exception as e:
        print(f"❌ Error while predicting: {e}")
        raise HTTPException(status_code=500, detail=str(e))
