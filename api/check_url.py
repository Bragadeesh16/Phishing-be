from fastapi import FastAPI, HTTPException, APIRouter
from pydantic import BaseModel
import joblib
import pandas as pd
import tldextract
from urllib.parse import urlparse
from nltk.tokenize import RegexpTokenizer
from sklearn.base import BaseEstimator, TransformerMixin
from api.transformers import Converter
import pickle 
from api.API import get_prediction 
import Utils

router = APIRouter()


# Define feature names
FEATURES = [
    'length_url', 'length_hostname', 'ip', 'nb_dots', 'nb_qm', 'nb_eq', 'nb_slash', 
    'nb_www', 'ratio_digits_url', 'ratio_digits_host', 'tld_in_subdomain', 'prefix_suffix',
    'shortest_word_host', 'longest_words_raw', 'longest_word_path', 'phish_hints',
    'nb_hyperlinks', 'ratio_intHyperlinks', 'empty_title', 'domain_in_title', 'domain_age',
    'google_index', 'page_rank'
]

    
with open("/home/bragadeesh/Desktop/final-year-project/env/source/phishing-backend/api/lightgbm_classifier.pkl", "rb") as file:
    clf = pickle.load(file)
    
class URLCheckRequest(BaseModel):
    url: str
    timestamp: int
    user_agent: str
    referrer: str
    tab_id: int
    screen_resolution: str


def extract_features(url):
    parsed = urlparse(url)
    
    # Dummy extraction logic (replace with actual logic)
    features = {
        'length_url': len(url),
        'length_hostname': len(parsed.netloc),
        'ip': 0,  # Assuming URL doesn't contain an IP; Implement actual IP check
        'nb_dots': url.count('.'),
        'nb_qm': url.count('?'),
        'nb_eq': url.count('='),
        'nb_slash': url.count('/'),
        'nb_www': 1 if "www" in url else 0,
        'ratio_digits_url': sum(c.isdigit() for c in url) / len(url),
        'ratio_digits_host': sum(c.isdigit() for c in parsed.netloc) / len(parsed.netloc),
        'tld_in_subdomain': 0,  # Implement actual logic
        'prefix_suffix': 1 if '-' in parsed.netloc else 0,
        'shortest_word_host': min(map(len, parsed.netloc.split('.'))) if '.' in parsed.netloc else len(parsed.netloc),
        'longest_words_raw': max(map(len, url.split('/'))) if '/' in url else len(url),
        'longest_word_path': max(map(len, parsed.path.split('/'))) if parsed.path else 0,
        'phish_hints': 0,  # Implement logic for phishing hints
        'nb_hyperlinks': 0,  # Requires scraping (if needed)
        'ratio_intHyperlinks': 0,  # Implement actual logic
        'empty_title': 0,  # Requires fetching page content
        'domain_in_title': 0,  # Requires fetching page content
        'domain_age': 0,  # Requires WHOIS lookup
        'google_index': 1,  # Assume indexed (Replace with actual API check)
        'page_rank': 0  # Implement actual logic
    }
    
    print(features)

    return pd.DataFrame([features])


# **Prediction API Endpoint**
@router.post("/api/check-url")
async def check_url(request: URLCheckRequest):
    try:
        print(request)
        url = request.url 
        
        prediction = get_prediction(url, clf)
        print("Predicted Probability : ", prediction)

        if(prediction["SCORE"] <= 110):
            Utils.store_predictions_in_firestore(url, prediction)
        # always return the output as dictionary/json.
        prediction = {"prediction": prediction}
        

        return prediction
    except Exception as e:
        print(e)
        raise HTTPException(status_code=500)
    try:
        # Extract features
        input_features = extract_features(request.url)
        
        # Predict phishing probability  
        prediction = phishing_model.predict(input_features)[0]
        print("prediction>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n", prediction, "\n")
        
        return {"url": request.url, "is_phishing": bool(prediction)}
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Run the app with: uvicorn filename:app --reload


# # Define Converter (must match the original definition)
# # class Converter(BaseEstimator, TransformerMixin):
# #     def fit(self, x, y=None):
# #         return self

# #     def transform(self, data_frame):
# #         return data_frame.values.ravel()

# # Load the trained model
# svc_clf = joblib.load("C:/Users/HP/Documents/extensions/phishing-backend/api/svc_clf_model.pkl", mmap_mode='r')

# # Initialize FastAPI app

# # Tokenizer
# tokenizer = RegexpTokenizer(r'[A-Za-z]+')


# # Define request body schema
# class URLCheckRequest(BaseModel):
#     url: str
#     timestamp: int
#     user_agent: str
#     referrer: str
#     tab_id: int
#     screen_resolution: str


# # **Feature Extraction Function** (must match training preprocessing)
# def extract_features(url: str):
#     parsed_url = urlparse(url)
#     netloc = parsed_url.netloc
#     path = parsed_url.path

#     features = {
#         "length": len(url),
#         "tld": tldextract.extract(netloc).suffix or "None",
#         "is_ip": 1 if netloc.replace(".", "").isdigit() else 0,
#         "domain_hyphens": netloc.count("-"),
#         "domain_underscores": netloc.count("_"),
#         "path_hyphens": path.count("-"),
#         "path_underscores": path.count("_"),
#         "slashes": path.count("/"),
#         "full_stops": path.count("."),
#         "num_subdomains": tldextract.extract(netloc).subdomain.count(".") + 1 if tldextract.extract(netloc).subdomain else 0,
#         "domain_tokens": " ".join(tokenizer.tokenize(tldextract.extract(netloc).subdomain + "." + tldextract.extract(netloc).domain)),
#         "path_tokens": " ".join(tokenizer.tokenize(path)),
#     }

#     return pd.DataFrame([features])  # Convert to DataFrame for model
