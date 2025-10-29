import math
import string
import socket
import os
import ipaddress
import Levenshtein
import traceback
from ail_typo_squatting import runAll
from tqdm import tqdm
from urllib.parse import urlparse
import requests
import csv
import time

# whois packages (some systems have both whois and whois.whois)
import whois
import whois.whois as whois_whois

from ssl_checker import SSLChecker
from datetime import datetime
from bs4 import BeautifulSoup
from Known_Sites import TEMPORARY_DOMAIN_PLATFORMS

# Firebase
import firebase_admin
from firebase_admin import firestore, credentials

# ----------------- FIRESTORE INIT (safe) -----------------
PRIVATE_KEY_PATH = "/home/bragadeesh/Desktop/phising/Phishing-be/phising-detecion-firebase-adminsdk-fbsvc-7b0e09d263.json"
db = None
try:
    if os.path.exists(PRIVATE_KEY_PATH):
        cred = credentials.Certificate(PRIVATE_KEY_PATH)
        firebase_admin.initialize_app(cred)
        db = firestore.client()
        print("✅ Firebase initialized.")
    else:
        print(f"⚠️ Firebase key not found at {PRIVATE_KEY_PATH} — continuing without Firestore.")
except Exception as e:
    print("⚠️ Firebase initialization failed:", e)
    db = None

# ----------------- UTILS & SAFETY WRAPPERS -----------------
def safe_execute(default=None):
    """
    Decorator factory that returns a decorator that wraps the function in try/except.
    On exception it logs and returns `default`.
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                print(f"❌ Exception in {func.__name__}: {e}")
                traceback.print_exc()
                return default
        return wrapper
    return decorator

def safe_request(url, timeout=8):
    """
    requests.get wrapper with timeout and exception handling.
    Returns Response or None on failure.
    """
    try:
        return requests.get(url, timeout=timeout)
    except requests.RequestException as e:
        print(f"⚠️ HTTP request failed for {url}: {e}")
        return None

# ----------------- BASIC CHECKS -----------------
@safe_execute(default=False)
def is_https(url):
    return str(url).lower().startswith('https')

@safe_execute(default=False)
def is_temporary_domain(url):
    for temp_domain in TEMPORARY_DOMAIN_PLATFORMS:
        if temp_domain in str(url):
            return True
    return False

# ----------------- TOP 1 MILLION (safe file access) -----------------
@safe_execute(default=False)
def check_top1million_database(url):
    if not os.path.exists('top-1million-sites.csv'):
        print("⚠️ top-1million-sites.csv missing.")
        return False
    with open('top-1million-sites.csv', 'r', newline='', encoding='utf-8', errors='ignore') as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) < 2:
                continue
            try:
                if str(url) in row[1] or str(url) in ("https://www." + row[1]):
                    print(f"{url} is in the top 1 million websites according to Alexa.")
                    return True
            except Exception:
                continue
    print(f"{url} is not in the top 1 million websites according to Alexa.")
    return False

@safe_execute(default=False)
def check_top1million_database_2(url):
    if not os.path.exists('top-1million-sites.csv'):
        print("⚠️ top-1million-sites.csv missing.")
        return False
    domain = urlparse(url).netloc or url.split('/')[0]
    with open('top-1million-sites.csv', 'r', newline='', encoding='utf-8', errors='ignore') as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) < 2:
                continue
            try:
                if domain == row[1] or domain == "www." + row[1]:
                    print(f"{domain} is in the top 1 million websites according to Alexa.")
                    return True
            except Exception:
                continue
    print(f"{domain} is not in the top 1 million websites according to Alexa.")
    return False

# ----------------- SSL CHECK -----------------
@safe_execute(default=False)
def check_ssl_certificate(url):
    try:
        ssl_checker = SSLChecker()
        args = ssl_checker.get_args(['-H', url])
        output = ssl_checker.show_result(args)

        # Normalize output and check for certificates
        if isinstance(output, str):
            return "cert_valid" in output or "valid" in output.lower()
        if isinstance(output, dict):
            # check common keys
            for k in ("cert_valid", "valid", "status"):
                if k in output and bool(output.get(k)):
                    return True
            # flatten dict values and search strings
            for v in output.values():
                if isinstance(v, str) and ("cert_valid" in v or "valid" in v.lower()):
                    return True
            return False
        if isinstance(output, (list, tuple)):
            for item in output:
                if isinstance(item, str) and ("cert_valid" in item or "valid" in item.lower()):
                    return True
                if isinstance(item, dict):
                    for k in ("cert_valid", "valid", "status"):
                        if k in item and bool(item.get(k)):
                            return True
            return False
        return False
    except Exception as e:
        print("⚠️ SSL check failed:", e)
        return False


# ----------------- WHOIS (safe) -----------------
@safe_execute(default=None)
def safe_whois_lookup(domain_or_url):
    """
    Try to use whois.whois with a cleaned domain.
    Returns whois result or None.
    """
    domain = strip_url(domain_or_url)
    if not domain:
        return None
    try:
        # some whois libraries accept plain domain names
        return whois_whois(domain)
    except Exception as e:
        # fallback to whois package
        try:
            return whois.whois(domain)
        except Exception as e2:
            print(f"⚠️ whois failed for {domain}: {e2}")
            return None

@safe_execute(default=None)
def get_registrar(url):
    w = safe_whois_lookup(url)
    if not w:
        return None
    try:
        return getattr(w, "registrar", None) or w.get("registrar") if isinstance(w, dict) else None
    except Exception:
        return None

@safe_execute(default=None)
def get_days_since_creation(domain, months):
    w = safe_whois_lookup(domain)
    if not w:
        print("Unable to access Registration date for Domain !")
        return None
    creation_date = getattr(w, "creation_date", None) or w.get("creation_date") if isinstance(w, dict) else None
    if not creation_date:
        print("Creation date not available")
        return None
    # creation_date can be list or datetime
    try:
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if not isinstance(creation_date, datetime):
            # try parse if possible
            print("Creation date not datetime:", creation_date)
            return None
        days_since_creation = (datetime.now() - creation_date).days
        months_since_creation = days_since_creation / 30.0
        return months_since_creation >= months
    except Exception as e:
        print("Error calculating domain age:", e)
        return None

# ----------------- THIRD-PARTY SCANS (safe wrappers) -----------------
@safe_execute(default=False)
def check_mcafee_database(url):
    mcafee_url = f"https://www.siteadvisor.com/sitereport.html?url={url}"
    res = safe_request(mcafee_url)
    if not res:
        print("Unable to check URL against McAfee SiteAdvisor database.")
        return False
    text = res.text
    if "is safe" in text:
        return True
    return False

@safe_execute(default=False)
def check_google_safe_browsing(url):
    google_url = f"https://transparencyreport.google.com/safe-browsing/search?url={url}"
    res = safe_request(google_url)
    if not res:
        return False
    if "No unsafe content found" in res.text:
        return True
    return False

@safe_execute(default=0)
def checkURLVoid(url):
    scan_url = f"https://www.urlvoid.com/scan/{url}"
    res = safe_request(scan_url)
    if not res:
        return 0
    soup = BeautifulSoup(res.content, 'html.parser')
    span_tag = soup.find('span', class_="label label-danger")
    if span_tag:
        label_text = span_tag.get_text().strip()
        try:
            return int(label_text.split('/')[0])
        except Exception:
            return 0
    return 0

@safe_execute(default=True)
def check_Nortan_WebSafe(url):
    res = safe_request(f"https://safeweb.norton.com/report/show?url={url}")
    if not res:
        return True
    html_content = res.text
    if "known dangerous webpage" in html_content:
        return False
    return True

@safe_execute(default=True)
def checkSucuriBlacklists(url):
    res = safe_request(f"https://sitecheck.sucuri.net/results/{url}")
    if not res:
        return True
    if "Site is Blacklisted" in res.text:
        return False
    return True

# ----------------- LOCAL BLACKLISTS & IP SETS -----------------
@safe_execute(default=False)
def checkLocalBlacklist(url):
    dataset = "blacklisted_sites.txt"
    if not os.path.exists(dataset):
        return False
    with open(dataset, 'r', encoding='utf-8', errors='ignore') as file:
        for line in file:
            website = line.strip()
            if not website:
                continue
            if url == website:
                return True
    return False

@safe_execute(default=False)
def is_valid_ip(text):
    try:
        ipaddress.ip_address(text)
        return True
    except Exception:
        return False

@safe_execute(default=False)
def check_ip_in_ipsets(ip):
    try:
        ip_address = ipaddress.ip_address(ip)
    except Exception:
        return False

    ipset_directory = "blocklist-ipsets/IpSets"
    if not os.path.isdir(ipset_directory):
        return False

    for root, dirs, files in os.walk(ipset_directory):
        for fname in files:
            ipset_file = os.path.join(root, fname)
            try:
                with open(ipset_file, 'r', encoding='utf-8', errors='ignore') as fh:
                    for line in fh:
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue
                        try:
                            subnet = ipaddress.ip_network(line, strict=False)
                            if ip_address in subnet:
                                return True
                        except ValueError:
                            continue
            except Exception:
                continue
    return False

# ----------------- FEATURE HELPERS (AI) -----------------
@safe_execute(default=0)
def get_domain_length(url):
    return len(url)

@safe_execute(default=0)
def get_domain_entropy(url):
    domain = urlparse(url).netloc or ""
    if not domain:
        return 0.0
    alphabet = string.ascii_lowercase + string.digits
    freq = [0] * len(alphabet)
    for char in domain.lower():
        if char in alphabet:
            freq[alphabet.index(char)] += 1
    entropy = 0.0
    length = len(domain)
    for count in freq:
        if count > 0:
            freq_ratio = float(count) / length
            entropy -= freq_ratio * math.log(freq_ratio, 2)
    return round(entropy, 2)

@safe_execute(default=0)
def is_ip_address(url):
    domain = urlparse(url).netloc or ""
    try:
        socket.inet_aton(domain)
        return 1
    except Exception:
        return 0

@safe_execute(default=0)
def has_malicious_extension(url):
    _, ext = os.path.splitext(url)
    malicious_extensions = ['.exe', '.dll', '.bat', '.cmd', '.scr', '.js', '.vbs',
                            '.hta', '.ps1', '.jar', '.py', '.rb']
    return 1 if ext.lower() in malicious_extensions else 0

@safe_execute(default=0)
def query_params_count(url):
    parsed = urlparse(url)
    query_params = parsed.query.split('&')
    if not query_params or query_params[0] == '':
        return 0
    return len(query_params)

@safe_execute(default=0)
def path_tokens_count(url):
    parsed = urlparse(url)
    path_tokens = [t for t in parsed.path.split('/') if t]
    return len(path_tokens)

@safe_execute(default=0)
def hyphens_count(url):
    return url.count('-')

@safe_execute(default=0)
def digits_count(url):
    return sum(c.isdigit() for c in url)

@safe_execute(default=0)
def has_special_characters(url):
    special_chars = ['@', '!', '#', '$', '%', '^', '&', '*', '_', '+']
    return 1 if any((c in url) for c in special_chars) else 0

def getInputArray(url):
    """Return list of features in a stable order (safe)."""
    return [
        get_domain_length(url) or 0,
        get_domain_entropy(url) or 0,
        is_ip_address(url) or 0,
        has_malicious_extension(url) or 0,
        query_params_count(url) or 0,
        path_tokens_count(url) or 0,
        hyphens_count(url) or 0,
        digits_count(url) or 0,
        has_special_characters(url) or 0
    ]

# ----------------- MODEL PREDICTION (safe) -----------------
@safe_execute(default=None)
def isURLMalicious(url, clf):
    """
    clf: pre-loaded classifier with predict / predict_proba methods.
    Returns dict {label, prob} or None on failure.
    """
    input_features = getInputArray(url)
    # If classifier expects feature names, caller should pass DataFrame. We try both:
    try:
        # Try as numpy-like
        import pandas as pd
        
        FEATURE_NAMES = ["domain_length", "domain_entropy", "is_ip", "malicious_ext",
                        "query_params", "path_tokens", "hyphens", "digits", "special_chars"]
        X = pd.DataFrame([input_features], columns=FEATURE_NAMES)
        label = clf.predict(X)[0]
        prob = None
        try:
            proba = clf.predict_proba([input_features])[0]
            # take prob of malicious class if available; assume class '1' at index 1
            prob = float(proba[1]) if len(proba) > 1 else float(proba[0])
        except Exception:
            prob = None
        return {"label": int(label), "probability": prob}
    except Exception as e:
        # Try DataFrame with simple column names if classifier was trained with feature names
        try:
            import pandas as pd
            colnames = ["f" + str(i) for i in range(len(input_features))]
            X = pd.DataFrame([input_features], columns=colnames)
            label = clf.predict(X)[0]
            prob = None
            try:
                proba = clf.predict_proba(X)[0]
                prob = float(proba[1]) if len(proba) > 1 else float(proba[0])
            except Exception:
                prob = None
            return {"label": int(label), "probability": prob}
        except Exception as e2:
            print("Model prediction failed:", e, e2)
            return None

# ----------------- URL SIMILARITY & TYPOSQUATTING -----------------
@safe_execute(default=0)
def calculate_url_similarity(url1, url2):
    levenshtein_distance = Levenshtein.distance(url1, url2)
    similarity_score = (1 - levenshtein_distance / max(len(url1), len(url2))) * 10
    return similarity_score

@safe_execute(default="")
def strip_url(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc or parsed_url.path.strip("/")
    domain = domain.lstrip("www.")
    return domain

@safe_execute(default=[])
def generate_similar_urls(url, max_urls=5000):
    pathOutput = "./type-squating-data/"
    formatoutput = "text"
    try:
        resultList = runAll(
            domain=url,
            limit=math.inf,
            pathOutput=pathOutput,
            formatoutput=formatoutput,
            verbose=False,
            givevariations=False,
            keeporiginal=False
        )
    except Exception as e:
        print("Typo-squatting generator failed:", e)
        return []
    similar_urls = []
    if resultList:
        for modifiedUrl in resultList:
            try:
                if calculate_url_similarity(url, modifiedUrl) > 5:
                    similar_urls.append(modifiedUrl)
                if len(similar_urls) >= max_urls:
                    return similar_urls
            except Exception:
                continue
    return similar_urls

@safe_execute(default=[])
def find_target_urls(fake_url, similarity_score=7):
    fake_url = str(fake_url).lower()
    domain = urlparse(fake_url).netloc or fake_url.split('/')[0]
    result = []
    if not os.path.exists('top-1million-sites.csv'):
        return []
    with open('top-1million-sites.csv', 'r', newline='', encoding='utf-8', errors='ignore') as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) < 2:
                continue
            try:
                if calculate_url_similarity(domain, row[1]) > similarity_score:
                    result.append(row[1])
            except Exception:
                continue
    return result

# ----------------- DOMAIN REGISTRATION PROCESSING -----------------
@safe_execute(default=[])
def process_domain_details(registered_urls):
    AlldomainDetails = []
    for domainDetails in registered_urls:
        try:
            registrar = domainDetails.get("registrar") if isinstance(domainDetails, dict) else getattr(domainDetails, "registrar", None)
            domain_name = domainDetails.get("domain_name") if isinstance(domainDetails, dict) else getattr(domainDetails, "domain_name", None)
            if isinstance(domain_name, list):
                domain_name = domain_name[0]
            country = domainDetails.get("country") if isinstance(domainDetails, dict) else getattr(domainDetails, "country", None)
            if isinstance(country, list):
                country = ", ".join(map(str, country))
            creation_date = domainDetails.get("creation_date") if isinstance(domainDetails, dict) else getattr(domainDetails, "creation_date", None)
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            creation_date_str = None
            if isinstance(creation_date, datetime):
                creation_date_str = "{:%d %B %Y, %H:%M:%S}".format(creation_date)
            else:
                creation_date_str = str(creation_date)
            name_servers = domainDetails.get("name_servers") if isinstance(domainDetails, dict) else getattr(domainDetails, "name_servers", None)
            if isinstance(name_servers, list):
                name_servers = ", ".join(map(str, name_servers))
            output = {
                "registrar": registrar,
                "domain_name": str(domain_name).upper() if domain_name else None,
                "country": country,
                "creation_date": creation_date_str,
                "name_servers": name_servers,
                "status": "VERIFIED ✅"
            }
            AlldomainDetails.append(output)
        except Exception as e:
            print("Error processing domainDetails:", e)
            continue
    return AlldomainDetails

@safe_execute(default=[])
def process_unregistered_urls(unregistered_urls):
    urls = []
    for url in unregistered_urls:
        if len(urls) >= 500:
            break
        output = {
            "registrar": None,
            "domain_name": str(url).upper(),
            "country": None,
            "creation_date": None,
            "name_servers": None,
            "status": "UNVERIFIED ✖️"
        }
        urls.append(output)
    return urls

# ----------------- REGISTERED SIMILAR DOMAINS -----------------
@safe_execute(default=False)
def check_domain_registration(domain):
    domain = strip_url(domain)
    if not domain:
        return None
    try:
        w = safe_whois_lookup(domain)
        if not w:
            return None
        status = getattr(w, "status", None) if not isinstance(w, dict) else w.get("status")
        return w if status else None
    except Exception as e:
        print("Error in check_domain_registration:", e)
        return None

@safe_execute(default={})
def registered_similar_domains(domain, max_urls=20):
    if check_domain_registration(domain) is None:
        if check_top1million_database(domain) or check_top1million_database_2(domain):
            print("Domain in Top 1 Million Sites !")
        else:
            return False

    domain = strip_url(domain)
    original_domain = domain
    similar_urls = generate_similar_urls(domain)
    urls = []
    stopper = 0
    for candidate in list(similar_urls):
        if candidate == original_domain:
            continue
        if stopper >= 20:
            break
        if len(urls) >= max_urls:
            break
        registration_details = check_domain_registration(candidate)
        if registration_details:
            stopper = 0
            urls.append(registration_details)
        else:
            stopper += 1
            similar_urls = [x for x in similar_urls if x != candidate]
    output = {
        "unregistered_urls": similar_urls,
        "registered_urls": urls,
        "total_permutations": len(similar_urls)
    }
    return output

@safe_execute(default={})
def getTypoSquattedDomains(domain, max_num=20):
    output = registered_similar_domains(domain, max_num)
    if output == False:
        return False
    total_permutations = output.get("total_permutations", 0)
    registered_urls = process_domain_details(output.get("registered_urls", []))
    unregistered_urls = process_unregistered_urls(output.get("unregistered_urls", []))
    allDomains = registered_urls + unregistered_urls
    return {
        "total_permutations": total_permutations,
        "allDomains": allDomains
    }

# ----------------- FIRESTORE SAFE FUNCTIONS -----------------
@safe_execute(default=False)
def safe_store_predictions_in_firestore(url, prediction):
    if not db:
        print("⚠️ Firestore client not initialized; skipping store.")
        return False
    try:
        doc_ref = db.collection("predictions_history").document()
        doc_ref.set({
            "url": url,
            "prediction": prediction,
            "checked_at": datetime.now()
        })
        print(f"✅ Stored prediction for {url}")
        return True
    except Exception as e:
        print("⚠️ Firestore write failed:", e)
        return False

@safe_execute(default={"predictions": []})
def safe_get_predictions_from_firestore():
    if not db:
        return {"predictions": []}
    try:
        predictions_ref = db.collection("predictions_history").stream()
        predictions = []
        for doc in predictions_ref:
            predictions.append({"id": doc.id, **doc.to_dict()})
        return {"predictions": predictions}
    except Exception as e:
        print("⚠️ Firestore read failed:", e)
        return {"predictions": []}
    
def where_query(collection_ref, field, op, value):
    try:
        # new-style: filter=(field, op, value)
        return collection_ref.where(filter=(field, op, value))
    except TypeError:
        # old-style: positional args
        return collection_ref.where(field, op, value)


# ----------------- REPORTING DATABASE CHECK (safe) -----------------
@safe_execute(default=False)
def url_in_reporting_database(url):
    if not db:
        return False
    try:
        reported_urls_query = where_query(db.collection('Reported_Urls'), "Url", "==", url)
        bulk_reported_urls_query = where_query(db.collection('Bulk_Reported_Urls'), "Url", "==", url)
        reported_urls_docs = list(reported_urls_query.stream())
        bulk_reported_urls_docs = list(bulk_reported_urls_query.stream())
        if len(reported_urls_docs) > 0:
            return True
        if len(bulk_reported_urls_docs) > 0:
            return True
        return False
    except Exception as e:
        print("⚠️ Error checking reporting DB:", e)
        return False

# ----------------- EXPORTS (for other modules) -----------------
# Keep function names same as before for compatibility
# e.g. store_predictions_in_firestore -> safe_store_predictions_in_firestore
store_predictions_in_firestore = safe_store_predictions_in_firestore
get_predictions_from_firestore = safe_get_predictions_from_firestore

# The rest of the functions keep their names as implemented above:
# check_top1million_database, check_top1million_database_2, check_google_safe_browsing,
# check_mcafee_database, checkSucuriBlacklists, checkURLVoid, check_Nortan_WebSafe,
# getInputArray, isURLMalicious, generate_similar_urls, find_target_urls, getTypoSquattedDomains, etc.

# ----------------- QUICK SELF-TEST (optional) -----------------
if __name__ == "__main__":
    test_urls = [
        "https://www.google.com",
        "http://localhost:5173/extension",
        "https://movies4u.sx/"
    ]
    for u in test_urls:
        print("\n---", u, "---")
        print("in top1:", check_top1million_database(u))
        print("in top1 (2):", check_top1million_database_2(u))
        print("https:", is_https(u))
        print("google safe:", check_google_safe_browsing(u))
        print("sucuri safe:", checkSucuriBlacklists(u))
        print("whois registrar:", get_registrar(u))
        print("domain age >3 months:", get_days_since_creation(u, 3))
        print("input array:", getInputArray(u))
