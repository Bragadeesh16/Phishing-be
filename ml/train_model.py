import re
import tldextract
import whois
import requests
import ssl
import socket
import pandas as pd
from bs4 import BeautifulSoup
from datetime import datetime

def extract_features(url):
    features = {}

    # URL-Based Features
    features["url_length"] = len(url)
    features["num_dots"] = url.count(".")
    features["num_hyphens"] = url.count("-")
    features["num_subdomains"] = len(tldextract.extract(url).subdomain.split("."))

    # WHOIS Features
    try:
        domain_info = whois.whois(url)
        creation_date = domain_info.creation_date if isinstance(domain_info.creation_date, datetime) else None
        age = (datetime.utcnow() - creation_date).days if creation_date else 0
        features["domain_age_days"] = age
    except:
        features["domain_age_days"] = 0

    # SSL Certificate Features
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((url, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=url) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert["issuer"])
                features["ssl_issuer"] = 1 if issuer.get("organizationName") in ["Google Trust Services", "DigiCert Inc."] else 0
    except:
        features["ssl_issuer"] = 0

    # Content-Based Features
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")
        title = soup.title.string if soup.title else ""
        meta_desc = soup.find("meta", attrs={"name": "description"})
        meta_desc = meta_desc["content"] if meta_desc else ""

        phishing_words = ["login", "verify", "update", "secure", "password"]
        features["suspicious_content"] = 1 if any(word in title.lower() + meta_desc.lower() for word in phishing_words) else 0
    except:
        features["suspicious_content"] = 0

    return features
