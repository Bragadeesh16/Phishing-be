import scrapy
import tldextract
import requests
import whois
from fuzzywuzzy import fuzz
from datetime import datetime
import re
from bs4 import BeautifulSoup
import os
import sys 
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import pandas as pd
from app.database import SessionLocal
from app.models import OrganizationDomain, ImpersonatingDomain
from ml.ml_feature_extractor import extract_features

class PhishingSpider(scrapy.Spider):
    name = "phishing_spider"

    def start_requests(self):
        print("start requests")
        db = SessionLocal()
        domains = db.query(OrganizationDomain.domain).all()
        db.close()

        search_urls = [
            f"https://www.google.com/search?q=site:{domain[0]}" for domain in domains
        ]

        for url in search_urls:
            yield scrapy.Request(url=url, callback=self.parse, meta={"original_domain": url.split(":")[1]})

    def parse(self, response):
        print("parse")
        original_domain = response.meta["original_domain"]
        links = response.css("a::attr(href)").getall()

        for link in links:
            domain = tldextract.extract(link).registered_domain
            print(domain)
            if domain and domain != original_domain:
                
                similarity = fuzz.ratio(original_domain, domain)
                
                print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>.similiarity >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
                print(similarity)
                print(self.is_content_suspicious(response, original_domain=original_domain))

                if similarity > 40 or self.is_content_suspicious(response, original_domain):
                    self.store_impersonation(original_domain, domain)
    
    # def parse(self, response):
    #     url = response.url
    #     features = extract_features(url)
    #     # prediction = self.model.predict(pd.DataFrame([features]))[0]

    #     # if prediction == 1:
    #     self.store_impersonation(response.meta["original_domain"], url)

    def store_impersonation(self, original, fake):
        print("store_impersonation", original, fake)
        db = SessionLocal()
        exists = db.query(ImpersonatingDomain).filter_by(domain=fake).first()

        if not exists:
            new_impersonation = ImpersonatingDomain(
                domain=fake,
                organization_id=db.query(OrganizationDomain.id).filter_by(domain=original).first()[0],
                detected_at=datetime.utcnow(),
                is_phishing=self.check_whois(fake)
            )
            db.add(new_impersonation)
            db.commit()

        db.close()

    def check_whois(self, domain):
        print("check whois")
        try:
            w = whois.whois(domain)
            return w.registrar not in ["Google LLC", "Cloudflare, Inc."]
        except:
            return False
        
        
    def is_content_suspicious(self, response, original_domain):
        print("is_content_suspicious")
        soup = BeautifulSoup(response.text, "html.parser")

        # Check for brand mentions in title/meta tags
        title = soup.title.string if soup.title else ""
        meta_desc = soup.find("meta", attrs={"name": "description"})
        meta_desc = meta_desc["content"] if meta_desc else ""

        if original_domain.lower() in title.lower() or original_domain.lower() in meta_desc.lower():
            return True

        # Check for common phishing words
        phishing_words = ["login", "verify", "update", "secure", "password"]
        if any(word in title.lower() or word in meta_desc.lower() for word in phishing_words):
            return True

        return False
