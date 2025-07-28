from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models import OrganizationDomain, ImpersonatingDomain
from Utils import getTypoSquattedDomains
import json

router = APIRouter()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.get("/api/check-impersonation")
def check_impersonation(domain: str):

    url = domain
    max_num = 0

    if (max_num <= 0):
        max_num = 20

    # result
    output = getTypoSquattedDomains(url, max_num)
    print("API OUTPUT : ", output)
    output = {"output": output}

    # Convert the output dictionary to JSON-compatible format
    output_dict = json.loads(json.dumps(output, default=str))
    return output_dict
