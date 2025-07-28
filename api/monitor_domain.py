from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models import OrganizationDomain
from pydantic import BaseModel
import validators
import pickle

router = APIRouter()


class DomainRequest(BaseModel):
    domain: str

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.post("/api/monitor-domain")
def monitor_domain(request: DomainRequest, db: Session = Depends(get_db)):
    print("hello", request)
    if not validators.domain(request.domain):
        raise HTTPException(status_code=400, detail="Invalid domain format")

    print(request, request.domain)
    existing_domain = db.query(OrganizationDomain).filter_by(domain=request.domain).first()
    if existing_domain:
        raise HTTPException(status_code=400, detail="Domain already registered")

    new_domain = OrganizationDomain(domain=request.domain)
    db.add(new_domain)
    db.commit()
    db.refresh(new_domain)

    return {"message": "Domain registered for monitoring", "domain": request.domain}
