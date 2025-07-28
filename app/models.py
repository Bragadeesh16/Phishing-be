from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from datetime import datetime
from app.database import Base

class OrganizationDomain(Base):
    __tablename__ = "organization_domains"

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String, unique=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    impersonations = relationship("ImpersonatingDomain", back_populates="organization")

class ImpersonatingDomain(Base):
    __tablename__ = "impersonating_domains"

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String, unique=True, nullable=False)
    organization_id = Column(Integer, ForeignKey("organization_domains.id"))
    detected_at = Column(DateTime, default=datetime.utcnow)
    is_phishing = Column(Boolean, default=False)

    organization = relationship("OrganizationDomain", back_populates="impersonations")
