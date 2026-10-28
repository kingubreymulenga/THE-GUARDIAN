from sqlalchemy import Column, Integer, String, Float, DateTime, Text, Boolean
from sqlalchemy.sql import func
from backend.app.db.database import Base


class Transaction(Base):
    __tablename__ = "transactions"

    id = Column(Integer, primary_key=True, index=True)
    transaction_id = Column(String(50), unique=True, index=True, nullable=False)
    amount = Column(Float, nullable=False)
    currency = Column(String(10), default="ZMW")
    sender_msisdn = Column(String(20), index=True)
    receiver_msisdn = Column(String(20), index=True)
    transaction_type = Column(String(50))
    channel = Column(String(50))
    location = Column(String(100))
    device_id = Column(String(100))
    risk_score = Column(Float)
    risk_level = Column(String(20))
    decision = Column(String(20))
    recommendation = Column(Text)
    factors = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    processed_at = Column(DateTime(timezone=True), server_default=func.now())


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    full_name = Column(String(100))
    password = Column(String(255), nullable=False)
    phone = Column(String(20))
    email = Column(String(100), nullable=True)
    balance = Column(Float, default=0.0)
    is_active = Column(Boolean, default=True)
    last_login = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    user_phone = Column(String(20), index=True)
    transaction_id = Column(String(50), nullable=True)
    reason = Column(String(100))
    description = Column(Text)
    status = Column(String(30), default="Pending")
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class ActivityLog(Base):
    __tablename__ = "activity_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_phone = Column(String(20), nullable=True)
    action = Column(String(100))          # e.g. "New Account Created", "User Login"
    details = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())