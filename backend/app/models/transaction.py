from pydantic import BaseModel, Field, field_validator
from typing import Optional, List
from datetime import datetime
from enum import Enum

class Decision(str, Enum):
    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"

class TransactionRequest(BaseModel):
    transaction_id: str = Field(..., example="TXN-2026-0001847")
    amount: float = Field(..., gt=0, example=850.00)
    currency: str = Field(default="ZMW", example="ZMW")

    sender_msisdn: str = Field(..., example="260977123456")
    receiver_msisdn: str = Field(..., example="260966654321")

    sender_device_id: Optional[str] = Field(None, example="device_a8f3k9")
    receiver_is_new: bool = Field(default=False, example=True)

    location_lat: Optional[float] = Field(None, example=-15.4167)
    location_lon: Optional[float] = Field(None, example=28.2833)

    channel: str = Field(default="mobile_money", example="mobile_money")
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    sender_tx_count_last_1h: int = Field(default=0, ge=0)
    sender_tx_count_last_24h: int = Field(default=0, ge=0)
    sender_total_amount_last_24h: float = Field(default=0.0, ge=0)

    is_international: bool = Field(default=False)
    beneficiary_risk_score: float = Field(default=0.0, ge=0, le=1)

    @field_validator("amount")
    def amount_must_be_reasonable(cls, v):
        if v > 500000:
            raise ValueError("Amount exceeds system limit")
        return v

class RiskFactor(BaseModel):
    name: str
    score: float
    reason: str

class FraudResponse(BaseModel):
    transaction_id: str
    decision: Decision
    risk_score: float = Field(..., ge=0, le=1)
    risk_level: str
    factors: List[RiskFactor]
    recommendation: str
    processed_at: datetime