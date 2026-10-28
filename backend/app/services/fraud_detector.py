from datetime import datetime
from typing import List
from backend.app.models.transaction import TransactionRequest, FraudResponse, RiskFactor, Decision
from backend.app.core.config import settings

class FraudDetector:
    """
    Core fraud detection engine for The Guardian.
    """

    def analyze(self, tx: TransactionRequest) -> FraudResponse:
        factors: List[RiskFactor] = []
        score = 0.0

        # High amount
        if tx.amount >= 5000:
            factor_score = min(0.45, (tx.amount / 20000) * 0.45)
            factors.append(RiskFactor(
                name="high_amount",
                score=round(factor_score, 4),
                reason=f"Transaction amount ZMW {tx.amount:,.2f} is high"
            ))
            score += factor_score

        # Velocity - last 1 hour
        if tx.sender_tx_count_last_1h >= settings.MAX_TRANSACTIONS_PER_HOUR:
            factor_score = 0.40
            factors.append(RiskFactor(
                name="high_velocity_1h",
                score=factor_score,
                reason=f"{tx.sender_tx_count_last_1h} transactions in the last hour"
            ))
            score += factor_score
        elif tx.sender_tx_count_last_1h >= 5:
            factor_score = 0.22
            factors.append(RiskFactor(
                name="elevated_velocity_1h",
                score=factor_score,
                reason=f"{tx.sender_tx_count_last_1h} transactions in the last hour"
            ))
            score += factor_score

        # Daily volume
        projected_daily = tx.sender_total_amount_last_24h + tx.amount
        if projected_daily > settings.MAX_AMOUNT_PER_DAY:
            factor_score = 0.35
            factors.append(RiskFactor(
                name="daily_limit_exceeded",
                score=factor_score,
                reason=f"Projected 24h volume ZMW {projected_daily:,.2f} exceeds limit"
            ))
            score += factor_score

        # New beneficiary
        if tx.receiver_is_new:
            factor_score = 0.28
            factors.append(RiskFactor(
                name="new_beneficiary",
                score=factor_score,
                reason="Receiver is a new beneficiary"
            ))
            score += factor_score

        # Unusual hour
        hour = tx.timestamp.hour
        if hour >= 23 or hour <= 4:
            factor_score = 0.18
            factors.append(RiskFactor(
                name="unusual_hour",
                score=factor_score,
                reason=f"Transaction at unusual hour ({hour}:00)"
            ))
            score += factor_score

        # International
        if tx.is_international:
            factor_score = 0.25
            factors.append(RiskFactor(
                name="international_transfer",
                score=factor_score,
                reason="International transfer detected"
            ))
            score += factor_score

        # High-risk beneficiary
        if tx.beneficiary_risk_score > 0.6:
            factor_score = tx.beneficiary_risk_score * 0.30
            factors.append(RiskFactor(
                name="high_risk_beneficiary",
                score=round(factor_score, 4),
                reason=f"Beneficiary has elevated risk score ({tx.beneficiary_risk_score:.2f})"
            ))
            score += factor_score

        # Dangerous combination
        if tx.sender_device_id and tx.amount > 2000 and tx.receiver_is_new:
            factor_score = 0.32
            factors.append(RiskFactor(
                name="new_device_high_value_new_beneficiary",
                score=factor_score,
                reason="New device + high value + new beneficiary combination"
            ))
            score += factor_score

        final_score = min(round(score, 4), 1.0)

        
        if final_score >= settings.BLOCK_THRESHOLD:
            decision = Decision.BLOCK
            risk_level = "CRITICAL"
            recommendation = "Block transaction immediately. Trigger secondary authentication and alert fraud team."
        elif final_score >= settings.REVIEW_THRESHOLD:
            decision = Decision.REVIEW
            risk_level = "HIGH"
            recommendation = "Hold for manual review or step-up authentication (OTP + device check)."
        else:
            decision = Decision.ALLOW
            risk_level = "LOW" if final_score < 0.25 else "MEDIUM"
            recommendation = "Allow transaction. Continue monitoring."

        return FraudResponse(
            transaction_id=tx.transaction_id,
            decision=decision,
            risk_score=final_score,
            risk_level=risk_level,
            factors=factors,
            recommendation=recommendation,
            processed_at=datetime.utcnow()
        )

detector = FraudDetector()