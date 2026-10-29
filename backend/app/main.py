from fastapi import FastAPI, Request, Depends, Form, status, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse
from datetime import datetime
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware
from passlib.context import CryptContext
import json
import os
from dotenv import load_dotenv

load_dotenv()

from backend.app.core.config import settings
from backend.app.models.transaction import TransactionRequest, FraudResponse
from backend.app.services.fraud_detector import detector
from backend.app.db.database import engine, Base, get_db
from backend.app.db import models
from backend.app.db.models import User, Report, ActivityLog, Transaction

# -------------------------------------------------
# Password Hashing
# -------------------------------------------------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Create database tables
Base.metadata.create_all(bind=engine)

# -------------------------------------------------
# FastAPI App
# -------------------------------------------------
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Real-time Fraud Detection Engine for Digital Wallets (The Guardian)",
    docs_url="/docs",
    redoc_url="/redoc"
)

# -------------------------------------------------
# Middleware
# -------------------------------------------------
app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SECRET_KEY", "guardian-secret-key-obby-mulenga-2026"),
    session_cookie="guardian_session",
    max_age=60 * 60 * 24 * 14,   # 14 days
    same_site="lax",
    https_only=False
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# -------------------------------------------------
# Templates
# -------------------------------------------------
templates = Jinja2Templates(directory="backend/app/templates")


# =================================================
# HELPER FUNCTIONS
# =================================================

def get_current_admin(request: Request):
    """Return admin session if logged in"""
    return request.session.get("user")


def get_current_normal_user(request: Request):
    """Return normal user session if logged in"""
    return request.session.get("normal_user")


def log_activity(db: Session, user_phone: str, action: str, details: str = None):
    """Save activity log for admin monitoring"""
    log = ActivityLog(user_phone=user_phone, action=action, details=details)
    db.add(log)
    db.commit()


# =================================================
# AUTHENTICATION ROUTES
# =================================================

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if get_current_admin(request):
        return RedirectResponse(url="/dashboard", status_code=302)
    if get_current_normal_user(request):
        return RedirectResponse(url="/user/dashboard", status_code=302)
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@app.post("/login", response_class=HTMLResponse)
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    # Admin login
    if username == "admin" and password == "mulenga":
        request.session["user"] = "admin"
        return RedirectResponse(url="/dashboard", status_code=302)

    # Normal user login
    user = db.query(User).filter(User.username == username).first()
    if user and pwd_context.verify(password, user.password):
        user.last_login = datetime.utcnow()
        db.commit()

        request.session["normal_user"] = {
            "id": user.id,
            "username": user.username,
            "full_name": user.full_name,
            "phone": user.phone
        }
        log_activity(db, user.username, "User Login", f"{user.full_name} logged in")
        return RedirectResponse(url="/user/dashboard", status_code=302)

    return templates.TemplateResponse("login.html", {
        "request": request,
        "error": "INVALID CREDENTIALS // ACCESS DENIED"
    })


@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=302)


@app.get("/user/logout")
async def user_logout(request: Request):
    request.session.pop("normal_user", None)
    return RedirectResponse(url="/login", status_code=302)


# =================================================
# ADMIN DASHBOARD
# =================================================

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    if not get_current_admin(request):
        return RedirectResponse(url="/login", status_code=302)
    return templates.TemplateResponse("dashboard.html", {"request": request})


# =================================================
# USER REGISTRATION
# =================================================

@app.get("/user/register", response_class=HTMLResponse)
async def user_register_page(request: Request):
    if get_current_normal_user(request):
        return RedirectResponse(url="/user/dashboard", status_code=302)
    return templates.TemplateResponse("user_register.html", {
        "request": request,
        "error": None,
        "success": None
    })


@app.post("/user/register", response_class=HTMLResponse)
async def user_register(
    request: Request,
    full_name: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    email: str = Form(None),
    db: Session = Depends(get_db)
):
    existing = db.query(User).filter(User.username == username).first()
    if existing:
        return templates.TemplateResponse("user_register.html", {
            "request": request,
            "error": "Phone number already registered",
            "success": None
        })

    hashed_password = pwd_context.hash(password[:72])
    new_user = User(
        username=username,
        full_name=full_name,
        password=hashed_password,
        phone=username,
        email=email
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    log_activity(db, username, "New Account Created", f"User {full_name} registered")

    # Auto login after registration
    request.session["normal_user"] = {
        "id": new_user.id,
        "username": new_user.username,
        "full_name": new_user.full_name,
        "phone": new_user.phone
    }
    return RedirectResponse(url="/user/dashboard", status_code=302)


# =================================================
# USER DASHBOARD (Server-side rendered)
# =================================================

@app.get("/user/dashboard", response_class=HTMLResponse)
async def user_dashboard(request: Request, db: Session = Depends(get_db)):
    user = get_current_normal_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=302)

    phone = user["phone"]

    total = db.query(Transaction).filter(
        (Transaction.sender_msisdn == phone) | (Transaction.receiver_msisdn == phone)
    ).count()

    allowed = db.query(Transaction).filter(
        ((Transaction.sender_msisdn == phone) | (Transaction.receiver_msisdn == phone)),
        Transaction.decision == "ALLOW"
    ).count()

    review = db.query(Transaction).filter(
        ((Transaction.sender_msisdn == phone) | (Transaction.receiver_msisdn == phone)),
        Transaction.decision == "REVIEW"
    ).count()

    blocked = db.query(Transaction).filter(
        ((Transaction.sender_msisdn == phone) | (Transaction.receiver_msisdn == phone)),
        Transaction.decision == "BLOCK"
    ).count()

    transactions = db.query(Transaction).filter(
        (Transaction.sender_msisdn == phone) | (Transaction.receiver_msisdn == phone)
    ).order_by(Transaction.created_at.desc()).limit(10).all()

    return templates.TemplateResponse("user_dashboard.html", {
        "request": request,
        "user": user,
        "stats": {
            "total": total,
            "allowed": allowed,
            "review": review,
            "blocked": blocked
        },
        "transactions": transactions
    })


@app.get("/user/login")
async def redirect_old_user_login():
    return RedirectResponse(url="/login", status_code=302)


# =================================================
# PUBLIC / ADMIN API ROUTES
# =================================================

@app.get("/")
def root():
    return {"service": settings.APP_NAME, "status": "online"}


@app.post("/api/v1/analyze", response_model=FraudResponse)
def analyze_transaction(transaction: TransactionRequest, db: Session = Depends(get_db)):
    try:
        result = detector.analyze(transaction)
        factors_json = json.dumps([factor.dict() for factor in result.factors])

        db_transaction = models.Transaction(
            transaction_id=result.transaction_id,
            amount=transaction.amount,
            currency=transaction.currency,
            sender_msisdn=transaction.sender_msisdn,
            receiver_msisdn=transaction.receiver_msisdn,
            transaction_type=getattr(transaction, "transaction_type", None),
            channel=getattr(transaction, "channel", None),
            location=getattr(transaction, "location", None),
            device_id=getattr(transaction, "device_id", None),
            risk_score=result.risk_score,
            risk_level=result.risk_level,
            decision=result.decision.value if hasattr(result.decision, "value") else str(result.decision),
            recommendation=result.recommendation,
            factors=factors_json
        )
        db.add(db_transaction)
        db.commit()
        return result
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/dashboard/stats")
def get_dashboard_stats(db: Session = Depends(get_db)):
    total = db.query(models.Transaction).count()
    allowed = db.query(models.Transaction).filter(models.Transaction.decision == "ALLOW").count()
    review = db.query(models.Transaction).filter(models.Transaction.decision == "REVIEW").count()
    blocked = db.query(models.Transaction).filter(models.Transaction.decision == "BLOCK").count()

    return {
        "total_transactions": total,
        "allowed": allowed,
        "review": review,
        "blocked": blocked,
        "allowed_percentage": round((allowed / total * 100) if total > 0 else 0, 1),
        "review_percentage": round((review / total * 100) if total > 0 else 0, 1),
        "blocked_percentage": round((blocked / total * 100) if total > 0 else 0, 1)
    }


@app.get("/api/v1/dashboard/recent")
def get_dashboard_recent_transactions(db: Session = Depends(get_db)):
    transactions = db.query(models.Transaction).order_by(
        models.Transaction.created_at.desc()
    ).limit(15).all()

    result = []
    for tx in transactions:
        result.append({
            "transaction_id": tx.transaction_id,
            "amount": tx.amount,
            "currency": tx.currency or "ZMW",
            "risk_score": tx.risk_score or 0,
            "decision": tx.decision or "ALLOW",
            "sender": tx.sender_msisdn or "N/A",
            "receiver": tx.receiver_msisdn or "N/A",
            "time": tx.created_at.strftime("%H:%M:%S") if tx.created_at else "N/A"
        })
    return result


@app.get("/api/v1/admin/activity")
def get_activity_logs(db: Session = Depends(get_db)):
    logs = db.query(ActivityLog).order_by(ActivityLog.created_at.desc()).limit(20).all()
    result = []
    for log in logs:
        result.append({
            "user_phone": log.user_phone or "System",
            "action": log.action,
            "details": log.details or "",
            "time": log.created_at.strftime("%Y-%m-%d %H:%M:%S") if log.created_at else ""
        })
    return result


@app.get("/api/v1/admin/users")
def get_all_users(db: Session = Depends(get_db)):
    users = db.query(User).order_by(User.created_at.desc()).all()
    result = []
    for u in users:
        result.append({
            "id": u.id,
            "username": u.username,
            "full_name": u.full_name,
            "phone": u.phone,
            "email": u.email or "N/A",
            "balance": u.balance or 0.0,
            "is_active": u.is_active,
            "last_login": u.last_login.strftime("%Y-%m-%d %H:%M") if u.last_login else "Never",
            "created_at": u.created_at.strftime("%Y-%m-%d %H:%M") if u.created_at else ""
        })
    return result


@app.delete("/api/v1/admin/users/{user_id}")
def delete_user(user_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    db.delete(user)
    db.commit()
    log_activity(db, "admin", "User Deleted", f"Deleted user {user.username} ({user.full_name})")
    return {"message": "User deleted successfully"}


# =================================================
# USER API ROUTES (FIXED AUTHENTICATION)
# =================================================

@app.get("/api/v1/user/profile")
def get_user_profile(request: Request, db: Session = Depends(get_db)):
    current = get_current_normal_user(request)
    if not current:
        raise HTTPException(status_code=401, detail="Not authenticated")

    user = db.query(User).filter(User.id == current["id"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return {
        "id": user.id,
        "username": user.username,
        "full_name": user.full_name,
        "phone": user.phone,
        "email": user.email or "",
        "balance": user.balance or 0.0,
        "is_active": user.is_active,
        "last_login": user.last_login.strftime("%Y-%m-%d %H:%M") if user.last_login else "Never",
        "created_at": user.created_at.strftime("%Y-%m-%d %H:%M") if user.created_at else ""
    }


@app.put("/api/v1/user/profile")
def update_user_profile(
    request: Request,
    full_name: str = Form(...),
    email: str = Form(None),
    db: Session = Depends(get_db)
):
    current = get_current_normal_user(request)
    if not current:
        raise HTTPException(status_code=401, detail="Not authenticated")

    user = db.query(User).filter(User.id == current["id"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.full_name = full_name
    user.email = email
    db.commit()

    log_activity(db, user.username, "Profile Updated", "User updated profile details")
    return {"message": "Profile updated successfully"}


@app.get("/api/v1/user/transactions")
def get_user_transactions(request: Request, db: Session = Depends(get_db)):
    current = get_current_normal_user(request)
    if not current:
        raise HTTPException(status_code=401, detail="Not authenticated")

    user = db.query(User).filter(User.id == current["id"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    transactions = db.query(Transaction).filter(
        (Transaction.sender_msisdn == user.phone) |
        (Transaction.receiver_msisdn == user.phone)
    ).order_by(Transaction.created_at.desc()).limit(50).all()

    result = []
    for tx in transactions:
        result.append({
            "transaction_id": tx.transaction_id,
            "amount": tx.amount,
            "sender": tx.sender_msisdn,
            "receiver": tx.receiver_msisdn,
            "risk_score": tx.risk_score,
            "decision": tx.decision,
            "time": tx.created_at.strftime("%Y-%m-%d %H:%M") if tx.created_at else ""
        })
    return result


@app.get("/api/v1/user/stats")
def get_user_stats(request: Request, db: Session = Depends(get_db)):
    current = get_current_normal_user(request)
    if not current:
        raise HTTPException(status_code=401, detail="Not authenticated")

    user = db.query(User).filter(User.id == current["id"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    total = db.query(Transaction).filter(
        (Transaction.sender_msisdn == user.phone) |
        (Transaction.receiver_msisdn == user.phone)
    ).count()

    allowed = db.query(Transaction).filter(
        ((Transaction.sender_msisdn == user.phone) | (Transaction.receiver_msisdn == user.phone)),
        Transaction.decision == "ALLOW"
    ).count()

    review = db.query(Transaction).filter(
        ((Transaction.sender_msisdn == user.phone) | (Transaction.receiver_msisdn == user.phone)),
        Transaction.decision == "REVIEW"
    ).count()

    blocked = db.query(Transaction).filter(
        ((Transaction.sender_msisdn == user.phone) | (Transaction.receiver_msisdn == user.phone)),
        Transaction.decision == "BLOCK"
    ).count()

    return {
        "total_transactions": total,
        "allowed": allowed,
        "review": review,
        "blocked": blocked,
        "balance": user.balance or 0.0
    }


@app.post("/api/v1/user/report")
def report_suspicious(
    request: Request,
    transaction_id: str = Form(...),
    reason: str = Form(...),
    db: Session = Depends(get_db)
):
    current = get_current_normal_user(request)
    if not current:
        raise HTTPException(status_code=401, detail="Not authenticated")

    new_report = Report(
        user_phone=current["username"],
        transaction_id=transaction_id,
        reason=reason,
        status="Pending"
    )
    db.add(new_report)
    db.commit()

    log_activity(
        db,
        current["username"],
        "Fraud Report Submitted",
        f"Reported TXN: {transaction_id} - {reason}"
    )
    return {"message": "Report submitted successfully. Admin will review it."}


@app.get("/api/v1/user/notifications")
def get_user_notifications(request: Request, db: Session = Depends(get_db)):
    current = get_current_normal_user(request)
    if not current:
        raise HTTPException(status_code=401, detail="Not authenticated")

    activities = db.query(ActivityLog).filter(
        ActivityLog.user_phone == current["username"]
    ).order_by(ActivityLog.created_at.desc()).limit(15).all()

    result = []
    for act in activities:
        result.append({
            "action": act.action,
            "details": act.details or "",
            "time": act.created_at.strftime("%Y-%m-%d %H:%M") if act.created_at else ""
        })
    return result

 #AIRTEL MONEY + WALLET FEATURES

from pydantic import BaseModel, Field
from typing import Optional
import uuid

class AirtelTransferRequest(BaseModel):
    recipient_phone: str = Field(..., min_length=9, max_length=15)
    amount: float = Field(..., gt=0)
    note: Optional[str] = None


class TopUpRequest(BaseModel):
    amount: float = Field(..., gt=0, le=10000)


@app.post("/api/v1/user/airtel-transfer")
def airtel_money_transfer(
    request: Request,
    data: AirtelTransferRequest,
    db: Session = Depends(get_db)
):
    """Simulate Airtel Money transfer"""
    current = get_current_normal_user(request)
    if not current:
        raise HTTPException(status_code=401, detail="Not authenticated")

    sender = db.query(User).filter(User.id == current["id"]).first()
    if not sender:
        raise HTTPException(status_code=404, detail="User not found")

    if sender.balance is None:
        sender.balance = 0.0

    if sender.balance < data.amount:
        raise HTTPException(status_code=400, detail="Insufficient balance")

    # Generate clean transaction ID
    txn_id = f"AIRTEL-{datetime.utcnow().strftime('%Y%m%d')}-{str(uuid.uuid4())[:8].upper()}"

    # Deduct from sender
    sender.balance -= data.amount

    # Credit receiver if they exist
    receiver = db.query(User).filter(User.phone == data.recipient_phone).first()
    if receiver:
        if receiver.balance is None:
            receiver.balance = 0.0
        receiver.balance += data.amount

    # Create transaction (Admin will see this)
    new_tx = Transaction(
        transaction_id=txn_id,
        amount=data.amount,
        currency="ZMW",
        sender_msisdn=sender.phone,
        receiver_msisdn=data.recipient_phone,
        transaction_type="Airtel Money",
        channel="Mobile App",
        location="Zambia",
        device_id="USER-APP",
        risk_score=8.5,
        risk_level="LOW",
        decision="ALLOW",
        recommendation="Normal Airtel Money transfer",
        factors=json.dumps([{"factor": "Peer to Peer", "weight": 0.1}])
    )

    db.add(new_tx)
    db.commit()

    log_activity(
        db,
        sender.username,
        "Airtel Money Transfer",
        f"Sent K{data.amount:.2f} to {data.recipient_phone} | Ref: {txn_id}"
    )

    return {
        "success": True,
        "message": "Transfer successful",
        "transaction_id": txn_id,
        "amount": data.amount,
        "recipient": data.recipient_phone,
        "new_balance": round(sender.balance, 2)
    }


@app.post("/api/v1/user/topup")
def topup_balance(
    request: Request,
    data: TopUpRequest,
    db: Session = Depends(get_db)
):
    """Simulate Airtel Money top-up / deposit"""
    current = get_current_normal_user(request)
    if not current:
        raise HTTPException(status_code=401, detail="Not authenticated")

    user = db.query(User).filter(User.id == current["id"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.balance is None:
        user.balance = 0.0

    user.balance += data.amount

    txn_id = f"TOPUP-{datetime.utcnow().strftime('%Y%m%d')}-{str(uuid.uuid4())[:8].upper()}"

    # Record the top-up as a transaction
    new_tx = Transaction(
        transaction_id=txn_id,
        amount=data.amount,
        currency="ZMW",
        sender_msisdn="AIRTEL-AGENT",
        receiver_msisdn=user.phone,
        transaction_type="Top Up",
        channel="Agent / App",
        location="Zambia",
        device_id="USER-APP",
        risk_score=3.0,
        risk_level="LOW",
        decision="ALLOW",
        recommendation="Wallet top-up",
        factors=json.dumps([{"factor": "Top-up", "weight": 0.05}])
    )

    db.add(new_tx)
    db.commit()

    log_activity(
        db,
        user.username,
        "Wallet Top-up",
        f"Topped up K{data.amount:.2f} | New Balance: K{user.balance:.2f}"
    )

    return {
        "success": True,
        "message": "Top-up successful",
        "transaction_id": txn_id,
        "amount": data.amount,
        "new_balance": round(user.balance, 2)
    }
