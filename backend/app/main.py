# ============================================================
# THE GUARDIAN
# main.py — Updated backend application
# ============================================================

import os
import json
import uuid
import asyncio
import logging

from datetime import datetime, timedelta
from typing import Optional, Any

from dotenv import load_dotenv

load_dotenv()

from fastapi import (
    FastAPI,
    Request,
    Depends,
    Form,
    HTTPException,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import or_, func, inspect, text
from starlette.middleware.sessions import SessionMiddleware
from passlib.context import CryptContext

from backend.app.core.config import settings
from backend.app.models.transaction import TransactionRequest, FraudResponse
from backend.app.services.fraud_detector import detector
from backend.app.db.database import engine, Base, get_db
from backend.app.db import models
from backend.app.db.models import User, Report, ActivityLog, Transaction


# ============================================================
# CONFIGURATION
# ============================================================

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("the_guardian")

pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto"
)

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "mulenga")

SECRET_KEY = os.getenv(
    "SECRET_KEY",
    "CHANGE-THIS-SECRET-KEY-BEFORE-DEPLOYMENT"
)

COOKIE_SECURE = os.getenv(
    "COOKIE_SECURE",
    "true" if os.getenv("RENDER") else "false"
).lower() == "true"

ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv(
        "ALLOWED_ORIGINS",
        "http://localhost:8000,http://127.0.0.1:8000"
    ).split(",")
    if origin.strip()
]


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

# Importing models above registers their tables with Base.metadata.
Base.metadata.create_all(bind=engine)


def run_sqlite_migrations():
    """
    Adds optional transaction coordinate columns to existing SQLite
    databases. New installations get these columns from models.py.
    """

    try:
        if engine.dialect.name != "sqlite":
            return

        inspector = inspect(engine)

        if not inspector.has_table("transactions"):
            return

        existing_columns = {
            column["name"]
            for column in inspector.get_columns("transactions")
        }

        with engine.begin() as connection:
            if "location_lat" not in existing_columns:
                connection.execute(
                    text(
                        "ALTER TABLE transactions "
                        "ADD COLUMN location_lat FLOAT"
                    )
                )

            if "location_lon" not in existing_columns:
                connection.execute(
                    text(
                        "ALTER TABLE transactions "
                        "ADD COLUMN location_lon FLOAT"
                    )
                )

        logger.info("SQLite transaction migration checked successfully.")

    except Exception:
        logger.exception("SQLite migration failed.")
        raise


run_sqlite_migrations()


# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "THE GUARDIAN — Real-Time Fraud Detection System "
        "for Digital Wallets"
    ),
    docs_url="/docs",
    redoc_url="/redoc"
)


# ============================================================
# MIDDLEWARE
# ============================================================

app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    session_cookie="guardian_session",
    max_age=60 * 60 * 24 * 14,
    same_site="lax",
    https_only=COOKIE_SECURE
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)


# ============================================================
# TEMPLATES
# ============================================================

templates = Jinja2Templates(
    directory="backend/app/templates"
)


# ============================================================
# AUTHENTICATION HELPERS
# ============================================================

def get_current_admin(request: Request):
    return request.session.get("user")


def get_current_normal_user(request: Request):
    return request.session.get("normal_user")


def require_admin(request: Request):
    """
    Protects administrator-only API endpoints.
    """

    if not get_current_admin(request):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Administrator authentication required."
        )

    return True


def require_user(request: Request):
    """
    Protects normal-user API endpoints.
    """

    current = get_current_normal_user(request)

    if not current:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User authentication required."
        )

    return current


def hash_password(password: str) -> str:
    """
    Bcrypt supports a maximum of 72 password bytes.
    """

    password_bytes = password.encode("utf-8")[:72]
    safe_password = password_bytes.decode("utf-8", errors="ignore")

    return pwd_context.hash(safe_password)


def verify_password(password: str, hashed_password: str) -> bool:
    password_bytes = password.encode("utf-8")[:72]
    safe_password = password_bytes.decode("utf-8", errors="ignore")

    try:
        return pwd_context.verify(safe_password, hashed_password)
    except Exception:
        logger.warning("Password verification failed.")
        return False


def log_activity(
    db: Session,
    user_phone: str,
    action: str,
    details: Optional[str] = None
):
    """
    Saves an activity record.
    """

    try:
        log = ActivityLog(
            user_phone=user_phone,
            action=action,
            details=details
        )

        db.add(log)
        db.commit()

    except Exception:
        db.rollback()
        logger.exception("Could not save activity log.")


def serialize_factors(factors: Any) -> str:
    """
    Supports both Pydantic v1 and Pydantic v2.
    """

    serialized = []

    for factor in factors or []:
        if hasattr(factor, "model_dump"):
            serialized.append(factor.model_dump())
        elif hasattr(factor, "dict"):
            serialized.append(factor.dict())
        elif isinstance(factor, dict):
            serialized.append(factor)
        else:
            serialized.append({"description": str(factor)})

    return json.dumps(serialized)


def enum_value(value: Any) -> str:
    if hasattr(value, "value"):
        return str(value.value)

    return str(value)


def get_transaction_location_fields(transaction: TransactionRequest):
    """
    Coordinates are optional. Only include them when the installed
    SQLAlchemy Transaction model supports them.
    """

    fields = {}

    if hasattr(Transaction, "location_lat"):
        fields["location_lat"] = getattr(
            transaction,
            "location_lat",
            None
        )

    if hasattr(Transaction, "location_lon"):
        fields["location_lon"] = getattr(
            transaction,
            "location_lon",
            None
        )

    return fields


def create_transaction_record(
    transaction: TransactionRequest,
    result: FraudResponse,
    transaction_type: Optional[str] = None,
    location: Optional[str] = None,
    device_id: Optional[str] = None
):
    """
    Creates a database transaction record using the existing
    SQLAlchemy Transaction model.
    """

    decision = enum_value(result.decision)

    values = {
        "transaction_id": result.transaction_id,
        "amount": transaction.amount,
        "currency": transaction.currency,
        "sender_msisdn": transaction.sender_msisdn,
        "receiver_msisdn": transaction.receiver_msisdn,
        "transaction_type": transaction_type,
        "channel": transaction.channel,
        "location": location,
        "device_id": device_id or transaction.sender_device_id,
        "risk_score": result.risk_score,
        "risk_level": result.risk_level,
        "decision": decision,
        "recommendation": result.recommendation,
        "factors": serialize_factors(result.factors)
    }

    values.update(
        get_transaction_location_fields(transaction)
    )

    return Transaction(**values)


def calculate_sender_activity(
    db: Session,
    sender_phone: str
):
    """
    Calculates sender transaction activity from stored records.
    """

    now = datetime.utcnow()
    one_hour_ago = now - timedelta(hours=1)
    one_day_ago = now - timedelta(hours=24)

    last_hour = db.query(Transaction).filter(
        Transaction.sender_msisdn == sender_phone,
        Transaction.created_at >= one_hour_ago
    ).count()

    last_day_query = db.query(
        func.count(Transaction.id),
        func.coalesce(func.sum(Transaction.amount), 0)
    ).filter(
        Transaction.sender_msisdn == sender_phone,
        Transaction.created_at >= one_day_ago
    ).first()

    count_24h = int(last_day_query[0] or 0)
    amount_24h = float(last_day_query[1] or 0)

    return last_hour, count_24h, amount_24h


# ============================================================
# REAL-TIME ADMIN DASHBOARD WEBSOCKET
# ============================================================

class DashboardConnectionManager:

    def __init__(self):
        self.connections = set()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.connections.add(websocket)

    def disconnect(self, websocket: WebSocket):
        self.connections.discard(websocket)

    async def broadcast(self, event: dict):
        disconnected = []

        for connection in list(self.connections):
            try:
                await connection.send_json(event)
            except Exception:
                disconnected.append(connection)

        for connection in disconnected:
            self.disconnect(connection)


dashboard_manager = DashboardConnectionManager()


async def publish_dashboard_event(event: dict):
    await dashboard_manager.broadcast(event)


@app.websocket("/ws/dashboard")
async def dashboard_websocket(websocket: WebSocket):
    """
    Admin-only dashboard event stream.

    Normal users are not permitted to connect to this endpoint.
    """

    session = websocket.scope.get("session", {})
    admin_user = session.get("user")

    if not admin_user:
        await websocket.close(code=1008)
        return

    await dashboard_manager.connect(websocket)

    try:
        await websocket.send_json({
            "type": "connection",
            "message": "THE GUARDIAN dashboard connected.",
            "time": datetime.utcnow().isoformat()
        })

        while True:
            # Keeps the connection alive.
            await websocket.receive_text()

    except WebSocketDisconnect:
        dashboard_manager.disconnect(websocket)

    except Exception:
        dashboard_manager.disconnect(websocket)
        logger.exception("Dashboard WebSocket error.")


# ============================================================
# AUTHENTICATION ROUTES
# ============================================================

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):

    if get_current_admin(request):
        return RedirectResponse(
            url="/dashboard",
            status_code=302
        )

    if get_current_normal_user(request):
        return RedirectResponse(
            url="/user/dashboard",
            status_code=302
        )

    return templates.TemplateResponse(
        "login.html",
        {
            "request": request,
            "error": None
        }
    )


@app.post("/login", response_class=HTMLResponse)
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):

    # Administrator login.
    if (
        username == ADMIN_USERNAME
        and password == ADMIN_PASSWORD
    ):
        request.session.clear()
        request.session["user"] = ADMIN_USERNAME

        log_activity(
            db,
            "admin",
            "Administrator Login",
            "Administrator logged into THE GUARDIAN."
        )

        return RedirectResponse(
            url="/dashboard",
            status_code=302
        )

    # Normal user login.
    user = db.query(User).filter(
        User.username == username
    ).first()

    if user and user.is_active and verify_password(
        password,
        user.password
    ):

        user.last_login = datetime.utcnow()
        db.commit()

        request.session.clear()

        request.session["normal_user"] = {
            "id": user.id,
            "username": user.username,
            "full_name": user.full_name,
            "phone": user.phone
        }

        log_activity(
            db,
            user.username,
            "User Login",
            f"{user.full_name} logged in."
        )

        return RedirectResponse(
            url="/user/dashboard",
            status_code=302
        )

    return templates.TemplateResponse(
        "login.html",
        {
            "request": request,
            "error": "INVALID CREDENTIALS // ACCESS DENIED"
        }
    )


@app.get("/logout")
async def logout(request: Request):
    request.session.clear()

    return RedirectResponse(
        url="/login",
        status_code=302
    )


@app.get("/user/logout")
async def user_logout(request: Request):
    request.session.pop("normal_user", None)

    return RedirectResponse(
        url="/login",
        status_code=302
    )


# ============================================================
# ADMIN DASHBOARD
# ============================================================

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):

    if not get_current_admin(request):
        return RedirectResponse(
            url="/login",
            status_code=302
        )

    return templates.TemplateResponse(
        "dashboard.html",
        {"request": request}
    )


# ============================================================
# USER REGISTRATION
# ============================================================

@app.get("/user/register", response_class=HTMLResponse)
async def user_register_page(request: Request):

    if get_current_normal_user(request):
        return RedirectResponse(
            url="/user/dashboard",
            status_code=302
        )

    return templates.TemplateResponse(
        "user_register.html",
        {
            "request": request,
            "error": None,
            "success": None
        }
    )


@app.post("/user/register", response_class=HTMLResponse)
async def user_register(
    request: Request,
    full_name: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    email: str = Form(None),
    db: Session = Depends(get_db)
):

    full_name = full_name.strip()
    username = username.strip()

    if not full_name or not username or not password:
        return templates.TemplateResponse(
            "user_register.html",
            {
                "request": request,
                "error": "Please complete all required fields.",
                "success": None
            }
        )

    if len(password) < 8:
        return templates.TemplateResponse(
            "user_register.html",
            {
                "request": request,
                "error": "Password must contain at least 8 characters.",
                "success": None
            }
        )

    existing = db.query(User).filter(
        User.username == username
    ).first()

    if existing:
        return templates.TemplateResponse(
            "user_register.html",
            {
                "request": request,
                "error": "Phone number or username already registered.",
                "success": None
            }
        )

    try:
        new_user = User(
            username=username,
            full_name=full_name,
            password=hash_password(password),
            phone=username,
            email=email
        )

        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        log_activity(
            db,
            username,
            "New Account Created",
            f"User {full_name} registered."
        )

        request.session.clear()

        request.session["normal_user"] = {
            "id": new_user.id,
            "username": new_user.username,
            "full_name": new_user.full_name,
            "phone": new_user.phone
        }

        return RedirectResponse(
            url="/user/dashboard",
            status_code=302
        )

    except Exception:
        db.rollback()
        logger.exception("User registration failed.")

        return templates.TemplateResponse(
            "user_register.html",
            {
                "request": request,
                "error": "Registration failed. Please try again.",
                "success": None
            }
        )


# ============================================================
# USER DASHBOARD
# ============================================================

@app.get("/user/dashboard", response_class=HTMLResponse)
async def user_dashboard(
    request: Request,
    db: Session = Depends(get_db)
):

    current = get_current_normal_user(request)

    if not current:
        return RedirectResponse(
            url="/login",
            status_code=302
        )

    user = db.query(User).filter(
        User.id == current["id"]
    ).first()

    if not user:
        request.session.pop("normal_user", None)

        return RedirectResponse(
            url="/login",
            status_code=302
        )

    return templates.TemplateResponse(
        "user_dashboard.html",
        {
            "request": request,
            "user": current
        }
    )


@app.get("/user/login")
async def redirect_old_user_login():
    return RedirectResponse(
        url="/login",
        status_code=302
    )


# ============================================================
# ROOT / HEALTH CHECK
# ============================================================

@app.get("/")
def root():
    return {
        "service": settings.APP_NAME,
        "status": "online",
        "system": "THE GUARDIAN",
        "time": datetime.utcnow().isoformat()
    }


@app.get("/health")
def health_check():
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))

        return {
            "status": "healthy",
            "database": "connected"
        }

    except Exception:
        logger.exception("Health check failed.")

        raise HTTPException(
            status_code=503,
            detail="Database connection unavailable."
        )


# ============================================================
# TRANSACTION ANALYSIS API
# ============================================================

@app.post(
    "/api/v1/analyze",
    response_model=FraudResponse
)
async def analyze_transaction(
    transaction: TransactionRequest,
    db: Session = Depends(get_db),
    admin: bool = Depends(require_admin)
):

    try:
        existing = db.query(Transaction).filter(
            Transaction.transaction_id == transaction.transaction_id
        ).first()

        if existing:
            raise HTTPException(
                status_code=409,
                detail="Transaction ID already exists."
            )

        result = detector.analyze(transaction)

        db_transaction = create_transaction_record(
            transaction=transaction,
            result=result
        )

        db.add(db_transaction)
        db.commit()

        await publish_dashboard_event({
            "type": "transaction",
            "transaction_id": result.transaction_id,
            "decision": enum_value(result.decision),
            "risk_score": result.risk_score,
            "time": datetime.utcnow().isoformat()
        })

        return result

    except HTTPException:
        db.rollback()
        raise

    except Exception:
        db.rollback()
        logger.exception("Transaction analysis failed.")

        raise HTTPException(
            status_code=500,
            detail="Transaction analysis could not be completed."
        )


# ============================================================
# ADMIN DASHBOARD STATISTICS
# ============================================================

@app.get("/api/v1/dashboard/stats")
def get_dashboard_stats(
    db: Session = Depends(get_db),
    admin: bool = Depends(require_admin)
):

    total = db.query(Transaction).count()

    allowed = db.query(Transaction).filter(
        Transaction.decision == "ALLOW"
    ).count()

    review = db.query(Transaction).filter(
        Transaction.decision == "REVIEW"
    ).count()

    blocked = db.query(Transaction).filter(
        Transaction.decision == "BLOCK"
    ).count()

    return {
        "total_transactions": total,
        "allowed": allowed,
        "review": review,
        "blocked": blocked,
        "allowed_percentage": round(
            allowed / total * 100 if total else 0,
            1
        ),
        "review_percentage": round(
            review / total * 100 if total else 0,
            1
        ),
        "blocked_percentage": round(
            blocked / total * 100 if total else 0,
            1
        )
    }


@app.get("/api/v1/dashboard/recent")
def get_dashboard_recent_transactions(
    db: Session = Depends(get_db),
    admin: bool = Depends(require_admin)
):

    transactions = db.query(Transaction).order_by(
        Transaction.created_at.desc()
    ).limit(15).all()

    return [
        {
            "transaction_id": tx.transaction_id,
            "amount": tx.amount,
            "currency": tx.currency or "ZMW",
            "risk_score": tx.risk_score or 0,
            "decision": tx.decision or "ALLOW",
            "sender": tx.sender_msisdn or "N/A",
            "receiver": tx.receiver_msisdn or "N/A",
            "location": getattr(tx, "location", None),
            "location_lat": getattr(tx, "location_lat", None),
            "location_lon": getattr(tx, "location_lon", None),
            "time": (
                tx.created_at.strftime("%H:%M:%S")
                if tx.created_at else "N/A"
            )
        }
        for tx in transactions
    ]


# ============================================================
# ADMIN TRANSACTION MANAGEMENT
# ============================================================

@app.get("/api/v1/admin/transactions")
def get_admin_transactions(
    limit: int = 200,
    db: Session = Depends(get_db),
    admin: bool = Depends(require_admin)
):

    limit = max(1, min(limit, 1000))

    transactions = db.query(Transaction).order_by(
        Transaction.created_at.desc()
    ).limit(limit).all()

    result = []

    for tx in transactions:
        try:
            factors = json.loads(tx.factors or "[]")
        except (ValueError, TypeError):
            factors = []

        result.append({
            "transaction_id": tx.transaction_id,
            "amount": tx.amount,
            "currency": tx.currency or "ZMW",
            "sender": tx.sender_msisdn,
            "receiver": tx.receiver_msisdn,
            "transaction_type": tx.transaction_type,
            "channel": tx.channel,
            "location": tx.location,
            "location_lat": getattr(tx, "location_lat", None),
            "location_lon": getattr(tx, "location_lon", None),
            "device_id": tx.device_id,
            "risk_score": tx.risk_score or 0,
            "risk_level": tx.risk_level,
            "decision": tx.decision,
            "recommendation": tx.recommendation,
            "factors": factors,
            "created_at": (
                tx.created_at.isoformat()
                if tx.created_at else None
            )
        })

    return result


# ============================================================
# ADMIN REPORT MANAGEMENT
# ============================================================

@app.get("/api/v1/admin/reports")
def get_admin_reports(
    db: Session = Depends(get_db),
    admin: bool = Depends(require_admin)
):

    reports = db.query(Report).order_by(
        Report.created_at.desc()
    ).all()

    return [
        {
            "id": report.id,
            "user_phone": report.user_phone,
            "transaction_id": report.transaction_id,
            "reason": report.reason,
            "description": report.description,
            "status": report.status,
            "created_at": (
                report.created_at.isoformat()
                if report.created_at else None
            )
        }
        for report in reports
    ]


@app.patch("/api/v1/admin/reports/{report_id}")
def update_admin_report(
    report_id: int,
    status_value: str,
    db: Session = Depends(get_db),
    admin: bool = Depends(require_admin)
):

    allowed_statuses = {
        "Pending",
        "Under Review",
        "Resolved",
        "Rejected"
    }

    if status_value not in allowed_statuses:
        raise HTTPException(
            status_code=400,
            detail="Invalid report status."
        )

    report = db.query(Report).filter(
        Report.id == report_id
    ).first()

    if not report:
        raise HTTPException(
            status_code=404,
            detail="Report not found."
        )

    report.status = status_value
    db.commit()

    log_activity(
        db,
        "admin",
        "Report Status Updated",
        f"Report {report_id} changed to {status_value}."
    )

    return {
        "success": True,
        "message": "Report status updated.",
        "report_id": report_id,
        "status": status_value
    }


# ============================================================
# ADMIN INVESTIGATION CASES
# ============================================================

def get_investigation_model():
    """
    InvestigationCase will be added in the updated models.py.
    This avoids breaking startup before that file is updated.
    """

    return getattr(models, "InvestigationCase", None)


@app.get("/api/v1/admin/cases")
def get_investigation_cases(
    db: Session = Depends(get_db),
    admin: bool = Depends(require_admin)
):

    CaseModel = get_investigation_model()

    if CaseModel is None:
        return []

    cases = db.query(CaseModel).order_by(
        CaseModel.created_at.desc()
    ).all()

    return [
        {
            "id": case.id,
            "title": case.title,
            "description": case.description,
            "transaction_id": case.transaction_id,
            "status": case.status,
            "priority": case.priority,
            "assigned_to": case.assigned_to,
            "created_at": (
                case.created_at.isoformat()
                if case.created_at else None
            )
        }
        for case in cases
    ]


class InvestigationCaseCreate(BaseModel):
    title: str = Field(..., min_length=3, max_length=200)
    description: Optional[str] = None
    transaction_id: Optional[str] = None
    priority: str = "Medium"
    assigned_to: Optional[str] = None


class InvestigationCaseUpdate(BaseModel):
    status: Optional[str] = None
    priority: Optional[str] = None
    assigned_to: Optional[str] = None
    description: Optional[str] = None


@app.post("/api/v1/admin/cases")
def create_investigation_case(
    data: InvestigationCaseCreate,
    db: Session = Depends(get_db),
    admin: bool = Depends(require_admin)
):

    CaseModel = get_investigation_model()

    if CaseModel is None:
        raise HTTPException(
            status_code=503,
            detail="Investigation model is not installed yet."
        )

    if data.transaction_id:
        transaction = db.query(Transaction).filter(
            Transaction.transaction_id == data.transaction_id
        ).first()

        if not transaction:
            raise HTTPException(
                status_code=404,
                detail="Related transaction not found."
            )

    try:
        case = CaseModel(
            title=data.title,
            description=data.description,
            transaction_id=data.transaction_id,
            priority=data.priority,
            assigned_to=data.assigned_to,
            status="Open"
        )

        db.add(case)
        db.commit()
        db.refresh(case)

        log_activity(
            db,
            "admin",
            "Investigation Case Created",
            f"Created case {case.id}: {case.title}"
        )

        return {
            "success": True,
            "case_id": case.id,
            "message": "Investigation case created."
        }

    except Exception:
        db.rollback()
        logger.exception("Investigation case creation failed.")

        raise HTTPException(
            status_code=500,
            detail="Could not create investigation case."
        )


@app.patch("/api/v1/admin/cases/{case_id}")
def update_investigation_case(
    case_id: int,
    data: InvestigationCaseUpdate,
    db: Session = Depends(get_db),
    admin: bool = Depends(require_admin)
):

    CaseModel = get_investigation_model()

    if CaseModel is None:
        raise HTTPException(
            status_code=503,
            detail="Investigation model is not installed yet."
        )

    case = db.query(CaseModel).filter(
        CaseModel.id == case_id
    ).first()

    if not case:
        raise HTTPException(
            status_code=404,
            detail="Investigation case not found."
        )

    allowed_statuses = {
        "Open",
        "In Progress",
        "Under Review",
        "Closed"
    }

    allowed_priorities = {
        "Low",
        "Medium",
        "High",
        "Critical"
    }

    if data.status is not None:
        if data.status not in allowed_statuses:
            raise HTTPException(
                status_code=400,
                detail="Invalid case status."
            )

        case.status = data.status

    if data.priority is not None:
        if data.priority not in allowed_priorities:
            raise HTTPException(
                status_code=400,
                detail="Invalid case priority."
            )

        case.priority = data.priority

    if data.assigned_to is not None:
        case.assigned_to = data.assigned_to

    if data.description is not None:
        case.description = data.description

    db.commit()

    log_activity(
        db,
        "admin",
        "Investigation Case Updated",
        f"Updated investigation case {case_id}."
    )

    return {
        "success": True,
        "message": "Investigation case updated."
    }


# ============================================================
# ADMIN ACTIVITY LOGS
# ============================================================

@app.get("/api/v1/admin/activity")
def get_activity_logs(
    db: Session = Depends(get_db),
    admin: bool = Depends(require_admin)
):

    logs = db.query(ActivityLog).order_by(
        ActivityLog.created_at.desc()
    ).limit(100).all()

    return [
        {
            "user_phone": log.user_phone or "System",
            "action": log.action,
            "details": log.details or "",
            "time": (
                log.created_at.strftime("%Y-%m-%d %H:%M:%S")
                if log.created_at else ""
            )
        }
        for log in logs
    ]


# ============================================================
# ADMIN USER MANAGEMENT
# ============================================================

@app.get("/api/v1/admin/users")
def get_all_users(
    db: Session = Depends(get_db),
    admin: bool = Depends(require_admin)
):

    users = db.query(User).order_by(
        User.created_at.desc()
    ).all()

    return [
        {
            "id": user.id,
            "username": user.username,
            "full_name": user.full_name,
            "phone": user.phone,
            "email": user.email or "N/A",
            "balance": user.balance or 0.0,
            "is_active": user.is_active,
            "last_login": (
                user.last_login.strftime("%Y-%m-%d %H:%M")
                if user.last_login else "Never"
            ),
            "created_at": (
                user.created_at.strftime("%Y-%m-%d %H:%M")
                if user.created_at else ""
            )
        }
        for user in users
    ]


@app.delete("/api/v1/admin/users/{user_id}")
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    admin: bool = Depends(require_admin)
):

    user = db.query(User).filter(
        User.id == user_id
    ).first()

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found."
        )

    try:
        username = user.username
        full_name = user.full_name

        db.delete(user)
        db.commit()

        log_activity(
            db,
            "admin",
            "User Deleted",
            f"Deleted user {username} ({full_name})."
        )

        return {
            "success": True,
            "message": "User deleted successfully."
        }

    except Exception:
        db.rollback()
        logger.exception("User deletion failed.")

        raise HTTPException(
            status_code=500,
            detail="Could not delete user."
        )


# ============================================================
# USER PROFILE API
# ============================================================

@app.get("/api/v1/user/profile")
def get_user_profile(
    request: Request,
    db: Session = Depends(get_db)
):

    current = require_user(request)

    user = db.query(User).filter(
        User.id == current["id"]
    ).first()

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found."
        )

    return {
        "id": user.id,
        "username": user.username,
        "full_name": user.full_name,
        "phone": user.phone,
        "email": user.email or "",
        "balance": user.balance or 0.0,
        "is_active": user.is_active,
        "last_login": (
            user.last_login.strftime("%Y-%m-%d %H:%M")
            if user.last_login else "Never"
        ),
        "created_at": (
            user.created_at.strftime("%Y-%m-%d %H:%M")
            if user.created_at else ""
        )
    }


@app.put("/api/v1/user/profile")
def update_user_profile(
    request: Request,
    full_name: str = Form(...),
    email: str = Form(None),
    db: Session = Depends(get_db)
):

    current = require_user(request)

    user = db.query(User).filter(
        User.id == current["id"]
    ).first()

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found."
        )

    user.full_name = full_name.strip()
    user.email = email

    db.commit()

    request.session["normal_user"]["full_name"] = user.full_name

    log_activity(
        db,
        user.username,
        "Profile Updated",
        "User updated profile details."
    )

    return {
        "success": True,
        "message": "Profile updated successfully."
    }


# ============================================================
# USER TRANSACTION HISTORY
# ============================================================

@app.get("/api/v1/user/transactions")
def get_user_transactions(
    request: Request,
    db: Session = Depends(get_db)
):

    current = require_user(request)

    user = db.query(User).filter(
        User.id == current["id"]
    ).first()

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found."
        )

    transactions = db.query(Transaction).filter(
        or_(
            Transaction.sender_msisdn == user.phone,
            Transaction.receiver_msisdn == user.phone
        )
    ).order_by(
        Transaction.created_at.desc()
    ).limit(50).all()

    return [
        {
            "transaction_id": tx.transaction_id,
            "amount": tx.amount,
            "currency": tx.currency or "ZMW",
            "sender": tx.sender_msisdn,
            "receiver": tx.receiver_msisdn,
            "risk_score": tx.risk_score,
            "decision": tx.decision,
            "time": (
                tx.created_at.strftime("%Y-%m-%d %H:%M")
                if tx.created_at else ""
            )
        }
        for tx in transactions
    ]


# ============================================================
# USER TRANSACTION STATISTICS
# ============================================================

@app.get("/api/v1/user/stats")
def get_user_stats(
    request: Request,
    db: Session = Depends(get_db)
):

    current = require_user(request)

    user = db.query(User).filter(
        User.id == current["id"]
    ).first()

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found."
        )

    user_filter = or_(
        Transaction.sender_msisdn == user.phone,
        Transaction.receiver_msisdn == user.phone
    )

    total = db.query(Transaction).filter(
        user_filter
    ).count()

    allowed = db.query(Transaction).filter(
        user_filter,
        Transaction.decision == "ALLOW"
    ).count()

    review = db.query(Transaction).filter(
        user_filter,
        Transaction.decision == "REVIEW"
    ).count()

    blocked = db.query(Transaction).filter(
        user_filter,
        Transaction.decision == "BLOCK"
    ).count()

    return {
        "total_transactions": total,
        "allowed": allowed,
        "review": review,
        "blocked": blocked,
        "balance": user.balance or 0.0
    }


# ============================================================
# USER FRAUD REPORTING
# ============================================================

@app.post("/api/v1/user/report")
def report_suspicious(
    request: Request,
    transaction_id: str = Form(...),
    reason: str = Form(...),
    db: Session = Depends(get_db)
):

    current = require_user(request)

    user = db.query(User).filter(
        User.id == current["id"]
    ).first()

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found."
        )

    transaction = db.query(Transaction).filter(
        Transaction.transaction_id == transaction_id
    ).first()

    if not transaction:
        raise HTTPException(
            status_code=404,
            detail="Transaction not found."
        )

    # Users may only report transactions involving their own account.
    if (
        transaction.sender_msisdn != user.phone
        and transaction.receiver_msisdn != user.phone
    ):
        raise HTTPException(
            status_code=403,
            detail="You cannot report a transaction unrelated to your account."
        )

    new_report = Report(
        user_phone=user.phone,
        transaction_id=transaction_id,
        reason=reason.strip(),
        status="Pending"
    )

    try:
        db.add(new_report)
        db.commit()

        log_activity(
            db,
            user.username,
            "Fraud Report Submitted",
            f"Reported TXN: {transaction_id} - {reason}"
        )

        return {
            "success": True,
            "message": "Report submitted successfully. Admin will review it."
        }

    except Exception:
        db.rollback()
        logger.exception("Fraud report submission failed.")

        raise HTTPException(
            status_code=500,
            detail="Could not submit fraud report."
        )


# ============================================================
# USER NOTIFICATIONS
# ============================================================

@app.get("/api/v1/user/notifications")
def get_user_notifications(
    request: Request,
    db: Session = Depends(get_db)
):

    current = require_user(request)

    activities = db.query(ActivityLog).filter(
        ActivityLog.user_phone == current["username"]
    ).order_by(
        ActivityLog.created_at.desc()
    ).limit(15).all()

    return [
        {
            "action": activity.action,
            "details": activity.details or "",
            "time": (
                activity.created_at.strftime("%Y-%m-%d %H:%M")
                if activity.created_at else ""
            )
        }
        for activity in activities
    ]


# ============================================================
# MULENGA — LOCAL AI ASSISTANT
# ============================================================

class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=2000)


@app.post("/api/v1/user/ai-chat")
async def user_ai_chat(
    request: Request,
    data: ChatRequest
):

    require_user(request)

    message = data.message.lower().strip()

    if any(word in message for word in [
        "hello", "hi", "hey", "mwaiseni", "takulandilani"
    ]):
        answer = (
            "Mwaiseni! Takulandilani. I am Mulenga, your AI assistant "
            "in THE GUARDIAN system. How can I help you today?"
        )

    elif any(word in message for word in [
        "balance", "money", "how much"
    ]):
        answer = (
            "You can check your current wallet balance on the Home page "
            "or in the Wallet section of your dashboard."
        )

    elif any(word in message for word in [
        "fraud", "scam", "suspicious", "block"
    ]):
        answer = (
            "THE GUARDIAN uses real-time fraud detection. If you see "
            "a suspicious transaction, go to Report Fraud and submit "
            "the Transaction ID. The administrator can review your report."
        )

    elif any(word in message for word in [
        "send money", "transfer", "airtel"
    ]):
        answer = (
            "To send money, go to the Wallet section, choose Send Money, "
            "enter the recipient's phone number and amount, then confirm. "
            "Transfers are subject to fraud screening."
        )

    elif any(word in message for word in [
        "top up", "topup", "deposit"
    ]):
        answer = (
            "To top up your demo wallet, go to the Wallet section "
            "and select Top Up. Demo top-ups are not verified Airtel "
            "Money payments."
        )

    elif any(word in message for word in [
        "transaction", "history", "statement"
    ]):
        answer = (
            "You can view your recorded transactions in the History "
            "section of your dashboard."
        )

    elif any(word in message for word in [
        "who are you", "your name", "mulenga"
    ]):
        answer = (
            "I am Mulenga, the AI assistant of THE GUARDIAN, created "
            "as part of Engineer Aubrey Mulenga's project to help "
            "protect digital wallet users."
        )

    elif any(word in message for word in [
        "help", "assist", "support"
    ]):
        answer = (
            "I can help you understand your wallet, sending money, "
            "reporting fraud, viewing transactions and how THE GUARDIAN "
            "screens transactions."
        )

    elif any(word in message for word in [
        "thank", "thanks"
    ]):
        answer = "You're welcome! Stay safe with THE GUARDIAN."

    else:
        answer = (
            "I'm still learning. You can ask me about your balance, "
            "sending money, reporting fraud or how THE GUARDIAN "
            "protects your transactions."
        )

    return {"answer": answer}


# ============================================================
# WALLET REQUEST MODELS
# ============================================================

class AirtelTransferRequest(BaseModel):
    recipient_phone: str = Field(
        ...,
        min_length=9,
        max_length=15
    )

    amount: float = Field(
        ...,
        gt=0,
        le=500000
    )

    note: Optional[str] = Field(
        default=None,
        max_length=250
    )


class TopUpRequest(BaseModel):
    amount: float = Field(
        ...,
        gt=0,
        le=10000
    )


# ============================================================
# AIRTEL / INTERNAL WALLET TRANSFER
# ============================================================

@app.post("/api/v1/user/airtel-transfer")
async def airtel_money_transfer(
    request: Request,
    data: AirtelTransferRequest,
    db: Session = Depends(get_db)
):

    current = require_user(request)

    sender = db.query(User).filter(
        User.id == current["id"]
    ).first()

    if not sender:
        raise HTTPException(
            status_code=404,
            detail="Sender account not found."
        )

    recipient_phone = data.recipient_phone.strip()

    if recipient_phone == sender.phone:
        raise HTTPException(
            status_code=400,
            detail="You cannot transfer money to your own account."
        )

    sender.balance = float(sender.balance or 0)

    if sender.balance < data.amount:
        raise HTTPException(
            status_code=400,
            detail="Insufficient wallet balance."
        )

    receiver = db.query(User).filter(
        User.phone == recipient_phone
    ).first()

    # Calculate real sender transaction activity.
    count_1h, count_24h, amount_24h = calculate_sender_activity(
        db,
        sender.phone
    )

    # Check whether the recipient has previously received funds.
    previous_beneficiary_transactions = db.query(Transaction).filter(
        Transaction.receiver_msisdn == recipient_phone
    ).count()

    receiver_is_new = previous_beneficiary_transactions == 0

    transaction_id = (
        f"GUARDIAN-{datetime.utcnow().strftime('%Y%m%d')}-"
        f"{uuid.uuid4().hex[:10].upper()}"
    )

    transaction_request = TransactionRequest(
        transaction_id=transaction_id,
        amount=data.amount,
        currency="ZMW",
        sender_msisdn=sender.phone,
        receiver_msisdn=recipient_phone,
        sender_device_id="USER-APP",
        receiver_is_new=receiver_is_new,
        channel="mobile_money",
        timestamp=datetime.utcnow(),
        sender_tx_count_last_1h=count_1h,
        sender_tx_count_last_24h=count_24h,
        sender_total_amount_last_24h=amount_24h,
        is_international=False,
        beneficiary_risk_score=0.0
    )

    try:
        # Run the actual fraud detector before changing balances.
        result = detector.analyze(transaction_request)

        db_transaction = create_transaction_record(
            transaction=transaction_request,
            result=result,
            transaction_type="Airtel Money Transfer",
            location="Zambia",
            device_id="USER-APP"
        )

        db.add(db_transaction)

        decision = enum_value(result.decision)

        # REVIEW and BLOCK never move wallet funds.
        if decision != "ALLOW":
            db.commit()

            await publish_dashboard_event({
                "type": "transaction",
                "transaction_id": transaction_id,
                "decision": decision,
                "risk_score": result.risk_score,
                "time": datetime.utcnow().isoformat()
            })

            return {
                "success": False,
                "transaction_id": transaction_id,
                "decision": decision,
                "risk_score": result.risk_score,
                "message": (
                    "Transaction held for manual review."
                    if decision == "REVIEW"
                    else "Transaction blocked by fraud detection."
                ),
                "recommendation": result.recommendation,
                "balance": round(sender.balance, 2)
            }

        # Only ALLOW transactions reach this point.
        sender.balance -= data.amount

        if receiver:
            receiver.balance = float(receiver.balance or 0)
            receiver.balance += data.amount

        db.commit()
        db.refresh(sender)

        log_activity(
            db,
            sender.username,
            "Wallet Transfer",
            (
                f"Sent K{data.amount:.2f} to {recipient_phone} "
                f"| Ref: {transaction_id}"
            )
        )

        await publish_dashboard_event({
            "type": "transaction",
            "transaction_id": transaction_id,
            "decision": decision,
            "risk_score": result.risk_score,
            "time": datetime.utcnow().isoformat()
        })

        return {
            "success": True,
            "message": "Transfer successful.",
            "transaction_id": transaction_id,
            "decision": decision,
            "risk_score": result.risk_score,
            "amount": data.amount,
            "recipient": recipient_phone,
            "new_balance": round(sender.balance, 2),
            "recommendation": result.recommendation
        }

    except HTTPException:
        db.rollback()
        raise

    except Exception:
        db.rollback()
        logger.exception("Wallet transfer failed.")

        raise HTTPException(
            status_code=500,
            detail="Transfer could not be completed."
        )


# ============================================================
# DEMO WALLET TOP-UP
# ============================================================

@app.post("/api/v1/user/topup")
async def topup_balance(
    request: Request,
    data: TopUpRequest,
    db: Session = Depends(get_db)
):

    current = require_user(request)

    user = db.query(User).filter(
        User.id == current["id"]
    ).first()

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found."
        )

    transaction_id = (
        f"TOPUP-{datetime.utcnow().strftime('%Y%m%d')}-"
        f"{uuid.uuid4().hex[:10].upper()}"
    )

    try:
        # This is a simulated wallet top-up.
        # It is NOT proof of a real Airtel Money payment.
        count_1h, count_24h, amount_24h = calculate_sender_activity(
            db,
            "DEMO-AGENT"
        )

        transaction_request = TransactionRequest(
            transaction_id=transaction_id,
            amount=data.amount,
            currency="ZMW",
            sender_msisdn="DEMO-AGENT",
            receiver_msisdn=user.phone,
            sender_device_id="USER-APP",
            receiver_is_new=False,
            channel="demo_wallet_topup",
            timestamp=datetime.utcnow(),
            sender_tx_count_last_1h=count_1h,
            sender_tx_count_last_24h=count_24h,
            sender_total_amount_last_24h=amount_24h,
            is_international=False,
            beneficiary_risk_score=0.0
        )

        result = detector.analyze(transaction_request)

        db_transaction = create_transaction_record(
            transaction=transaction_request,
            result=result,
            transaction_type="Demo Wallet Top-up",
            location="Zambia",
            device_id="USER-APP"
        )

        db.add(db_transaction)

        decision = enum_value(result.decision)

        if decision != "ALLOW":
            db.commit()

            await publish_dashboard_event({
                "type": "transaction",
                "transaction_id": transaction_id,
                "decision": decision,
                "risk_score": result.risk_score,
                "time": datetime.utcnow().isoformat()
            })

            return {
                "success": False,
                "transaction_id": transaction_id,
                "decision": decision,
                "message": "Top-up held by fraud detection.",
                "recommendation": result.recommendation,
                "new_balance": float(user.balance or 0)
            }

        user.balance = float(user.balance or 0) + data.amount

        db.commit()
        db.refresh(user)

        log_activity(
            db,
            user.username,
            "Demo Wallet Top-up",
            (
                f"Simulated top-up K{data.amount:.2f} "
                f"| Balance: K{user.balance:.2f}"
            )
        )

        await publish_dashboard_event({
            "type": "transaction",
            "transaction_id": transaction_id,
            "decision": decision,
            "risk_score": result.risk_score,
            "time": datetime.utcnow().isoformat()
        })

        return {
            "success": True,
            "simulated": True,
            "message": (
                "Demo top-up successful. No real Airtel payment "
                "was processed or verified."
            ),
            "transaction_id": transaction_id,
            "amount": data.amount,
            "new_balance": round(user.balance, 2)
        }

    except Exception:
        db.rollback()
        logger.exception("Wallet top-up failed.")

        raise HTTPException(
            status_code=500,
            detail="Top-up could not be completed."
        )


# ============================================================
# APPLICATION STARTUP
# ============================================================

@app.on_event("startup")
async def startup_event():
    logger.info("THE GUARDIAN backend started.")
    logger.info("Database: %s", engine.dialect.name)


@app.on_event("shutdown")
async def shutdown_event():
    logger.info("THE GUARDIAN backend shutting down.")
