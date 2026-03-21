"""
Lumina Ingegno V2 - Backend API
Configurato per Railway + MongoDB Atlas
Include: Auth, Libri, IAP, Push Notifications (Firebase), Admin Panel, AI Tools
"""

import os
import secrets
import string
import logging
import hashlib
import uuid
from datetime import datetime, timedelta
from typing import Optional, List
from pathlib import Path

from fastapi import FastAPI, HTTPException, Depends, Form, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr
from motor.motor_asyncio import AsyncIOMotorClient
from jose import JWTError, jwt
import resend
import httpx
from dotenv import load_dotenv

# Firebase Admin SDK
import firebase_admin
from firebase_admin import credentials, messaging

# Google Auth per conversione token APNs -> FCM
from google.oauth2 import service_account
from google.auth.transport.requests import Request as GoogleAuthRequest

# OpenAI Integration
from openai import OpenAI

# PDF to Image conversion
import pymupdf
import io
import base64
import tempfile
from fastapi.responses import Response

# Load environment variables
load_dotenv()

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
MONGO_URL = os.getenv("MONGO_URL")
DB_NAME = os.getenv("DB_NAME", "lumina_v2")
SECRET_KEY = os.getenv("SECRET_KEY", "fallback-secret-key")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "raffaeleingegno.com@gmail.com")
RESEND_API_KEY = os.getenv("RESEND_API_KEY")
EMERGENT_LLM_KEY = os.getenv("EMERGENT_LLM_KEY")

# Uploads directory - usa path relativo per compatibilità Railway
BASE_DIR = Path(__file__).resolve().parent
UPLOADS_DIR = BASE_DIR / "uploads"
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)

# JWT Config
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_DAYS = 30

# Security
security = HTTPBearer(auto_error=False)

# Initialize Resend
if RESEND_API_KEY:
    resend.api_key = RESEND_API_KEY

# Initialize Firebase Admin SDK
FIREBASE_CREDS_PATH = Path(__file__).parent / "firebase-credentials.json"
firebase_initialized = False
firebase_credentials_dict = None

if FIREBASE_CREDS_PATH.exists():
    try:
        cred = credentials.Certificate(str(FIREBASE_CREDS_PATH))
        firebase_admin.initialize_app(cred)
        firebase_initialized = True
        logger.info("Firebase Admin SDK initialized successfully")
        
        # Carica le credenziali per la conversione APNs -> FCM
        import json
        with open(FIREBASE_CREDS_PATH) as f:
            firebase_credentials_dict = json.load(f)
    except Exception as e:
        logger.error(f"Failed to initialize Firebase: {e}")
else:
    logger.warning(f"Firebase credentials not found at {FIREBASE_CREDS_PATH}")

# Configurazione per la conversione APNs token -> FCM token
IOS_BUNDLE_ID = "com.ringegno.luminaingegno"
# APNS_SANDBOX: "true" per development locale, "false" per TestFlight e App Store
# IMPORTANTE: TestFlight usa l'ambiente PRODUCTION, non sandbox!
APNS_SANDBOX = os.getenv("APNS_SANDBOX", "false").lower() == "true"

# =============================================================================
# APNs DIRECT - Configurazione per invio diretto ad Apple Push Notification Service
# =============================================================================
APNS_KEY_ID = os.getenv("APNS_KEY_ID", "4WWUDFPP3U")
APNS_TEAM_ID = os.getenv("APNS_TEAM_ID", "AS2H2X2A7B")
APNS_AUTH_KEY = os.getenv("APNS_AUTH_KEY", """-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQg7LpOa713J+9z2qkB
Nm6dW4PgGuU4Ss3GYBLKDKGlPg2gCgYIKoZIzj0DAQehRANCAAQSfAdBR6Wj/A2d
95OBwiKzBmeL9OCPfZQRD1PpPYj2mMknb0lk4rKit49Hr8PK36gNK4tGWyqzGL5g
SEpX9KIq
-----END PRIVATE KEY-----""")

# Endpoint APNs
APNS_HOST_SANDBOX = "api.sandbox.push.apple.com"
APNS_HOST_PRODUCTION = "api.push.apple.com"

def get_apns_host():
    """Restituisce l'host APNs corretto in base all'ambiente"""
    return APNS_HOST_SANDBOX if APNS_SANDBOX else APNS_HOST_PRODUCTION

def create_apns_jwt_token():
    """Crea un JWT token per autenticarsi con APNs"""
    import time
    
    headers = {
        "alg": "ES256",
        "kid": APNS_KEY_ID,
    }
    
    payload = {
        "iss": APNS_TEAM_ID,
        "iat": int(time.time()),
    }
    
    # Usa PyJWT per firmare con ES256
    import jwt as pyjwt
    token = pyjwt.encode(payload, APNS_AUTH_KEY, algorithm="ES256", headers=headers)
    return token

async def send_apns_push(device_token: str, title: str, body: str, data: dict = None) -> dict:
    """
    Invia notifica push direttamente ad APNs (Apple Push Notification Service).
    Questo è il metodo più affidabile per iOS.
    """
    import httpx
    import json
    
    try:
        # Crea JWT per autenticazione
        jwt_token = create_apns_jwt_token()
        
        # Prepara il payload APNs
        apns_payload = {
            "aps": {
                "alert": {
                    "title": title,
                    "body": body,
                },
                "sound": "default",
                "badge": 1,
            }
        }
        
        # Aggiungi dati custom se presenti
        if data:
            apns_payload["data"] = data
        
        # Headers richiesti da APNs
        headers = {
            "authorization": f"bearer {jwt_token}",
            "apns-topic": IOS_BUNDLE_ID,
            "apns-push-type": "alert",
            "apns-priority": "10",
            "apns-expiration": "0",
        }
        
        # URL endpoint APNs
        host = get_apns_host()
        url = f"https://{host}/3/device/{device_token}"
        
        logger.info(f"Sending APNs push to {device_token[:20]}... via {host}")
        
        # Invia richiesta HTTP/2 ad APNs
        async with httpx.AsyncClient(http2=True) as client:
            response = await client.post(
                url,
                headers=headers,
                json=apns_payload,
                timeout=30.0
            )
        
        if response.status_code == 200:
            logger.info(f"APNs push sent successfully to {device_token[:20]}...")
            return {"success": True, "message_id": response.headers.get("apns-id", "ok")}
        else:
            error_body = response.text
            logger.error(f"APNs push failed: {response.status_code} - {error_body}")
            
            # Gestisci token non validi
            if response.status_code == 410 or "BadDeviceToken" in error_body or "Unregistered" in error_body:
                return {"success": False, "error": "Token unregistered"}
            
            return {"success": False, "error": f"APNs error {response.status_code}: {error_body}"}
            
    except Exception as e:
        logger.error(f"APNs push exception: {e}")
        return {"success": False, "error": str(e)}

async def convert_apns_to_fcm(apns_token: str) -> str | None:
    """
    Converte un token APNs (iOS) in un token FCM registration.
    Usa l'API Instance ID di Firebase con autenticazione OAuth2.
    """
    if not firebase_credentials_dict:
        logger.error("Firebase credentials not available for APNs conversion")
        return None
    
    try:
        import requests
        
        # Crea credenziali OAuth2 dal service account
        scopes = ['https://www.googleapis.com/auth/firebase.messaging']
        credentials_sa = service_account.Credentials.from_service_account_info(
            firebase_credentials_dict,
            scopes=scopes
        )
        
        # Ottieni il token OAuth2
        credentials_sa.refresh(GoogleAuthRequest())
        access_token = credentials_sa.token
        
        # Chiama l'API Instance ID per importare il token APNs
        url = "https://iid.googleapis.com/iid/v1:batchImport"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "access_token_auth": "true"
        }
        payload = {
            "application": IOS_BUNDLE_ID,
            "sandbox": APNS_SANDBOX,
            "apns_tokens": [apns_token]
        }
        
        response = requests.post(url, json=payload, headers=headers, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            results = data.get("results", [])
            if results and results[0].get("registration_token"):
                fcm_token = results[0]["registration_token"]
                logger.info(f"Successfully converted APNs token to FCM token")
                return fcm_token
            elif results and results[0].get("status"):
                logger.warning(f"APNs conversion failed: {results[0].get('status')}")
                return None
        else:
            logger.error(f"APNs conversion API error: {response.status_code} - {response.text}")
            return None
            
    except Exception as e:
        logger.error(f"Error converting APNs to FCM: {e}")
        return None

# MongoDB connection
client = AsyncIOMotorClient(MONGO_URL)
db = client[DB_NAME]

# FastAPI app
app = FastAPI(title="Lumina Ingegno V2 API")

# Monta la cartella uploads per servire file statici (banner, ecc.)
app.mount("/uploads", StaticFiles(directory=str(UPLOADS_DIR)), name="uploads")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =============================================================================
# IAP PRODUCT IDs (Google Play)
# =============================================================================
IAP_PRODUCTS = {
    "books_full_access": {"type": "inapp", "name": "Accesso Completo Libri"},
    "book_single": {"type": "inapp", "name": "Libro Singolo"},
}

IAP_SUBSCRIPTIONS = {
    "tutorials-monthly": {"type": "subs", "name": "Tutorial Mensile", "duration_days": 30},
    "tutorials-yearly": {"type": "subs", "name": "Tutorial Annuale", "duration_days": 365},
}

# =============================================================================
# MODELS
# =============================================================================

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    name: str
    referral_used: Optional[str] = None  # Codice referral usato in registrazione

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class VerifyCode(BaseModel):
    email: EmailStr
    code: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: dict

class PushNotification(BaseModel):
    title: str
    body: str

class BookCreate(BaseModel):
    title: str
    description: str
    cover_url: str
    pdf_url: str
    price: float = 0
    product_id: str = "book_single"
    sort_order: int = 1

class PurchaseVerify(BaseModel):
    product_id: str
    purchase_token: str
    platform: str = "android"

class TutorialCreate(BaseModel):
    title: str
    description: str = ""
    image_url: str = ""
    url: str
    is_free: bool = False

class HomeBadgeUpdate(BaseModel):
    active: bool = False
    text: str = ""
    link: str = ""
    auto_expire_24h: bool = False

class HomeBannerCreate(BaseModel):
    image_base64: str  # Immagine in base64
    link_type: str = "none"  # none, internal, external
    link_url: str = ""  # URL interno o esterno
    order: int = 0  # Ordine nel carousel
    active: bool = True

class HomeBannerUpdate(BaseModel):
    image_base64: Optional[str] = None
    link_type: Optional[str] = None
    link_url: Optional[str] = None
    order: Optional[int] = None
    active: Optional[bool] = None

class ScheduledNotification(BaseModel):
    title: str
    body: str
    scheduled_at: str  # ISO format datetime string (es. "2026-03-25T09:00:00")

# =============================================================================
# SCHEDULED NOTIFICATIONS - APScheduler
# =============================================================================
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

scheduler = AsyncIOScheduler()

async def check_and_send_scheduled_notifications():
    """
    Controlla ogni minuto se ci sono notifiche programmate da inviare.
    Invia SOLO a utenti iOS via APNs diretto.
    """
    try:
        now = datetime.utcnow()
        
        # Trova notifiche programmate che devono essere inviate
        pending = await db.scheduled_notifications.find({
            "scheduled_at": {"$lte": now},
            "sent": False
        }).to_list(100)
        
        for notif in pending:
            logger.info(f"Sending scheduled notification: {notif['title']}")
            
            # Invia la notifica SOLO a utenti iOS
            users = await db.users.find({
                "push_token": {"$exists": True, "$ne": None},
                "push_platform": "ios"
            }).to_list(1000)
            
            sent_ios = 0
            errors = 0
            
            for user in users:
                try:
                    apns_token = user.get("push_token_original", user.get("push_token"))
                    if apns_token:
                        result = await send_apns_push(apns_token, notif["title"], notif["body"])
                        if result.get("success"):
                            sent_ios += 1
                        else:
                            errors += 1
                            logger.error(f"Scheduled push failed for {user['email']}: {result.get('error')}")
                except Exception as e:
                    logger.error(f"Error sending scheduled push to {user.get('email')}: {e}")
                    errors += 1
            
            # Segna come inviata
            await db.scheduled_notifications.update_one(
                {"_id": notif["_id"]},
                {"$set": {
                    "sent": True,
                    "sent_at": datetime.utcnow(),
                    "result": {
                        "sent_ios": sent_ios,
                        "errors": errors
                    }
                }}
            )
            
            logger.info(f"Scheduled notification sent: {sent_ios} iOS, {errors} errors")
            
    except Exception as e:
        logger.error(f"Error checking scheduled notifications: {e}")

@app.on_event("startup")
async def start_scheduler():
    """Avvia lo scheduler all'avvio dell'app"""
    scheduler.add_job(
        check_and_send_scheduled_notifications,
        IntervalTrigger(minutes=1),
        id="check_scheduled_notifications",
        replace_existing=True
    )
    scheduler.start()
    logger.info("Scheduler started - checking notifications every minute")

@app.on_event("shutdown")
async def shutdown_scheduler():
    """Ferma lo scheduler alla chiusura dell'app"""
    scheduler.shutdown()
    logger.info("Scheduler stopped")

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def generate_verification_code() -> str:
    return ''.join(secrets.choice(string.digits) for _ in range(6))

def generate_referral_code() -> str:
    letters = ''.join(secrets.choice(string.ascii_uppercase) for _ in range(2))
    numbers = ''.join(secrets.choice(string.digits) for _ in range(6))
    return letters + numbers

def generate_user_id() -> str:
    return f"user_{secrets.token_hex(8)}"

def generate_book_id() -> str:
    return f"book_{secrets.token_hex(6)}"

def hash_password(password: str) -> str:
    """Hash password using SHA256 with salt"""
    salt = SECRET_KEY[:16]
    return hashlib.sha256(f"{salt}{password}".encode()).hexdigest()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against hash"""
    return hash_password(plain_password) == hashed_password

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(days=ACCESS_TOKEN_EXPIRE_DAYS))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials:
        raise HTTPException(status_code=401, detail="Non autenticato")
    
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Token non valido")
        
        user = await db.users.find_one({"user_id": user_id})
        if not user:
            raise HTTPException(status_code=401, detail="Utente non trovato")
        
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Token non valido")

async def get_admin_user(current_user: dict = Depends(get_current_user)):
    if not current_user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Accesso negato. Solo admin.")
    return current_user

def user_to_response(user: dict) -> dict:
    return {
        "user_id": user.get("user_id"),
        "email": user.get("email"),
        "name": user.get("name"),
        "referral_code": user.get("referral_code"),
        "is_admin": user.get("is_admin", False),
        "plan": user.get("plan", "free"),
        "purchases": user.get("purchases", []),
        "tutorials_access_expires": user.get("tutorials_access_expires"),
        "created_at": user.get("created_at"),
    }

# =============================================================================
# EMAIL FUNCTIONS
# =============================================================================

async def send_verification_email(email: str, code: str, name: str):
    if not RESEND_API_KEY:
        logger.warning("RESEND_API_KEY not set, skipping email")
        return
    
    try:
        logger.info(f"Attempting to send verification email to {email}")
        result = resend.Emails.send({
            "from": "Lumina Ingegno <noreply@raffaeleingegno.com>",
            "to": [email],
            "subject": "Codice di verifica - Lumina Ingegno",
            "html": f"""
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h2 style="color: #cc3333;">Ciao {name}!</h2>
                <p>Il tuo codice di verifica è:</p>
                <h1 style="font-size: 36px; letter-spacing: 8px; color: #333; background: #f5f5f5; padding: 20px; text-align: center;">{code}</h1>
                <p>Inserisci questo codice nell'app per completare la registrazione.</p>
                <p style="color: #888; font-size: 12px;">Il codice scade tra 10 minuti.</p>
            </div>
            """
        })
        logger.info(f"Verification email sent to {email}, result: {result}")
    except Exception as e:
        logger.error(f"Error sending email to {email}: {str(e)}")

# =============================================================================
# PUSH NOTIFICATIONS (Firebase Cloud Messaging)
# =============================================================================

async def send_fcm_push(token: str, title: str, body: str, data: dict = None) -> dict:
    """Send push notification via Firebase Cloud Messaging"""
    if not firebase_initialized:
        logger.warning("Firebase not initialized - skipping push")
        return {"success": False, "error": "Firebase not initialized"}
    
    try:
        message = messaging.Message(
            notification=messaging.Notification(
                title=title,
                body=body,
            ),
            data=data or {},
            token=token,
            android=messaging.AndroidConfig(
                priority="high",
                notification=messaging.AndroidNotification(
                    icon="notification_icon",
                    color="#cc3333",
                    sound="default",
                ),
            ),
            apns=messaging.APNSConfig(
                headers={
                    "apns-priority": "10",
                    "apns-push-type": "alert",
                },
                payload=messaging.APNSPayload(
                    aps=messaging.Aps(
                        alert=messaging.ApsAlert(
                            title=title,
                            body=body,
                        ),
                        sound="default",
                        badge=1,
                    ),
                ),
            ),
        )
        
        response = messaging.send(message)
        logger.info(f"FCM push sent successfully: {response}")
        return {"success": True, "message_id": response}
    except messaging.UnregisteredError:
        logger.warning(f"FCM token unregistered: {token[:20]}...")
        return {"success": False, "error": "Token unregistered"}
    except Exception as e:
        logger.error(f"FCM push error: {e}")
        return {"success": False, "error": str(e)}

# Legacy function for backward compatibility
async def send_expo_push(token: str, title: str, body: str, data: dict = None):
    """Legacy Expo push - now routes to FCM"""
    return await send_fcm_push(token, title, body, data)

# =============================================================================
# API ENDPOINTS
# =============================================================================

@app.get("/api/health")
async def health_check():
    return {"status": "healthy", "message": "Lumina Ingegno V2 API is running"}

# Endpoint temporaneo per creare utente test (da rimuovere dopo)
@app.post("/api/admin/create-test-user")
async def create_test_user(secret: str, email: str, password: str, name: str, is_admin: bool = False):
    if secret != "lumina-secret-2025":
        raise HTTPException(status_code=403, detail="Non autorizzato")
    
    existing = await db.users.find_one({"email": email.lower()})
    if existing:
        raise HTTPException(status_code=400, detail="Email già esistente")
    
    user_id = generate_user_id()
    user = {
        "user_id": user_id,
        "email": email.lower(),
        "password_hash": hash_password(password),
        "name": name,
        "referral_code": generate_referral_code(),
        "is_admin": is_admin,
        "is_verified": True,
        "plan": "free",
        "purchases": [],
        "created_at": datetime.utcnow()
    }
    await db.users.insert_one(user)
    return {"message": "Utente creato", "user_id": user_id, "email": email}

# -----------------------------------------------------------------------------
# AUTH ENDPOINTS
# -----------------------------------------------------------------------------

@app.post("/api/auth/register")
async def register(user: UserCreate):
    existing = await db.users.find_one({"email": user.email.lower()})
    if existing and existing.get("is_verified"):
        raise HTTPException(status_code=400, detail="Email già registrata")
    
    # Verifica codice referral se fornito
    referrer = None
    if user.referral_used:
        referrer = await db.users.find_one({"referral_code": user.referral_used.upper()})
        if not referrer:
            raise HTTPException(status_code=400, detail="Codice referral non valido")
    
    code = generate_verification_code()
    expires_at = datetime.utcnow() + timedelta(minutes=10)
    
    await db.pending_registrations.update_one(
        {"email": user.email.lower()},
        {
            "$set": {
                "email": user.email.lower(),
                "password_hash": hash_password(user.password),
                "name": user.name,
                "referral_used": user.referral_used.upper() if user.referral_used else None,
                "verification_code": code,
                "code_expires_at": expires_at,
                "created_at": datetime.utcnow()
            }
        },
        upsert=True
    )
    
    await send_verification_email(user.email, code, user.name)
    
    return {"message": "Codice di verifica inviato", "email": user.email}

@app.post("/api/auth/verify", response_model=TokenResponse)
async def verify_registration(data: VerifyCode):
    pending = await db.pending_registrations.find_one({"email": data.email.lower()})
    if not pending:
        raise HTTPException(status_code=400, detail="Registrazione non trovata")
    
    if pending.get("verification_code") != data.code:
        raise HTTPException(status_code=400, detail="Codice non valido")
    
    if datetime.utcnow() > pending.get("code_expires_at", datetime.utcnow()):
        raise HTTPException(status_code=400, detail="Codice scaduto")
    
    user_id = generate_user_id()
    is_admin = data.email.lower() == ADMIN_EMAIL.lower()
    
    # Gestione bonus referral
    referral_used = pending.get("referral_used")
    tutorials_access_expires = None
    referral_bonus_received = False
    
    if referral_used:
        # Trova chi ha condiviso il codice
        referrer = await db.users.find_one({"referral_code": referral_used})
        if referrer:
            # Controlla se il referrer ha già ricevuto il bonus (max 1 volta)
            if not referrer.get("referral_bonus_given"):
                # Dai 1 mese di tutorial gratis al referrer
                referrer_expires = referrer.get("tutorials_access_expires") or datetime.utcnow()
                if referrer_expires < datetime.utcnow():
                    referrer_expires = datetime.utcnow()
                new_referrer_expires = referrer_expires + timedelta(days=30)
                
                await db.users.update_one(
                    {"user_id": referrer["user_id"]},
                    {"$set": {
                        "tutorials_access_expires": new_referrer_expires,
                        "referral_bonus_given": True
                    }}
                )
                logger.info(f"Referral bonus given to {referrer['email']}")
            
            # Dai 1 mese di tutorial gratis al nuovo utente
            tutorials_access_expires = datetime.utcnow() + timedelta(days=30)
            referral_bonus_received = True
            logger.info(f"Referral bonus received by {data.email}")
    
    user = {
        "user_id": user_id,
        "email": data.email.lower(),
        "password_hash": pending.get("password_hash"),
        "name": pending.get("name"),
        "referral_code": generate_referral_code(),
        "referral_used": referral_used,
        "referral_bonus_received": referral_bonus_received,
        "referral_bonus_given": False,
        "is_admin": is_admin,
        "is_verified": True,
        "plan": "free",
        "purchases": [],
        "tutorials_access_expires": tutorials_access_expires,
        "created_at": datetime.utcnow()
    }
    
    await db.users.insert_one(user)
    await db.pending_registrations.delete_one({"email": data.email.lower()})
    
    token = create_access_token({"sub": user_id})
    logger.info(f"User registered: {data.email}")
    
    return TokenResponse(access_token=token, user=user_to_response(user))

@app.post("/api/auth/login", response_model=TokenResponse)
async def login(data: UserLogin):
    user = await db.users.find_one({"email": data.email.lower()})
    
    if not user:
        raise HTTPException(status_code=401, detail="Email o password non validi")
    
    if not verify_password(data.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Email o password non validi")
    
    if not user.get("is_verified"):
        raise HTTPException(status_code=401, detail="Account non verificato")
    
    token = create_access_token({"sub": user["user_id"]})
    logger.info(f"User logged in: {data.email}")
    
    return TokenResponse(access_token=token, user=user_to_response(user))

# -----------------------------------------------------------------------------
# PASSWORD RECOVERY
# -----------------------------------------------------------------------------

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    email: EmailStr
    code: str
    new_password: str

@app.post("/api/auth/forgot-password")
async def forgot_password(data: ForgotPasswordRequest):
    """Invia codice di recupero password via email"""
    user = await db.users.find_one({"email": data.email.lower()})
    
    if not user:
        # Per sicurezza non riveliamo se l'email esiste o no
        return {"message": "Se l'email esiste, riceverai un codice di recupero"}
    
    code = generate_verification_code()
    expires_at = datetime.utcnow() + timedelta(minutes=15)
    
    await db.password_resets.update_one(
        {"email": data.email.lower()},
        {
            "$set": {
                "email": data.email.lower(),
                "code": code,
                "expires_at": expires_at,
                "created_at": datetime.utcnow()
            }
        },
        upsert=True
    )
    
    # Invia email con codice
    try:
        if RESEND_API_KEY:
            result = resend.Emails.send({
                "from": "Lumina Ingegno <noreply@raffaeleingegno.com>",
                "to": data.email,
                "subject": "Recupero Password - Lumina Ingegno",
                "html": f"""
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                    <h2 style="color: #cc3333;">Recupero Password</h2>
                    <p>Ciao {user.get('name', '')},</p>
                    <p>Hai richiesto di reimpostare la tua password.</p>
                    <p>Il tuo codice di recupero è:</p>
                    <div style="background: #f5f5f5; padding: 20px; text-align: center; font-size: 32px; font-weight: bold; letter-spacing: 5px; margin: 20px 0;">
                        {code}
                    </div>
                    <p>Il codice scade tra 15 minuti.</p>
                    <p>Se non hai richiesto tu il recupero password, ignora questa email.</p>
                    <p style="color: #888; font-size: 12px;">Team Lumina Ingegno</p>
                </div>
                """
            })
            logger.info(f"Password reset email sent to {data.email}, response: {result}")
    except Exception as e:
        logger.error(f"Error sending reset email: {e}")
    except Exception as e:
        logger.error(f"Error sending reset email: {e}")
    
    return {"message": "Se l'email esiste, riceverai un codice di recupero"}

@app.post("/api/auth/reset-password")
async def reset_password(data: ResetPasswordRequest):
    """Reimposta la password usando il codice di recupero"""
    reset_request = await db.password_resets.find_one({"email": data.email.lower()})
    
    if not reset_request:
        raise HTTPException(status_code=400, detail="Richiesta di recupero non trovata")
    
    if reset_request.get("code") != data.code:
        raise HTTPException(status_code=400, detail="Codice non valido")
    
    if datetime.utcnow() > reset_request.get("expires_at", datetime.utcnow()):
        raise HTTPException(status_code=400, detail="Codice scaduto")
    
    # Aggiorna la password dell'utente (mantiene tutti gli altri dati del profilo)
    result = await db.users.update_one(
        {"email": data.email.lower()},
        {"$set": {"password_hash": hash_password(data.new_password)}}
    )
    
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Utente non trovato")
    
    # Elimina la richiesta di reset
    await db.password_resets.delete_one({"email": data.email.lower()})
    
    logger.info(f"Password reset successful for {data.email}")
    
    return {"message": "Password reimpostata con successo"}

@app.get("/api/auth/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    return user_to_response(current_user)

@app.delete("/api/auth/delete-account")
async def delete_account(current_user: dict = Depends(get_current_user)):
    """Elimina completamente l'account e tutti i dati dell'utente"""
    user_id = current_user["user_id"]
    email = current_user["email"]
    
    # Elimina tutti i dati dell'utente
    await db.users.delete_one({"user_id": user_id})
    await db.push_tokens.delete_many({"user_id": user_id})
    await db.purchases.delete_many({"user_id": user_id})
    
    logger.info(f"Account deleted: {email}")
    
    return {"message": "Account eliminato con successo"}

# -----------------------------------------------------------------------------
# ADMIN PASSWORD RESET (one-time setup endpoint)
# -----------------------------------------------------------------------------

@app.post("/api/admin/reset-password")
async def reset_admin_password(email: str = Form(...), password: str = Form(...)):
    """Reset password for admin user - use once then remove"""
    if email.lower() != ADMIN_EMAIL.lower():
        raise HTTPException(status_code=403, detail="Solo per admin")
    
    result = await db.users.update_one(
        {"email": email.lower()},
        {"$set": {"password_hash": hash_password(password), "is_admin": True, "is_verified": True}}
    )
    
    if result.matched_count == 0:
        # Create admin user if not exists
        user = {
            "user_id": generate_user_id(),
            "email": email.lower(),
            "password_hash": hash_password(password),
            "name": "Admin",
            "referral_code": generate_referral_code(),
            "is_admin": True,
            "is_verified": True,
            "plan": "free",
            "purchases": [],
            "created_at": datetime.utcnow()
        }
        await db.users.insert_one(user)
        logger.info(f"Admin user created: {email}")
        return {"message": "Admin creato"}
    
    logger.info(f"Admin password reset: {email}")
    return {"message": "Password aggiornata"}

# -----------------------------------------------------------------------------
# PUSH TOKEN ENDPOINTS
# -----------------------------------------------------------------------------

class PushTokenRequest(BaseModel):
    token: str
    platform: str = "android"

@app.post("/api/push-token")
async def register_push_token(
    data: PushTokenRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Registra il push token per l'utente.
    - iOS: salva il token APNs direttamente (per invio diretto ad Apple)
    - Android: salva il token FCM
    """
    token = data.token
    platform = data.platform
    
    # Log per debug
    logger.info(f"Push token received for {current_user['email']} (platform: {platform}, token: {token[:30]}...)")
    
    # Salva il token - per iOS usiamo APNs diretto, niente conversione
    await db.users.update_one(
        {"user_id": current_user["user_id"]},
        {"$set": {
            "push_token": token,
            "push_token_original": token,  # Per iOS APNs diretto
            "push_platform": platform
        }}
    )
    
    logger.info(f"Push token registered for {current_user['email']} (platform: {platform})")
    return {"message": "Token registrato", "platform": platform}

# -----------------------------------------------------------------------------
# BOOKS ENDPOINTS
# -----------------------------------------------------------------------------

@app.get("/api/books")
async def get_books(current_user: dict = Depends(get_current_user)):
    """Ottieni lista libri con stato accesso, ordinati per sort_order"""
    books = await db.books.find().sort("sort_order", 1).to_list(100)
    user_purchases = current_user.get("purchases", [])
    has_full_access = "books_full_access" in user_purchases
    is_admin = current_user.get("is_admin", False)
    
    result = []
    for book in books:
        # Verifica accesso tramite book_id o product_id
        # L'ADMIN ha sempre accesso a tutti i libri
        book_id = book.get("book_id")
        product_id = book.get("product_id", "")
        has_access = is_admin or has_full_access or book_id in user_purchases or product_id in user_purchases
        
        book_data = {
            "book_id": book_id,
            "title": book.get("title"),
            "description": book.get("description"),
            "cover_url": book.get("cover_url"),
            "price": book.get("price", 0),
            "sort_order": book.get("sort_order", 999),
            "has_access": has_access,
        }
        if has_access:
            book_data["pdf_url"] = book.get("pdf_url")
        result.append(book_data)
    
    return result

@app.get("/api/books/{book_id}")
async def get_book(book_id: str, current_user: dict = Depends(get_current_user)):
    """Ottieni singolo libro"""
    book = await db.books.find_one({"book_id": book_id})
    if not book:
        raise HTTPException(status_code=404, detail="Libro non trovato")
    
    user_purchases = current_user.get("purchases", [])
    has_full_access = "books_full_access" in user_purchases
    is_admin = current_user.get("is_admin", False)
    product_id = book.get("product_id", "")
    has_access = is_admin or has_full_access or book_id in user_purchases or product_id in user_purchases
    
    result = {
        "book_id": book.get("book_id"),
        "title": book.get("title"),
        "description": book.get("description"),
        "cover_url": book.get("cover_url"),
        "price": book.get("price", 0),
        "has_access": has_access,
    }
    if has_access:
        result["pdf_url"] = book.get("pdf_url")
    
    return result

@app.get("/api/books/{book_id}/pdf")
async def get_book_pdf(book_id: str, current_user: dict = Depends(get_current_user)):
    """Ottieni URL del PDF per un libro acquistato"""
    # Trova il libro
    book = await db.books.find_one({"book_id": book_id})
    if not book:
        raise HTTPException(status_code=404, detail="Libro non trovato")
    
    # Verifica accesso: admin sempre, oppure controlla purchases dell'utente
    user_purchases = current_user.get("purchases", [])
    has_full_access = "books_full_access" in user_purchases
    is_admin = current_user.get("is_admin", False)
    product_id = book.get("product_id", "")
    
    has_access = is_admin or has_full_access or book_id in user_purchases or product_id in user_purchases
    
    if not has_access:
        raise HTTPException(status_code=403, detail="Libro non acquistato")
    
    pdf_url = book.get("pdf_url")
    if not pdf_url:
        raise HTTPException(status_code=404, detail="PDF non disponibile")
    
    return {"pdf_url": pdf_url, "title": book.get("title", "Libro")}


# Endpoint per inizializzare/aggiornare i libri con i link PDF corretti (solo admin)
@app.post("/api/admin/init-books")
async def init_books(current_user: dict = Depends(get_current_user)):
    """Inizializza o aggiorna i libri con i link PDF corretti - SOLO ADMIN"""
    if not current_user.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Solo admin")
    
    books_data = [
        {
            "book_id": "lux",
            "title": "LUX",
            "description": "Il primo libro della serie Lumina",
            "cover_url": "https://i.imgur.com/placeholder_lux.jpg",
            "pdf_url": "https://drive.google.com/file/d/14-U0-kdh7-Xir-RX-x8mO2lVbjMU6m6j/view?usp=drive_link",
            "product_id": "book_lux",
            "price": 9.99,
            "sort_order": 1,
        },
        {
            "book_id": "imago",
            "title": "IMAGO",
            "description": "Il secondo libro della serie Lumina",
            "cover_url": "https://i.imgur.com/placeholder_imago.jpg",
            "pdf_url": "https://drive.google.com/file/d/1HlVbNCEVs4eHoSql8w2tVQHZb9_efuyC/view?usp=drive_link",
            "product_id": "book_imago",
            "price": 9.99,
            "sort_order": 2,
        },
        {
            "book_id": "omnia",
            "title": "OMNIA",
            "description": "Il terzo libro della serie Lumina",
            "cover_url": "https://i.imgur.com/placeholder_omnia.jpg",
            "pdf_url": "https://drive.google.com/file/d/13INl4_nWvTqG386QVZMEhKBWB7Qjdm58/view?usp=drive_link",
            "product_id": "book_omnia",
            "price": 9.99,
            "sort_order": 3,
        },
        {
            "book_id": "tabula",
            "title": "TABULA",
            "description": "Il quarto libro della serie Lumina",
            "cover_url": "https://i.imgur.com/placeholder_tabula.jpg",
            "pdf_url": "https://drive.google.com/file/d/11fc3yD4bx2Hq5JZ--rutMMF8t4wHCmdO/view?usp=drive_link",
            "product_id": "book_tabula",
            "price": 9.99,
            "sort_order": 4,
        },
        {
            "book_id": "lux2",
            "title": "LUX2",
            "description": "Il quinto libro della serie Lumina",
            "cover_url": "https://i.imgur.com/placeholder_lux2.jpg",
            "pdf_url": "https://drive.google.com/file/d/1OmriITXScZwUAH1BY4ZYxYdTBEMefCZh/view?usp=drive_link",
            "product_id": "book_lux2",
            "price": 9.99,
            "sort_order": 5,
        },
    ]
    
    updated = 0
    created = 0
    
    for book in books_data:
        existing = await db.books.find_one({"book_id": book["book_id"]})
        if existing:
            # Aggiorna solo il pdf_url, mantieni gli altri dati esistenti
            await db.books.update_one(
                {"book_id": book["book_id"]},
                {"$set": {"pdf_url": book["pdf_url"]}}
            )
            updated += 1
        else:
            # Crea nuovo libro
            await db.books.insert_one(book)
            created += 1
    
    return {"message": f"Libri aggiornati: {updated}, creati: {created}"}
    book = await db.books.find_one({"book_id": book_id})
    if not book:
        raise HTTPException(status_code=404, detail="Libro non trovato")
    
    user_purchases = current_user.get("purchases", [])
    has_full_access = "books_full_access" in user_purchases
    is_admin = current_user.get("is_admin", False)
    
    # Verifica accesso: admin, full access, book_id diretto, o product_id (es. book_lux)
    product_id = book.get("product_id", "")
    has_access = is_admin or has_full_access or book_id in user_purchases or product_id in user_purchases
    
    if not has_access:
        raise HTTPException(status_code=403, detail="Non hai accesso a questo libro")
    
    pdf_url = book.get("pdf_url")
    if not pdf_url:
        raise HTTPException(status_code=404, detail="PDF non disponibile")
    
    return {"pdf_url": pdf_url, "title": book.get("title")}


# Cache per i PDF scaricati (evita download ripetuti)
_pdf_cache = {}

async def download_pdf_from_drive(pdf_url: str) -> bytes:
    """Scarica il PDF da Google Drive e lo restituisce come bytes"""
    # Estrai file ID da URL Google Drive
    file_id = None
    if '/d/' in pdf_url:
        file_id = pdf_url.split('/d/')[1].split('/')[0]
    elif 'id=' in pdf_url:
        file_id = pdf_url.split('id=')[1].split('&')[0]
    
    if not file_id:
        raise HTTPException(status_code=400, detail="URL PDF non valido")
    
    # Controlla cache
    if file_id in _pdf_cache:
        cache_time, pdf_data = _pdf_cache[file_id]
        # Cache valida per 1 ora
        if datetime.now() - cache_time < timedelta(hours=1):
            return pdf_data
    
    # Download diretto da Google Drive
    download_url = f"https://drive.google.com/uc?export=download&id={file_id}"
    
    async with httpx.AsyncClient(follow_redirects=True, timeout=60.0) as client:
        response = await client.get(download_url)
        
        # Google Drive può richiedere conferma per file grandi
        if b'confirm=' in response.content or b'download_warning' in response.text.encode():
            # Cerca il token di conferma
            import re
            confirm_match = re.search(r'confirm=([^&]+)', response.text)
            if confirm_match:
                confirm_token = confirm_match.group(1)
                download_url = f"https://drive.google.com/uc?export=download&confirm={confirm_token}&id={file_id}"
                response = await client.get(download_url)
        
        if response.status_code != 200:
            raise HTTPException(status_code=500, detail="Impossibile scaricare il PDF")
        
        pdf_data = response.content
        
        # Verifica che sia un PDF valido
        if not pdf_data.startswith(b'%PDF'):
            raise HTTPException(status_code=500, detail="Il file scaricato non è un PDF valido")
        
        # Salva in cache
        _pdf_cache[file_id] = (datetime.now(), pdf_data)
        
        return pdf_data


@app.get("/api/books/{book_id}/info")
async def get_book_info(book_id: str, current_user: dict = Depends(get_current_user)):
    """Ottieni informazioni sul libro incluso numero di pagine"""
    book = await db.books.find_one({"book_id": book_id})
    if not book:
        raise HTTPException(status_code=404, detail="Libro non trovato")
    
    user_purchases = current_user.get("purchases", [])
    has_full_access = "books_full_access" in user_purchases
    is_admin = current_user.get("is_admin", False)
    product_id = book.get("product_id", "")
    has_access = is_admin or has_full_access or book_id in user_purchases or product_id in user_purchases
    
    if not has_access:
        raise HTTPException(status_code=403, detail="Non hai accesso a questo libro")
    
    pdf_url = book.get("pdf_url")
    if not pdf_url:
        raise HTTPException(status_code=404, detail="PDF non disponibile")
    
    try:
        # Scarica il PDF per ottenere il numero di pagine
        pdf_data = await download_pdf_from_drive(pdf_url)
        doc = pymupdf.open(stream=pdf_data, filetype="pdf")
        num_pages = len(doc)
        doc.close()
        
        return {
            "book_id": book_id,
            "title": book.get("title"),
            "num_pages": num_pages
        }
    except Exception as e:
        logger.error(f"Error getting book info: {e}")
        raise HTTPException(status_code=500, detail="Errore nel caricamento del libro")


@app.get("/api/books/{book_id}/page/{page_num}")
async def get_book_page(
    book_id: str, 
    page_num: int, 
    current_user: dict = Depends(get_current_user),
    quality: int = 2  # 1=bassa, 2=media, 3=alta
):
    """Ottieni una singola pagina del libro come immagine JPEG"""
    book = await db.books.find_one({"book_id": book_id})
    if not book:
        raise HTTPException(status_code=404, detail="Libro non trovato")
    
    user_purchases = current_user.get("purchases", [])
    has_full_access = "books_full_access" in user_purchases
    is_admin = current_user.get("is_admin", False)
    product_id = book.get("product_id", "")
    has_access = is_admin or has_full_access or book_id in user_purchases or product_id in user_purchases
    
    if not has_access:
        raise HTTPException(status_code=403, detail="Non hai accesso a questo libro")
    
    pdf_url = book.get("pdf_url")
    if not pdf_url:
        raise HTTPException(status_code=404, detail="PDF non disponibile")
    
    try:
        # Scarica il PDF
        pdf_data = await download_pdf_from_drive(pdf_url)
        doc = pymupdf.open(stream=pdf_data, filetype="pdf")
        
        if page_num < 0 or page_num >= len(doc):
            doc.close()
            raise HTTPException(status_code=404, detail="Pagina non trovata")
        
        page = doc[page_num]
        
        # Zoom in base alla qualità richiesta (2 = ~150 DPI, 3 = ~225 DPI)
        zoom = min(max(quality, 1), 3)  # Limita tra 1 e 3
        mat = pymupdf.Matrix(zoom, zoom)
        
        # Renderizza la pagina come immagine
        pix = page.get_pixmap(matrix=mat)
        
        # Converti in JPEG
        img_data = pix.tobytes("jpeg")
        
        doc.close()
        
        return Response(
            content=img_data,
            media_type="image/jpeg",
            headers={
                "Cache-Control": "private, max-age=300",  # Cache 5 minuti
                "X-Page-Number": str(page_num),
                "X-Total-Pages": str(len(doc)) if doc else "0"
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error rendering page: {e}")
        raise HTTPException(status_code=500, detail="Errore nel rendering della pagina")

# -----------------------------------------------------------------------------
# IAP ENDPOINTS
# -----------------------------------------------------------------------------

@app.post("/api/iap/verify")
async def verify_purchase(
    purchase: PurchaseVerify,
    current_user: dict = Depends(get_current_user)
):
    """Verifica e registra un acquisto"""
    product_id = purchase.product_id
    user_id = current_user["user_id"]
    
    # Salva acquisto nel database
    purchase_record = {
        "user_id": user_id,
        "product_id": product_id,
        "purchase_token": purchase.purchase_token,
        "platform": purchase.platform,
        "verified_at": datetime.utcnow()
    }
    await db.purchases.insert_one(purchase_record)
    
    # Aggiorna utente
    update = {"$addToSet": {"purchases": product_id}}
    
    # Se è un abbonamento, imposta la data di scadenza
    if product_id in IAP_SUBSCRIPTIONS:
        sub_info = IAP_SUBSCRIPTIONS[product_id]
        expires = datetime.utcnow() + timedelta(days=sub_info["duration_days"])
        update["$set"] = {"tutorials_access_expires": expires, "plan": "premium"}
    elif product_id == "books_full_access":
        update["$set"] = {"plan": "premium"}
    
    await db.users.update_one({"user_id": user_id}, update)
    
    logger.info(f"Purchase verified: {product_id} for {current_user['email']}")
    
    return {"success": True, "product_id": product_id}

@app.post("/api/iap/restore")
async def restore_purchases(current_user: dict = Depends(get_current_user)):
    """Ripristina acquisti dell'utente"""
    purchases = await db.purchases.find({"user_id": current_user["user_id"]}).to_list(100)
    product_ids = list(set([p["product_id"] for p in purchases]))
    
    return {"purchases": product_ids}

# -----------------------------------------------------------------------------
# NEWS ENDPOINTS
# -----------------------------------------------------------------------------

@app.get("/api/news")
async def get_news():
    news = await db.news.find().sort("created_at", -1).to_list(100)
    return [{"news_id": n.get("news_id"), "title": n.get("title"), "link": n.get("link"),
             "content": n.get("content"), "image_url": n.get("image_url"), 
             "has_ticket": n.get("has_ticket", False), "price": n.get("price"),
             "created_at": n.get("created_at")} for n in news]

# -----------------------------------------------------------------------------
# TUTORIALS ENDPOINTS
# -----------------------------------------------------------------------------

@app.get("/api/tutorials")
async def get_tutorials(current_user: dict = Depends(get_current_user)):
    tutorials = await db.tutorials.find().to_list(100)
    
    # Controlla se l'utente ha accesso premium
    has_access = current_user.get("plan") == "premium"
    expires = current_user.get("tutorials_access_expires")
    if expires and datetime.utcnow() < expires:
        has_access = True
    
    result = []
    for t in tutorials:
        tutorial_data = {
            "tutorial_id": t.get("tutorial_id"),
            "title": t.get("title"),
            "description": t.get("description"),
            "image_url": t.get("image_url"),
            "is_free": t.get("is_free", False),
            "has_access": has_access or t.get("is_free", False),
        }
        if tutorial_data["has_access"]:
            tutorial_data["url"] = t.get("url")
        result.append(tutorial_data)
    
    return result

# -----------------------------------------------------------------------------
# BLOG ENDPOINTS
# -----------------------------------------------------------------------------

@app.get("/api/blog")
async def get_blog():
    posts = await db.blog.find().sort("created_at", -1).to_list(100)
    return [{"post_id": p.get("post_id"), "title": p.get("title"), "url": p.get("link"),
             "image_url": p.get("image_url"), "created_at": p.get("created_at")} for p in posts]

@app.get("/api/latest-updates")
async def get_latest_updates():
    """Restituisce le date degli ultimi contenuti pubblicati per News, Tutorial e Blog"""
    # Ultimo news
    latest_news = await db.news.find_one(sort=[("created_at", -1)])
    news_date = latest_news.get("created_at").isoformat() if latest_news and latest_news.get("created_at") else None
    
    # Ultimo tutorial
    latest_tutorial = await db.tutorials.find_one(sort=[("created_at", -1)])
    tutorial_date = latest_tutorial.get("created_at").isoformat() if latest_tutorial and latest_tutorial.get("created_at") else None
    
    # Ultimo blog post
    latest_blog = await db.blog.find_one(sort=[("created_at", -1)])
    blog_date = latest_blog.get("created_at").isoformat() if latest_blog and latest_blog.get("created_at") else None
    
    return {
        "news": news_date,
        "tutorials": tutorial_date,
        "blog": blog_date
    }

# -----------------------------------------------------------------------------
# ADMIN ENDPOINTS
# -----------------------------------------------------------------------------

@app.get("/api/admin/users")
async def get_all_users(admin: dict = Depends(get_admin_user)):
    users = await db.users.find().to_list(1000)
    return [
        {
            **user_to_response(user),
            "has_push_token": bool(user.get("push_token")),
            "purchases": user.get("purchases", []),
            "gifts": user.get("gifts", []),
        }
        for user in users
    ]

@app.get("/api/admin/users-with-push")
async def get_users_with_push(admin: dict = Depends(get_admin_user)):
    users = await db.users.find({"push_token": {"$exists": True, "$ne": None}}).to_list(1000)
    return [
        {
            "user_id": user.get("user_id"),
            "email": user.get("email"),
            "name": user.get("name"),
        }
        for user in users
    ]

@app.post("/api/admin/send-notification")
async def send_notification_to_all(
    notification: PushNotification,
    admin: dict = Depends(get_admin_user)
):
    """
    Send push notification SOLO a utenti iOS via APNs diretto.
    Per Android usare Firebase Console.
    """
    # Filtra SOLO utenti iOS
    users = await db.users.find({
        "push_token": {"$exists": True, "$ne": None},
        "push_platform": "ios"
    }).to_list(1000)
    
    sent_ios = 0
    errors = 0
    unregistered = 0
    error_details = []
    
    logger.info(f"Sending notification to {len(users)} iOS users")
    
    for user in users:
        try:
            # Usa il token APNs originale
            apns_token = user.get("push_token_original", user.get("push_token"))
            
            if not apns_token:
                logger.warning(f"No APNs token for {user['email']}")
                errors += 1
                continue
                
            logger.info(f"Sending to {user['email']}: token={apns_token[:30]}...")
            
            result = await send_apns_push(apns_token, notification.title, notification.body)
            
            if result.get("success"):
                sent_ios += 1
                logger.info(f"SUCCESS for {user['email']}")
            elif result.get("error") == "Token unregistered":
                unregistered += 1
                await db.users.update_one(
                    {"user_id": user["user_id"]},
                    {"$unset": {"push_token": "", "push_token_original": ""}}
                )
                logger.warning(f"Token unregistered for {user['email']}")
            else:
                errors += 1
                error_msg = result.get('error', 'Unknown error')
                error_details.append(f"{user['email']}: {error_msg}")
                logger.error(f"FAILED for {user['email']}: {error_msg}")
                
        except Exception as e:
            logger.error(f"Exception sending push to {user['email']}: {e}")
            errors += 1
            error_details.append(f"{user['email']}: {str(e)}")
    
    return {
        "sent": sent_ios,
        "sent_ios": sent_ios,
        "sent_android": 0,  # Non inviamo più ad Android da qui
        "errors": errors, 
        "unregistered": unregistered,
        "total_ios_users": len(users),
        "error_details": error_details[:5],  # Max 5 errori per non sovraccaricare
        "message": f"Notifica inviata a {sent_ios} utenti iOS" if sent_ios > 0 else "Nessuna notifica inviata (controlla se ci sono utenti iOS registrati)"
    }

# -----------------------------------------------------------------------------
# SCHEDULED NOTIFICATIONS ENDPOINTS
# -----------------------------------------------------------------------------

@app.post("/api/admin/schedule-notification")
async def schedule_notification(
    notification: ScheduledNotification,
    admin: dict = Depends(get_admin_user)
):
    """Programma una notifica per essere inviata in futuro"""
    try:
        # Parsa la data/ora
        scheduled_at = datetime.fromisoformat(notification.scheduled_at.replace('Z', '+00:00'))
        
        # Verifica che la data sia nel futuro
        if scheduled_at <= datetime.utcnow():
            raise HTTPException(status_code=400, detail="La data deve essere nel futuro")
        
        # Salva la notifica programmata
        notif_data = {
            "notification_id": f"notif_{uuid.uuid4().hex[:12]}",
            "title": notification.title,
            "body": notification.body,
            "scheduled_at": scheduled_at,
            "created_at": datetime.utcnow(),
            "created_by": admin["email"],
            "sent": False,
            "sent_at": None,
            "result": None
        }
        
        await db.scheduled_notifications.insert_one(notif_data)
        
        logger.info(f"Notification scheduled for {scheduled_at} by {admin['email']}")
        
        return {
            "message": "Notifica programmata con successo",
            "notification_id": notif_data["notification_id"],
            "scheduled_at": scheduled_at.isoformat()
        }
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Formato data non valido: {str(e)}")

@app.get("/api/admin/scheduled-notifications")
async def get_scheduled_notifications(admin: dict = Depends(get_admin_user)):
    """Ottieni lista delle notifiche programmate"""
    notifications = await db.scheduled_notifications.find().sort("scheduled_at", 1).to_list(100)
    
    return [
        {
            "notification_id": n.get("notification_id"),
            "title": n.get("title"),
            "body": n.get("body"),
            "scheduled_at": n.get("scheduled_at").isoformat() if n.get("scheduled_at") else None,
            "created_at": n.get("created_at").isoformat() if n.get("created_at") else None,
            "created_by": n.get("created_by"),
            "sent": n.get("sent", False),
            "sent_at": n.get("sent_at").isoformat() if n.get("sent_at") else None,
            "result": n.get("result")
        }
        for n in notifications
    ]

@app.delete("/api/admin/scheduled-notifications/{notification_id}")
async def delete_scheduled_notification(
    notification_id: str,
    admin: dict = Depends(get_admin_user)
):
    """Cancella una notifica programmata (solo se non ancora inviata)"""
    notif = await db.scheduled_notifications.find_one({"notification_id": notification_id})
    
    if not notif:
        raise HTTPException(status_code=404, detail="Notifica non trovata")
    
    if notif.get("sent"):
        raise HTTPException(status_code=400, detail="Impossibile cancellare una notifica già inviata")
    
    await db.scheduled_notifications.delete_one({"notification_id": notification_id})
    
    logger.info(f"Scheduled notification {notification_id} deleted by {admin['email']}")
    
    return {"message": "Notifica cancellata"}

@app.post("/api/admin/books")
async def create_book(book: BookCreate, admin: dict = Depends(get_admin_user)):
    book_data = {
        "book_id": generate_book_id(),
        "title": book.title,
        "description": book.description,
        "cover_url": book.cover_url,
        "pdf_url": book.pdf_url,
        "price": book.price,
        "product_id": book.product_id,
        "sort_order": book.sort_order,
        "created_at": datetime.utcnow()
    }
    await db.books.insert_one(book_data)
    return book_data

@app.delete("/api/admin/books/{book_id}")
async def delete_book(book_id: str, admin: dict = Depends(get_admin_user)):
    # Solo il super admin può eliminare libri
    if admin.get("email", "").lower() != SUPER_ADMIN_EMAIL.lower():
        raise HTTPException(status_code=403, detail="Solo il super admin può eliminare libri")
    
    result = await db.books.delete_one({"book_id": book_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Libro non trovato")
    return {"message": "Libro eliminato"}

@app.get("/api/admin/books")
async def get_all_books_admin(admin: dict = Depends(get_admin_user)):
    """Ottieni tutti i libri con tutti i dettagli (admin)"""
    books = await db.books.find().sort("sort_order", 1).to_list(100)
    return [{
        "book_id": b.get("book_id"),
        "title": b.get("title"),
        "description": b.get("description"),
        "cover_url": b.get("cover_url"),
        "pdf_url": b.get("pdf_url"),
        "product_id": b.get("product_id"),
        "sort_order": b.get("sort_order", 999),
    } for b in books]

class BookUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    cover_url: Optional[str] = None
    pdf_url: Optional[str] = None
    product_id: Optional[str] = None
    sort_order: Optional[int] = None

@app.put("/api/admin/books/{book_id}")
async def update_book(book_id: str, book: BookUpdate, admin: dict = Depends(get_admin_user)):
    """Aggiorna un libro esistente"""
    existing = await db.books.find_one({"book_id": book_id})
    if not existing:
        raise HTTPException(status_code=404, detail="Libro non trovato")
    
    update_data = {k: v for k, v in book.dict().items() if v is not None}
    if update_data:
        await db.books.update_one({"book_id": book_id}, {"$set": update_data})
    
    updated = await db.books.find_one({"book_id": book_id})
    return {
        "book_id": updated.get("book_id"),
        "title": updated.get("title"),
        "description": updated.get("description"),
        "cover_url": updated.get("cover_url"),
        "pdf_url": updated.get("pdf_url"),
        "product_id": updated.get("product_id"),
        "sort_order": updated.get("sort_order"),
    }

# Tutorial Admin Endpoints
def generate_tutorial_id() -> str:
    return f"tutorial_{secrets.token_hex(6)}"

@app.post("/api/admin/tutorials")
async def create_tutorial(tutorial: TutorialCreate, admin: dict = Depends(get_admin_user)):
    tutorial_data = {
        "tutorial_id": generate_tutorial_id(),
        "title": tutorial.title,
        "description": tutorial.description,
        "image_url": tutorial.image_url,
        "url": tutorial.url,
        "is_free": tutorial.is_free,
        "created_at": datetime.utcnow()
    }
    await db.tutorials.insert_one(tutorial_data)
    # Rimuovi _id per evitare errore JSON serialization
    tutorial_data.pop('_id', None)
    return tutorial_data

@app.put("/api/admin/tutorials/{tutorial_id}")
async def update_tutorial(tutorial_id: str, tutorial: TutorialCreate, admin: dict = Depends(get_admin_user)):
    result = await db.tutorials.update_one(
        {"tutorial_id": tutorial_id},
        {"$set": {
            "title": tutorial.title,
            "description": tutorial.description,
            "image_url": tutorial.image_url,
            "url": tutorial.url,
            "is_free": tutorial.is_free
        }}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Tutorial non trovato")
    return {"message": "Tutorial aggiornato"}

@app.delete("/api/admin/tutorials/{tutorial_id}")
async def delete_tutorial(tutorial_id: str, admin: dict = Depends(get_admin_user)):
    result = await db.tutorials.delete_one({"tutorial_id": tutorial_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Tutorial non trovato")
    return {"message": "Tutorial eliminato"}

@app.get("/api/admin/tutorials")
async def get_all_tutorials(admin: dict = Depends(get_admin_user)):
    tutorials = await db.tutorials.find().to_list(100)
    return [{"tutorial_id": t.get("tutorial_id"), "title": t.get("title"), 
             "description": t.get("description"), "url": t.get("url"),
             "image_url": t.get("image_url"), "is_free": t.get("is_free", False)} for t in tutorials]

# -----------------------------------------------------------------------------
# ADMIN USER MANAGEMENT
# -----------------------------------------------------------------------------

class AdminCreateUser(BaseModel):
    email: str
    password: str
    name: str
    is_admin: bool = False

@app.post("/api/admin/create-user")
async def admin_create_user(data: AdminCreateUser, admin: dict = Depends(get_admin_user)):
    """Crea un nuovo utente dal pannello admin"""
    email_lower = data.email.lower()
    existing = await db.users.find_one({"email": email_lower})
    if existing:
        raise HTTPException(status_code=400, detail="Email già esistente")
    
    user_id = generate_user_id()
    user = {
        "user_id": user_id,
        "email": email_lower,
        "password_hash": hash_password(data.password),
        "name": data.name,
        "referral_code": generate_referral_code(),
        "is_admin": data.is_admin,
        "is_verified": True,
        "plan": "free",
        "purchases": [],
        "created_at": datetime.utcnow()
    }
    await db.users.insert_one(user)
    logger.info(f"Admin created user: {email_lower}")
    return {"message": "Utente creato", "user_id": user_id}

# Email super admin protetto (non può essere modificato)
SUPER_ADMIN_EMAIL = "raffaeleingegno.com@gmail.com"

@app.post("/api/admin/toggle-admin/{user_id}")
async def toggle_admin(user_id: str, admin: dict = Depends(get_admin_user)):
    """Rende un utente admin o rimuove privilegi admin"""
    user = await db.users.find_one({"user_id": user_id})
    if not user:
        raise HTTPException(status_code=404, detail="Utente non trovato")
    
    # Protezione super admin - non può essere modificato
    if user.get("email", "").lower() == SUPER_ADMIN_EMAIL.lower():
        raise HTTPException(status_code=403, detail="Impossibile modificare i privilegi del super admin")
    
    # Solo il super admin può creare/rimuovere altri admin
    if admin.get("email", "").lower() != SUPER_ADMIN_EMAIL.lower():
        raise HTTPException(status_code=403, detail="Solo il super admin può modificare i privilegi admin")
    
    new_admin_status = not user.get("is_admin", False)
    await db.users.update_one(
        {"user_id": user_id},
        {"$set": {"is_admin": new_admin_status}}
    )
    return {"message": f"Admin {'attivato' if new_admin_status else 'disattivato'}", "is_admin": new_admin_status}

class GiftBook(BaseModel):
    user_id: str
    product_id: str

@app.post("/api/admin/gift-book")
async def gift_book(data: GiftBook, admin: dict = Depends(get_admin_user)):
    """Regala un libro o pacchetto a un utente"""
    user = await db.users.find_one({"user_id": data.user_id})
    if not user:
        raise HTTPException(status_code=404, detail="Utente non trovato")
    
    gifts = user.get("gifts", [])
    if data.product_id not in gifts:
        gifts.append(data.product_id)
        await db.users.update_one(
            {"user_id": data.user_id},
            {"$set": {"gifts": gifts}}
        )
    
    logger.info(f"Admin gifted {data.product_id} to user {data.user_id}")
    return {"message": f"Prodotto {data.product_id} regalato", "gifts": gifts}

@app.post("/api/admin/revoke-gift")
async def revoke_gift(data: GiftBook, admin: dict = Depends(get_admin_user)):
    """Revoca un gift a un utente"""
    user = await db.users.find_one({"user_id": data.user_id})
    if not user:
        raise HTTPException(status_code=404, detail="Utente non trovato")
    
    gifts = user.get("gifts", [])
    if data.product_id in gifts:
        gifts.remove(data.product_id)
        await db.users.update_one(
            {"user_id": data.user_id},
            {"$set": {"gifts": gifts}}
        )
    
    logger.info(f"Admin revoked gift {data.product_id} from user {data.user_id}")
    return {"message": f"Gift {data.product_id} revocato", "gifts": gifts}

@app.post("/api/admin/export-users")
async def export_users_email(admin: dict = Depends(get_admin_user)):
    """Esporta lista utenti via email"""
    users = await db.users.find().to_list(1000)
    
    # Costruisci la tabella HTML
    rows = ""
    for u in users:
        purchases = ", ".join(u.get("purchases", [])) or "Nessuno"
        gifts = ", ".join(u.get("gifts", [])) or "Nessuno"
        rows += f"""
        <tr>
            <td style="padding: 8px; border: 1px solid #ddd;">{u.get("name", "")}</td>
            <td style="padding: 8px; border: 1px solid #ddd;">{u.get("email", "")}</td>
            <td style="padding: 8px; border: 1px solid #ddd;">{purchases}</td>
            <td style="padding: 8px; border: 1px solid #ddd;">{gifts}</td>
        </tr>
        """
    
    html_content = f"""
    <html>
    <body>
        <h2>Export Utenti Lumina Ingegno</h2>
        <p>Totale utenti: {len(users)}</p>
        <table style="border-collapse: collapse; width: 100%;">
            <thead>
                <tr style="background-color: #cc3333; color: white;">
                    <th style="padding: 10px; border: 1px solid #ddd;">Nome</th>
                    <th style="padding: 10px; border: 1px solid #ddd;">Email</th>
                    <th style="padding: 10px; border: 1px solid #ddd;">Acquisti</th>
                    <th style="padding: 10px; border: 1px solid #ddd;">Gift</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </body>
    </html>
    """
    
    try:
        resend.api_key = os.getenv("RESEND_API_KEY")
        resend.Emails.send({
            "from": "Lumina Ingegno <noreply@raffaeleingegno.com>",
            "to": ["info@raffaeleingegno.com"],
            "subject": f"Export Utenti - {len(users)} utenti",
            "html": html_content
        })
        return {"message": "Email inviata a info@raffaeleingegno.com"}
    except Exception as e:
        logger.error(f"Error sending export email: {e}")
        raise HTTPException(status_code=500, detail="Errore nell'invio email")

@app.post("/api/admin/apply-referral/{user_id}")
async def admin_apply_referral(user_id: str, admin: dict = Depends(get_admin_user)):
    """Applica il bonus referral a un utente (1 mese tutorial gratis)"""
    user = await db.users.find_one({"user_id": user_id})
    if not user:
        raise HTTPException(status_code=404, detail="Utente non trovato")
    
    # Aggiungi 1 mese di tutorial
    current_sub = user.get("subscription_until")
    if current_sub and current_sub > datetime.utcnow():
        new_until = current_sub + timedelta(days=30)
    else:
        new_until = datetime.utcnow() + timedelta(days=30)
    
    await db.users.update_one(
        {"user_id": user_id},
        {"$set": {"subscription_until": new_until, "plan": "premium"}}
    )
    
    return {"message": "Bonus referral applicato", "subscription_until": new_until.isoformat()}

# -----------------------------------------------------------------------------
# ADMIN NEWS ENDPOINTS
# -----------------------------------------------------------------------------

def generate_news_id() -> str:
    return f"news_{secrets.token_hex(6)}"

class NewsCreate(BaseModel):
    title: str
    content: Optional[str] = None
    image_url: Optional[str] = None
    link: Optional[str] = None
    has_ticket: bool = False
    price: Optional[float] = None

@app.get("/api/admin/news")
async def get_all_news_admin(admin: dict = Depends(get_admin_user)):
    news = await db.news.find().sort("created_at", -1).to_list(100)
    return [{"news_id": n.get("news_id"), "title": n.get("title"), 
             "link": n.get("link"), "has_ticket": n.get("has_ticket", False),
             "price": n.get("price"), "created_at": n.get("created_at")} for n in news]

@app.post("/api/admin/news")
async def create_news(news: NewsCreate, admin: dict = Depends(get_admin_user)):
    news_data = {
        "news_id": generate_news_id(),
        "title": news.title,
        "content": news.content,
        "image_url": news.image_url,
        "link": news.link,
        "has_ticket": news.has_ticket,
        "price": news.price,
        "created_at": datetime.utcnow()
    }
    await db.news.insert_one(news_data)
    # Rimuovi _id per evitare errore JSON serialization
    news_data.pop('_id', None)
    return news_data

@app.put("/api/admin/news/{news_id}")
async def update_news(news_id: str, news: NewsCreate, admin: dict = Depends(get_admin_user)):
    result = await db.news.update_one(
        {"news_id": news_id},
        {"$set": {
            "title": news.title, 
            "content": news.content,
            "image_url": news.image_url,
            "link": news.link, 
            "has_ticket": news.has_ticket, 
            "price": news.price
        }}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="News non trovata")
    return {"message": "News aggiornata"}

@app.delete("/api/admin/news/{news_id}")
async def delete_news(news_id: str, admin: dict = Depends(get_admin_user)):
    result = await db.news.delete_one({"news_id": news_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="News non trovata")
    return {"message": "News eliminata"}

# -----------------------------------------------------------------------------
# ADMIN MARKET ENDPOINTS
# -----------------------------------------------------------------------------

def generate_market_id() -> str:
    return f"item_{secrets.token_hex(6)}"

class MarketItemCreate(BaseModel):
    title: str
    description: str = ""
    image_url: str = ""
    link: str
    category: str = "Altro"

# Endpoint pubblico per il market
@app.get("/api/market")
async def get_market_items():
    """Lista prodotti market per tutti gli utenti"""
    items = await db.market.find().to_list(100)
    return [{"item_id": i.get("item_id"), "title": i.get("title"), 
             "description": i.get("description"),
             "link": i.get("link"), "category": i.get("category")} for i in items]

@app.get("/api/admin/market")
async def get_all_market_admin(admin: dict = Depends(get_admin_user)):
    items = await db.market.find().to_list(100)
    return [{"item_id": i.get("item_id"), "title": i.get("title"), 
             "description": i.get("description"), "image_url": i.get("image_url"),
             "link": i.get("link"), "category": i.get("category")} for i in items]

@app.post("/api/admin/market")
async def create_market_item(item: MarketItemCreate, admin: dict = Depends(get_admin_user)):
    item_data = {
        "item_id": generate_market_id(),
        "title": item.title,
        "description": item.description,
        "image_url": item.image_url,
        "link": item.link,
        "category": item.category,
        "created_at": datetime.utcnow()
    }
    await db.market.insert_one(item_data)
    # Rimuovi _id per evitare errore JSON serialization
    item_data.pop('_id', None)
    return item_data

@app.put("/api/admin/market/{item_id}")
async def update_market_item(item_id: str, item: MarketItemCreate, admin: dict = Depends(get_admin_user)):
    result = await db.market.update_one(
        {"item_id": item_id},
        {"$set": {
            "title": item.title,
            "description": item.description,
            "image_url": item.image_url,
            "link": item.link,
            "category": item.category
        }}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Prodotto non trovato")
    return {"message": "Prodotto aggiornato"}

@app.delete("/api/admin/market/{item_id}")
async def delete_market_item(item_id: str, admin: dict = Depends(get_admin_user)):
    result = await db.market.delete_one({"item_id": item_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Prodotto non trovato")
    return {"message": "Prodotto eliminato"}

# -----------------------------------------------------------------------------
# ADMIN LINKS ENDPOINTS
# -----------------------------------------------------------------------------

def generate_link_id() -> str:
    return f"link_{secrets.token_hex(6)}"

class SocialLinkCreate(BaseModel):
    title: str
    url: str
    icon: str = "link-outline"  # Ionicons icon name
    color: str = "#3B82F6"  # Hex color
    order: int = 0

# Endpoint pubblico per i links
@app.get("/api/links")
async def get_social_links():
    """Lista links per tutti gli utenti"""
    links = await db.social_links.find().sort("order", 1).to_list(50)
    return [{
        "link_id": l.get("link_id"),
        "title": l.get("title"),
        "url": l.get("url"),
        "icon": l.get("icon", "link-outline"),
        "color": l.get("color", "#3B82F6"),
        "order": l.get("order", 0)
    } for l in links]

@app.get("/api/admin/links")
async def get_all_links_admin(admin: dict = Depends(get_admin_user)):
    """Lista links per admin"""
    links = await db.social_links.find().sort("order", 1).to_list(50)
    return [{
        "link_id": l.get("link_id"),
        "title": l.get("title"),
        "url": l.get("url"),
        "icon": l.get("icon", "link-outline"),
        "color": l.get("color", "#3B82F6"),
        "order": l.get("order", 0)
    } for l in links]

@app.post("/api/admin/links")
async def create_social_link(link: SocialLinkCreate, admin: dict = Depends(get_admin_user)):
    """Crea un nuovo link"""
    link_data = {
        "link_id": generate_link_id(),
        "title": link.title,
        "url": link.url,
        "icon": link.icon,
        "color": link.color,
        "order": link.order,
        "created_at": datetime.utcnow()
    }
    await db.social_links.insert_one(link_data)
    link_data.pop('_id', None)
    return link_data

@app.put("/api/admin/links/{link_id}")
async def update_social_link(link_id: str, link: SocialLinkCreate, admin: dict = Depends(get_admin_user)):
    """Aggiorna un link esistente"""
    result = await db.social_links.update_one(
        {"link_id": link_id},
        {"$set": {
            "title": link.title,
            "url": link.url,
            "icon": link.icon,
            "color": link.color,
            "order": link.order
        }}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Link non trovato")
    return {"message": "Link aggiornato"}

@app.delete("/api/admin/links/{link_id}")
async def delete_social_link(link_id: str, admin: dict = Depends(get_admin_user)):
    """Elimina un link"""
    result = await db.social_links.delete_one({"link_id": link_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Link non trovato")
    return {"message": "Link eliminato"}

# -----------------------------------------------------------------------------
# ADMIN SECTIONS ENDPOINTS
# -----------------------------------------------------------------------------

class AppSectionsUpdate(BaseModel):
    sections: list

@app.get("/api/admin/sections")
async def get_app_sections(admin: dict = Depends(get_admin_user)):
    config = await db.app_config.find_one({"config_id": "sections"})
    if config:
        return config.get("sections", [])
    return []

@app.put("/api/admin/sections")
async def update_app_sections(data: AppSectionsUpdate, admin: dict = Depends(get_admin_user)):
    await db.app_config.update_one(
        {"config_id": "sections"},
        {"$set": {"sections": data.sections, "updated_at": datetime.utcnow()}},
        upsert=True
    )
    return {"message": "Sezioni aggiornate"}

# -----------------------------------------------------------------------------
# ADMIN BLOG ENDPOINTS
# -----------------------------------------------------------------------------

def generate_post_id() -> str:
    return f"post_{secrets.token_hex(6)}"

class BlogPostCreate(BaseModel):
    title: str
    link: str

@app.get("/api/admin/blog")
async def get_all_blog_admin(admin: dict = Depends(get_admin_user)):
    posts = await db.blog.find().sort("created_at", -1).to_list(100)
    return [{"post_id": p.get("post_id"), "title": p.get("title"), 
             "link": p.get("link"), "created_at": p.get("created_at")} for p in posts]

@app.post("/api/admin/blog")
async def create_blog_post(post: BlogPostCreate, admin: dict = Depends(get_admin_user)):
    post_data = {
        "post_id": generate_post_id(),
        "title": post.title,
        "link": post.link,
        "created_at": datetime.utcnow()
    }
    await db.blog.insert_one(post_data)
    # Rimuovi _id per evitare errore JSON serialization
    post_data.pop('_id', None)
    return post_data

@app.put("/api/admin/blog/{post_id}")
async def update_blog_post(post_id: str, post: BlogPostCreate, admin: dict = Depends(get_admin_user)):
    result = await db.blog.update_one(
        {"post_id": post_id},
        {"$set": {"title": post.title, "link": post.link}}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Articolo non trovato")
    return {"message": "Articolo aggiornato"}

@app.delete("/api/admin/blog/{post_id}")
async def delete_blog_post(post_id: str, admin: dict = Depends(get_admin_user)):
    result = await db.blog.delete_one({"post_id": post_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Articolo non trovato")
    return {"message": "Articolo eliminato"}

# =============================================================================
# CALENDAR CLOUD SYNC
# =============================================================================

def generate_event_id() -> str:
    return f"evt_{secrets.token_hex(8)}"

class CalendarEventCreate(BaseModel):
    date: str  # Formato: YYYY-MM-DD
    time: str  # Formato: HH:MM
    text: str

class CalendarEventUpdate(BaseModel):
    time: Optional[str] = None
    text: Optional[str] = None

class CalendarSettingsUpdate(BaseModel):
    notificationEnabled: bool = True
    notificationTime: str = "08:00"
    dayBeforeEnabled: bool = False
    dayBeforeTime: str = "19:00"

@app.get("/api/calendar/events")
async def get_calendar_events(current_user: dict = Depends(get_current_user)):
    """Ottieni tutti gli eventi del calendario dell'utente"""
    events = await db.calendar_events.find({"user_id": current_user["user_id"]}).to_list(1000)
    
    # Raggruppa per data (formato compatibile con il frontend)
    events_by_date = {}
    for event in events:
        date_key = event.get("date")
        if date_key not in events_by_date:
            events_by_date[date_key] = []
        events_by_date[date_key].append({
            "id": event.get("event_id"),
            "time": event.get("time"),
            "text": event.get("text"),
        })
    
    return {"events": events_by_date}

@app.post("/api/calendar/events")
async def create_calendar_event(
    event: CalendarEventCreate,
    current_user: dict = Depends(get_current_user)
):
    """Crea un nuovo evento nel calendario"""
    event_id = generate_event_id()
    event_data = {
        "event_id": event_id,
        "user_id": current_user["user_id"],
        "date": event.date,
        "time": event.time,
        "text": event.text,
        "created_at": datetime.utcnow(),
    }
    await db.calendar_events.insert_one(event_data)
    
    return {
        "id": event_id,
        "date": event.date,
        "time": event.time,
        "text": event.text,
    }

@app.put("/api/calendar/events/{event_id}")
async def update_calendar_event(
    event_id: str,
    event: CalendarEventUpdate,
    current_user: dict = Depends(get_current_user)
):
    """Aggiorna un evento esistente"""
    # Verifica che l'evento appartenga all'utente
    existing = await db.calendar_events.find_one({
        "event_id": event_id,
        "user_id": current_user["user_id"]
    })
    if not existing:
        raise HTTPException(status_code=404, detail="Evento non trovato")
    
    update_data = {}
    if event.time is not None:
        update_data["time"] = event.time
    if event.text is not None:
        update_data["text"] = event.text
    
    if update_data:
        await db.calendar_events.update_one(
            {"event_id": event_id},
            {"$set": update_data}
        )
    
    return {"message": "Evento aggiornato"}

@app.delete("/api/calendar/events/{event_id}")
async def delete_calendar_event(
    event_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Elimina un evento"""
    result = await db.calendar_events.delete_one({
        "event_id": event_id,
        "user_id": current_user["user_id"]
    })
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Evento non trovato")
    
    return {"message": "Evento eliminato"}

@app.get("/api/calendar/settings")
async def get_calendar_settings(current_user: dict = Depends(get_current_user)):
    """Ottieni le impostazioni del calendario dell'utente"""
    settings = await db.calendar_settings.find_one({"user_id": current_user["user_id"]})
    
    if not settings:
        # Restituisci impostazioni di default
        return {
            "notificationEnabled": True,
            "notificationTime": "08:00",
            "dayBeforeEnabled": False,
            "dayBeforeTime": "19:00",
        }
    
    return {
        "notificationEnabled": settings.get("notificationEnabled", True),
        "notificationTime": settings.get("notificationTime", "08:00"),
        "dayBeforeEnabled": settings.get("dayBeforeEnabled", False),
        "dayBeforeTime": settings.get("dayBeforeTime", "19:00"),
    }

@app.put("/api/calendar/settings")
async def update_calendar_settings(
    settings: CalendarSettingsUpdate,
    current_user: dict = Depends(get_current_user)
):
    """Aggiorna le impostazioni del calendario"""
    await db.calendar_settings.update_one(
        {"user_id": current_user["user_id"]},
        {"$set": {
            "user_id": current_user["user_id"],
            "notificationEnabled": settings.notificationEnabled,
            "notificationTime": settings.notificationTime,
            "dayBeforeEnabled": settings.dayBeforeEnabled,
            "dayBeforeTime": settings.dayBeforeTime,
            "updated_at": datetime.utcnow(),
        }},
        upsert=True
    )
    
    return {"message": "Impostazioni salvate"}

# =============================================================================
# ADMIN WEB PANEL
# =============================================================================

ADMIN_HTML = """
<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Lumina Ingegno - Admin Panel</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0c0c0c; color: #fff; min-height: 100vh; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        h1 { color: #cc3333; margin-bottom: 20px; }
        h2 { margin: 30px 0 15px; color: #fff; border-bottom: 1px solid #333; padding-bottom: 10px; }
        .card { background: #1a1a1a; border-radius: 12px; padding: 20px; margin-bottom: 20px; border: 1px solid #333; }
        .btn { background: #cc3333; color: #fff; border: none; padding: 12px 24px; border-radius: 8px; cursor: pointer; font-size: 16px; margin: 5px; }
        .btn:hover { background: #aa2222; }
        .btn-secondary { background: #333; }
        .btn-secondary:hover { background: #444; }
        input, textarea { width: 100%; padding: 12px; margin: 8px 0; border: 1px solid #333; border-radius: 8px; background: #0c0c0c; color: #fff; font-size: 16px; }
        textarea { min-height: 100px; resize: vertical; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .user-item { background: #222; padding: 15px; border-radius: 8px; display: flex; justify-content: space-between; align-items: center; margin: 8px 0; }
        .user-info { flex: 1; }
        .user-name { font-weight: bold; color: #fff; }
        .user-email { font-size: 14px; color: #888; }
        .badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; margin-left: 8px; }
        .badge-admin { background: #cc3333; }
        .badge-push { background: #33cc66; }
        .badge-premium { background: #cc9933; }
        .login-form { max-width: 400px; margin: 100px auto; }
        .stats { display: flex; gap: 20px; flex-wrap: wrap; }
        .stat { background: #222; padding: 20px; border-radius: 8px; text-align: center; flex: 1; min-width: 150px; }
        .stat-value { font-size: 36px; font-weight: bold; color: #cc3333; }
        .stat-label { color: #888; margin-top: 5px; }
        .hidden { display: none; }
        .alert { padding: 15px; border-radius: 8px; margin: 10px 0; }
        .alert-success { background: rgba(51, 204, 102, 0.2); border: 1px solid #33cc66; }
        .alert-error { background: rgba(204, 51, 51, 0.2); border: 1px solid #cc3333; }
        .tabs { display: flex; gap: 10px; margin-bottom: 20px; }
        .tab { padding: 10px 20px; background: #222; border-radius: 8px; cursor: pointer; }
        .tab.active { background: #cc3333; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #333; }
        th { background: #222; }
    </style>
</head>
<body>
    <div class="container">
        <!-- Login Form -->
        <div id="loginSection" class="login-form">
            <div class="card">
                <h1>🔐 Admin Login</h1>
                <input type="email" id="loginEmail" placeholder="Email admin">
                <input type="password" id="loginPassword" placeholder="Password">
                <button class="btn" onclick="login()" style="width:100%">Accedi</button>
                <div id="loginError" class="alert alert-error hidden"></div>
            </div>
        </div>

        <!-- Admin Panel -->
        <div id="adminPanel" class="hidden">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                <h1>🎛️ Lumina Ingegno - Admin Panel</h1>
                <button class="btn btn-secondary" onclick="logout()">Esci</button>
            </div>

            <!-- Stats -->
            <div class="stats" id="stats"></div>

            <!-- Tabs -->
            <div class="tabs">
                <div class="tab active" onclick="showTab('notifications')">📢 Notifiche</div>
                <div class="tab" onclick="showTab('users')">👥 Utenti</div>
                <div class="tab" onclick="showTab('books')">📚 Libri</div>
                <div class="tab" onclick="showTab('tutorials')">🎓 Tutorial</div>
            </div>

            <!-- Notifications Tab -->
            <div id="notificationsTab" class="card">
                <h2>🍎 Notifiche Push iOS</h2>
                <p style="color: #888; margin-bottom: 15px; font-size: 13px;">
                    Questo pannello invia notifiche solo a dispositivi iOS via APNs.<br>
                    Per Android usa <a href="https://console.firebase.google.com" target="_blank" style="color: #4CAF50;">Firebase Console</a>
                </p>
                
                <!-- Invio Immediato -->
                <div style="background: #1a1a1a; padding: 15px; border-radius: 8px; margin-bottom: 20px;">
                    <h3 style="margin-bottom: 15px;">⚡ Invio Immediato iOS</h3>
                    <input type="text" id="notifTitle" placeholder="Titolo notifica">
                    <textarea id="notifBody" placeholder="Messaggio"></textarea>
                    <button class="btn" onclick="sendNotification()">🍎 Invia ORA a iOS</button>
                    <div id="notifResult"></div>
                </div>
                
                <!-- Programmazione -->
                <div style="background: #1a1a1a; padding: 15px; border-radius: 8px; margin-bottom: 20px;">
                    <h3 style="margin-bottom: 15px;">📅 Programma Notifica iOS</h3>
                    <input type="text" id="schedNotifTitle" placeholder="Titolo notifica">
                    <textarea id="schedNotifBody" placeholder="Messaggio"></textarea>
                    <div style="display: flex; gap: 10px; margin-bottom: 10px;">
                        <input type="date" id="schedDate" style="flex: 1; padding: 12px; background: #222; color: #fff; border: 1px solid #444; border-radius: 5px;">
                        <input type="time" id="schedTime" style="flex: 1; padding: 12px; background: #222; color: #fff; border: 1px solid #444; border-radius: 5px;">
                    </div>
                    <button class="btn" onclick="scheduleNotification()" style="background: #8B5CF6;">📅 Programma iOS</button>
                    <div id="schedResult"></div>
                </div>
                
                <!-- Lista Programmate -->
                <div style="background: #1a1a1a; padding: 15px; border-radius: 8px;">
                    <h3 style="margin-bottom: 15px;">📋 Notifiche Programmate</h3>
                    <button class="btn btn-secondary" onclick="loadScheduledNotifications()" style="margin-bottom: 15px;">🔄 Aggiorna</button>
                    <div id="scheduledList"></div>
                </div>
            </div>

            <!-- Users Tab -->
            <div id="usersTab" class="card hidden">
                <h2>👥 Gestione Utenti</h2>
                
                <!-- Crea nuovo utente -->
                <div style="background: #1a1a1a; padding: 15px; border-radius: 8px; margin-bottom: 20px;">
                    <h3 style="margin-bottom: 15px;">➕ Crea Nuovo Utente</h3>
                    <input type="text" id="newUserName" placeholder="Nome">
                    <input type="email" id="newUserEmail" placeholder="Email">
                    <input type="password" id="newUserPassword" placeholder="Password">
                    <label style="color: #ccc; display: flex; align-items: center; gap: 8px; margin: 10px 0;">
                        <input type="checkbox" id="newUserAdmin"> Rendi Admin
                    </label>
                    <button class="btn" onclick="createUser()">Crea Utente</button>
                    <div id="createUserResult"></div>
                </div>
                
                <!-- Regala libro -->
                <div style="background: #1a1a1a; padding: 15px; border-radius: 8px; margin-bottom: 20px;">
                    <h3 style="margin-bottom: 15px;">🎁 Regala Libro</h3>
                    <select id="giftUserSelect" style="width: 100%; padding: 12px; margin-bottom: 10px; background: #222; color: #fff; border: 1px solid #444; border-radius: 5px;">
                        <option value="">Seleziona utente...</option>
                    </select>
                    <select id="giftProductSelect" style="width: 100%; padding: 12px; margin-bottom: 10px; background: #222; color: #fff; border: 1px solid #444; border-radius: 5px;">
                        <option value="">Seleziona prodotto...</option>
                        <option value="books_full_access">📚 Tutti i Libri (pacchetto completo)</option>
                        <option value="book_lux">📖 LUX</option>
                        <option value="book_imago">📖 IMAGO</option>
                        <option value="book_omnia">📖 OMNIA</option>
                        <option value="book_tabula">📖 TABULA</option>
                        <option value="book_lux2">📖 LUX2</option>
                    </select>
                    <button class="btn" onclick="giftBook()">🎁 Regala</button>
                    <div id="giftResult"></div>
                </div>
                
                <!-- Lista utenti -->
                <h3 style="margin-bottom: 15px;">📋 Utenti Registrati</h3>
                <div id="usersList"></div>
            </div>

            <!-- Books Tab -->
            <div id="booksTab" class="card hidden">
                <h2>📚 Gestione Libri</h2>
                <div class="grid">
                    <div>
                        <h3 style="margin-bottom: 15px;">Aggiungi Nuovo Libro</h3>
                        <input type="text" id="bookTitle" placeholder="Titolo">
                        <input type="text" id="bookDesc" placeholder="Descrizione">
                        <input type="text" id="bookCover" placeholder="URL Cover">
                        <input type="text" id="bookPdf" placeholder="URL PDF (Google Drive, Dropbox...)">
                        <input type="text" id="bookProductId" placeholder="Product ID (es: book_lux)">
                        <input type="number" id="bookOrder" placeholder="Ordine (1=primo, 2=secondo...)" value="1">
                        <button class="btn" onclick="addBook()">Aggiungi Libro</button>
                    </div>
                    <div>
                        <h3 style="margin-bottom: 15px;">Libri Esistenti (clicca per modificare)</h3>
                        <div id="booksList"></div>
                    </div>
                </div>
                
                <!-- Modal Modifica Libro -->
                <div id="editBookModal" style="display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.8); z-index: 1000; padding: 20px; overflow-y: auto;">
                    <div style="max-width: 500px; margin: 50px auto; background: #1a1a1a; padding: 30px; border-radius: 12px;">
                        <h3 style="margin-bottom: 20px;">✏️ Modifica Libro</h3>
                        <input type="hidden" id="editBookId">
                        <label style="color: #888; font-size: 12px;">Titolo</label>
                        <input type="text" id="editBookTitle" placeholder="Titolo">
                        <label style="color: #888; font-size: 12px;">Descrizione</label>
                        <input type="text" id="editBookDesc" placeholder="Descrizione">
                        <label style="color: #888; font-size: 12px;">URL Cover</label>
                        <input type="text" id="editBookCover" placeholder="URL Cover">
                        <label style="color: #888; font-size: 12px;">URL PDF</label>
                        <input type="text" id="editBookPdf" placeholder="URL PDF">
                        <label style="color: #888; font-size: 12px;">Product ID (per IAP)</label>
                        <input type="text" id="editBookProductId" placeholder="es: book_lux">
                        <label style="color: #888; font-size: 12px;">Ordine</label>
                        <input type="number" id="editBookOrder" placeholder="Ordine">
                        <div style="display: flex; gap: 10px; margin-top: 20px;">
                            <button class="btn" onclick="saveBookEdit()">💾 Salva</button>
                            <button class="btn btn-secondary" onclick="closeEditModal()">Annulla</button>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Tutorials Tab -->
            <div id="tutorialsTab" class="card hidden">
                <h2>🎓 Gestione Tutorial</h2>
                <div class="grid">
                    <div>
                        <h3 style="margin-bottom: 15px;">Aggiungi Nuovo Tutorial</h3>
                        <input type="text" id="tutorialTitle" placeholder="Titolo">
                        <input type="text" id="tutorialDesc" placeholder="Descrizione">
                        <input type="text" id="tutorialImage" placeholder="URL Immagine">
                        <input type="text" id="tutorialUrl" placeholder="URL Pagina Tutorial">
                        <label style="display: flex; align-items: center; gap: 10px; margin: 15px 0; cursor: pointer;">
                            <input type="checkbox" id="tutorialFree" style="width: auto; margin: 0;">
                            <span>Tutorial Gratuito</span>
                        </label>
                        <button class="btn" onclick="addTutorial()">Aggiungi Tutorial</button>
                    </div>
                    <div>
                        <h3 style="margin-bottom: 15px;">Tutorial Esistenti</h3>
                        <div id="tutorialsList"></div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        const API_URL = '';
        let authToken = localStorage.getItem('adminToken');

        // Check if already logged in
        if (authToken) {
            checkAuth();
        }

        async function checkAuth() {
            try {
                const res = await fetch(API_URL + '/api/auth/me', {
                    headers: { 'Authorization': 'Bearer ' + authToken }
                });
                if (res.ok) {
                    const user = await res.json();
                    if (user.is_admin) {
                        showAdminPanel();
                        loadData();
                    } else {
                        logout();
                    }
                } else {
                    logout();
                }
            } catch (e) {
                logout();
            }
        }

        async function login() {
            const email = document.getElementById('loginEmail').value;
            const password = document.getElementById('loginPassword').value;
            
            try {
                const res = await fetch(API_URL + '/api/auth/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email, password })
                });
                const data = await res.json();
                
                if (res.ok && data.user.is_admin) {
                    authToken = data.access_token;
                    localStorage.setItem('adminToken', authToken);
                    showAdminPanel();
                    loadData();
                } else {
                    showError('loginError', data.detail || 'Accesso non autorizzato');
                }
            } catch (e) {
                showError('loginError', 'Errore di connessione');
            }
        }

        function logout() {
            authToken = null;
            localStorage.removeItem('adminToken');
            document.getElementById('loginSection').classList.remove('hidden');
            document.getElementById('adminPanel').classList.add('hidden');
        }

        function showAdminPanel() {
            document.getElementById('loginSection').classList.add('hidden');
            document.getElementById('adminPanel').classList.remove('hidden');
        }

        function showError(elementId, message) {
            const el = document.getElementById(elementId);
            el.textContent = message;
            el.classList.remove('hidden');
            setTimeout(() => el.classList.add('hidden'), 5000);
        }

        function showTab(tab) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('[id$="Tab"]').forEach(t => t.classList.add('hidden'));
            event.target.classList.add('active');
            document.getElementById(tab + 'Tab').classList.remove('hidden');
        }

        async function loadData() {
            // Load scheduled notifications
            loadScheduledNotifications();
            
            // Load users
            const usersRes = await fetch(API_URL + '/api/admin/users', {
                headers: { 'Authorization': 'Bearer ' + authToken }
            });
            const users = await usersRes.json();
            
            // Stats
            const pushUsers = users.filter(u => u.has_push_token).length;
            const premiumUsers = users.filter(u => u.plan === 'premium').length;
            document.getElementById('stats').innerHTML = `
                <div class="stat"><div class="stat-value">${users.length}</div><div class="stat-label">Utenti Totali</div></div>
                <div class="stat"><div class="stat-value">${pushUsers}</div><div class="stat-label">Con Push Token</div></div>
                <div class="stat"><div class="stat-value">${premiumUsers}</div><div class="stat-label">Premium</div></div>
            `;
            
            // Users list with actions
            let userSelectOptions = '<option value="">Seleziona utente...</option>';
            document.getElementById('usersList').innerHTML = users.map(u => {
                userSelectOptions += `<option value="${u.user_id}">${u.name} (${u.email})</option>`;
                return `
                <div class="user-item">
                    <div class="user-info">
                        <div class="user-name">${u.name} ${u.is_admin ? '<span class="badge badge-admin">Admin</span>' : ''} ${u.has_push_token ? '<span class="badge badge-push">Push</span>' : ''} ${u.plan === 'premium' ? '<span class="badge badge-premium">Premium</span>' : ''}</div>
                        <div class="user-email">${u.email}</div>
                        <div style="font-size: 12px; color: #666; margin-top: 4px;">Acquisti: ${u.purchases ? u.purchases.join(', ') : 'nessuno'}</div>
                    </div>
                    <div style="display: flex; gap: 5px; flex-wrap: wrap;">
                        <button class="btn btn-secondary" onclick="toggleAdmin('${u.user_id}')" title="Toggle Admin">${u.is_admin ? '👤' : '👑'}</button>
                        <button class="btn btn-secondary" onclick="applyReferral('${u.user_id}')" title="Applica Referral">🎁</button>
                    </div>
                </div>
            `}).join('');
            document.getElementById('giftUserSelect').innerHTML = userSelectOptions;
            
            // Load books - use admin endpoint for full details
            try {
                const booksRes = await fetch(API_URL + '/api/admin/books', {
                    headers: { 'Authorization': 'Bearer ' + authToken }
                });
                const books = await booksRes.json();
                window.booksData = books; // Store for edit modal
                document.getElementById('booksList').innerHTML = books.length ? books.map(b => `
                    <div class="user-item" style="cursor: pointer;" onclick='openEditModal(${JSON.stringify(b).replace(/'/g, "\\'")})'>
                        <div class="user-info">
                            <div class="user-name">${b.sort_order || '?'}. ${b.title}</div>
                            <div class="user-email">${b.description || ''}</div>
                            <div style="font-size: 11px; color: #666; margin-top: 4px;">
                                ID: ${b.product_id || 'N/A'} | 
                                PDF: ${b.pdf_url ? '✅' : '❌ MANCA'}
                            </div>
                        </div>
                        <div style="display: flex; gap: 5px;">
                            <button class="btn btn-secondary" onclick="event.stopPropagation(); deleteBook('${b.book_id}')">🗑️</button>
                        </div>
                    </div>
                `).join('') : '<p style="color:#888">Nessun libro</p>';
            } catch (e) {
                console.log('Error loading books:', e);
            }

            // Load tutorials
            try {
                const tutorialsRes = await fetch(API_URL + '/api/admin/tutorials', {
                    headers: { 'Authorization': 'Bearer ' + authToken }
                });
                const tutorials = await tutorialsRes.json();
                document.getElementById('tutorialsList').innerHTML = tutorials.length ? tutorials.map(t => `
                    <div class="user-item">
                        <div class="user-info">
                            <div class="user-name">${t.title} ${t.is_free ? '<span class="badge badge-push">FREE</span>' : '<span class="badge badge-premium">PREMIUM</span>'}</div>
                            <div class="user-email">${t.description || t.url}</div>
                        </div>
                        <button class="btn btn-secondary" onclick="deleteTutorial('${t.tutorial_id}')">🗑️</button>
                    </div>
                `).join('') : '<p style="color:#888">Nessun tutorial</p>';
            } catch (e) {
                console.log('Error loading tutorials');
            }
        }

        async function sendNotification() {
            const title = document.getElementById('notifTitle').value;
            const body = document.getElementById('notifBody').value;
            
            if (!title || !body) {
                alert('Inserisci titolo e messaggio');
                return;
            }
            
            const res = await fetch(API_URL + '/api/admin/send-notification', {
                method: 'POST',
                headers: { 
                    'Authorization': 'Bearer ' + authToken,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ title, body })
            });
            const data = await res.json();
            
            document.getElementById('notifResult').innerHTML = `
                <div class="alert alert-success">
                    📱 iOS: ${data.sent_ios || 0} | 🤖 Android: ${data.sent_android || 0} | ❌ Errori: ${data.errors || 0}
                </div>
            `;
            document.getElementById('notifTitle').value = '';
            document.getElementById('notifBody').value = '';
        }

        async function scheduleNotification() {
            const title = document.getElementById('schedNotifTitle').value;
            const body = document.getElementById('schedNotifBody').value;
            const date = document.getElementById('schedDate').value;
            const time = document.getElementById('schedTime').value;
            
            if (!title || !body || !date || !time) {
                alert('Inserisci tutti i campi: titolo, messaggio, data e ora');
                return;
            }
            
            const scheduledAt = `${date}T${time}:00`;
            
            try {
                const res = await fetch(API_URL + '/api/admin/schedule-notification', {
                    method: 'POST',
                    headers: { 
                        'Authorization': 'Bearer ' + authToken,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ title, body, scheduled_at: scheduledAt })
                });
                const data = await res.json();
                
                if (res.ok) {
                    document.getElementById('schedResult').innerHTML = `
                        <div class="alert alert-success">✅ Notifica programmata per ${date} alle ${time}</div>
                    `;
                    document.getElementById('schedNotifTitle').value = '';
                    document.getElementById('schedNotifBody').value = '';
                    document.getElementById('schedDate').value = '';
                    document.getElementById('schedTime').value = '';
                    loadScheduledNotifications();
                } else {
                    document.getElementById('schedResult').innerHTML = `
                        <div class="alert alert-danger">❌ ${data.detail || 'Errore'}</div>
                    `;
                }
            } catch (e) {
                document.getElementById('schedResult').innerHTML = `
                    <div class="alert alert-danger">❌ Errore di connessione</div>
                `;
            }
        }

        async function loadScheduledNotifications() {
            try {
                const res = await fetch(API_URL + '/api/admin/scheduled-notifications', {
                    headers: { 'Authorization': 'Bearer ' + authToken }
                });
                const notifications = await res.json();
                
                const pending = notifications.filter(n => !n.sent);
                const sent = notifications.filter(n => n.sent);
                
                let html = '';
                
                if (pending.length > 0) {
                    html += '<h4 style="color: #FFD700; margin-bottom: 10px;">⏳ In attesa</h4>';
                    pending.forEach(n => {
                        const schedDate = new Date(n.scheduled_at);
                        html += `
                            <div class="user-item">
                                <div class="user-info">
                                    <div class="user-name">${n.title}</div>
                                    <div class="user-email">${n.body}</div>
                                    <div style="color: #FFD700; font-size: 12px; margin-top: 5px;">
                                        📅 ${schedDate.toLocaleDateString('it-IT')} alle ${schedDate.toLocaleTimeString('it-IT', {hour: '2-digit', minute:'2-digit'})}
                                    </div>
                                </div>
                                <button class="btn btn-secondary" onclick="deleteScheduledNotification('${n.notification_id}')" title="Cancella">🗑️</button>
                            </div>
                        `;
                    });
                }
                
                if (sent.length > 0) {
                    html += '<h4 style="color: #888; margin: 20px 0 10px 0;">✅ Inviate</h4>';
                    sent.slice(0, 5).forEach(n => {
                        const sentDate = new Date(n.sent_at);
                        html += `
                            <div class="user-item" style="opacity: 0.6;">
                                <div class="user-info">
                                    <div class="user-name">${n.title}</div>
                                    <div class="user-email" style="font-size: 11px;">
                                        ${sentDate.toLocaleDateString('it-IT')} - iOS: ${n.result?.sent_ios || 0}, Android: ${n.result?.sent_android || 0}
                                    </div>
                                </div>
                            </div>
                        `;
                    });
                }
                
                if (!html) {
                    html = '<p style="color:#888">Nessuna notifica programmata</p>';
                }
                
                document.getElementById('scheduledList').innerHTML = html;
            } catch (e) {
                console.log('Error loading scheduled notifications:', e);
            }
        }

        async function deleteScheduledNotification(notificationId) {
            if (!confirm('Vuoi cancellare questa notifica programmata?')) return;
            
            try {
                const res = await fetch(API_URL + '/api/admin/scheduled-notifications/' + notificationId, {
                    method: 'DELETE',
                    headers: { 'Authorization': 'Bearer ' + authToken }
                });
                
                if (res.ok) {
                    loadScheduledNotifications();
                } else {
                    const data = await res.json();
                    alert('Errore: ' + (data.detail || 'Errore sconosciuto'));
                }
            } catch (e) {
                alert('Errore di connessione');
            }
        }

        async function addBook() {
            const book = {
                title: document.getElementById('bookTitle').value,
                description: document.getElementById('bookDesc').value,
                cover_url: document.getElementById('bookCover').value,
                pdf_url: document.getElementById('bookPdf').value,
                product_id: document.getElementById('bookProductId').value || 'book_single',
                sort_order: parseInt(document.getElementById('bookOrder').value) || 1
            };
            
            if (!book.title || !book.cover_url || !book.pdf_url) {
                alert('Compila tutti i campi obbligatori (Titolo, Cover, PDF)');
                return;
            }
            
            await fetch(API_URL + '/api/admin/books', {
                method: 'POST',
                headers: { 
                    'Authorization': 'Bearer ' + authToken,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(book)
            });
            
            // Clear form and reload
            document.getElementById('bookTitle').value = '';
            document.getElementById('bookDesc').value = '';
            document.getElementById('bookCover').value = '';
            document.getElementById('bookPdf').value = '';
            document.getElementById('bookProductId').value = '';
            document.getElementById('bookOrder').value = '1';
            loadData();
        }

        async function deleteBook(bookId) {
            if (!confirm('Sei sicuro di voler eliminare questo libro?')) return;
            
            await fetch(API_URL + '/api/admin/books/' + bookId, {
                method: 'DELETE',
                headers: { 'Authorization': 'Bearer ' + authToken }
            });
            loadData();
        }

        function openEditModal(book) {
            document.getElementById('editBookId').value = book.book_id;
            document.getElementById('editBookTitle').value = book.title || '';
            document.getElementById('editBookDesc').value = book.description || '';
            document.getElementById('editBookCover').value = book.cover_url || '';
            document.getElementById('editBookPdf').value = book.pdf_url || '';
            document.getElementById('editBookProductId').value = book.product_id || '';
            document.getElementById('editBookOrder').value = book.sort_order || 1;
            document.getElementById('editBookModal').style.display = 'block';
        }

        function closeEditModal() {
            document.getElementById('editBookModal').style.display = 'none';
        }

        async function saveBookEdit() {
            const bookId = document.getElementById('editBookId').value;
            const book = {
                title: document.getElementById('editBookTitle').value,
                description: document.getElementById('editBookDesc').value,
                cover_url: document.getElementById('editBookCover').value,
                pdf_url: document.getElementById('editBookPdf').value,
                product_id: document.getElementById('editBookProductId').value,
                sort_order: parseInt(document.getElementById('editBookOrder').value) || 1
            };
            
            try {
                const res = await fetch(API_URL + '/api/admin/books/' + bookId, {
                    method: 'PUT',
                    headers: { 
                        'Authorization': 'Bearer ' + authToken,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(book)
                });
                
                if (res.ok) {
                    alert('Libro aggiornato!');
                    closeEditModal();
                    loadData();
                } else {
                    const data = await res.json();
                    alert('Errore: ' + (data.detail || 'Errore sconosciuto'));
                }
            } catch (e) {
                alert('Errore di connessione');
            }
        }

        async function addTutorial() {
            const tutorial = {
                title: document.getElementById('tutorialTitle').value,
                description: document.getElementById('tutorialDesc').value,
                image_url: document.getElementById('tutorialImage').value,
                url: document.getElementById('tutorialUrl').value,
                is_free: document.getElementById('tutorialFree').checked
            };
            
            if (!tutorial.title || !tutorial.url) {
                alert('Inserisci almeno titolo e URL');
                return;
            }
            
            await fetch(API_URL + '/api/admin/tutorials', {
                method: 'POST',
                headers: { 
                    'Authorization': 'Bearer ' + authToken,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(tutorial)
            });
            
            // Clear form and reload
            document.getElementById('tutorialTitle').value = '';
            document.getElementById('tutorialDesc').value = '';
            document.getElementById('tutorialImage').value = '';
            document.getElementById('tutorialUrl').value = '';
            document.getElementById('tutorialFree').checked = false;
            loadData();
        }

        async function deleteTutorial(tutorialId) {
            if (!confirm('Sei sicuro di voler eliminare questo tutorial?')) return;
            
            await fetch(API_URL + '/api/admin/tutorials/' + tutorialId, {
                method: 'DELETE',
                headers: { 'Authorization': 'Bearer ' + authToken }
            });
            loadData();
        }

        async function createUser() {
            const name = document.getElementById('newUserName').value;
            const email = document.getElementById('newUserEmail').value;
            const password = document.getElementById('newUserPassword').value;
            const isAdmin = document.getElementById('newUserAdmin').checked;
            
            if (!name || !email || !password) {
                alert('Compila tutti i campi');
                return;
            }
            
            try {
                const res = await fetch(API_URL + '/api/admin/create-user', {
                    method: 'POST',
                    headers: { 
                        'Authorization': 'Bearer ' + authToken,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ name, email, password, is_admin: isAdmin })
                });
                const data = await res.json();
                
                if (res.ok) {
                    document.getElementById('createUserResult').innerHTML = `
                        <div class="alert alert-success">Utente creato: ${email}</div>
                    `;
                    document.getElementById('newUserName').value = '';
                    document.getElementById('newUserEmail').value = '';
                    document.getElementById('newUserPassword').value = '';
                    document.getElementById('newUserAdmin').checked = false;
                    loadData();
                } else {
                    document.getElementById('createUserResult').innerHTML = `
                        <div class="alert alert-error">${data.detail || 'Errore'}</div>
                    `;
                }
            } catch (e) {
                document.getElementById('createUserResult').innerHTML = `
                    <div class="alert alert-error">Errore di connessione</div>
                `;
            }
        }

        async function giftBook() {
            const userId = document.getElementById('giftUserSelect').value;
            const productId = document.getElementById('giftProductSelect').value;
            
            if (!userId || !productId) {
                alert('Seleziona utente e prodotto');
                return;
            }
            
            try {
                const res = await fetch(API_URL + '/api/admin/gift-book', {
                    method: 'POST',
                    headers: { 
                        'Authorization': 'Bearer ' + authToken,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ user_id: userId, product_id: productId })
                });
                const data = await res.json();
                
                if (res.ok) {
                    document.getElementById('giftResult').innerHTML = `
                        <div class="alert alert-success">🎁 ${data.message}</div>
                    `;
                    loadData();
                } else {
                    document.getElementById('giftResult').innerHTML = `
                        <div class="alert alert-error">${data.detail || 'Errore'}</div>
                    `;
                }
            } catch (e) {
                document.getElementById('giftResult').innerHTML = `
                    <div class="alert alert-error">Errore di connessione</div>
                `;
            }
        }

        async function toggleAdmin(userId) {
            if (!confirm('Sei sicuro di voler cambiare lo stato admin di questo utente?')) return;
            
            try {
                const res = await fetch(API_URL + '/api/admin/toggle-admin/' + userId, {
                    method: 'POST',
                    headers: { 'Authorization': 'Bearer ' + authToken }
                });
                const data = await res.json();
                alert(data.message);
                loadData();
            } catch (e) {
                alert('Errore');
            }
        }

        async function applyReferral(userId) {
            try {
                const res = await fetch(API_URL + '/api/admin/apply-referral/' + userId, {
                    method: 'POST',
                    headers: { 'Authorization': 'Bearer ' + authToken }
                });
                const data = await res.json();
                alert(data.message);
                loadData();
            } catch (e) {
                alert('Errore');
            }
        }
    </script>
</body>
</html>
"""

@app.get("/admin", response_class=HTMLResponse)
async def admin_panel():
    """Pannello admin web"""
    return ADMIN_HTML

@app.get("/", response_class=HTMLResponse)
async def root():
    """Redirect to admin panel"""
    return """
    <html>
        <head><meta http-equiv="refresh" content="0; url=/admin"></head>
        <body><a href="/admin">Vai al pannello admin</a></body>
    </html>
    """

# =============================================================================
# AI TOOLS - Generatore Idee e Moodboard
# =============================================================================

class AIRequest(BaseModel):
    prompt: str
    tool_type: str  # "ideas" o "moodboard"

class AIResponse(BaseModel):
    content: str
    remaining_today: int

# Limite giornaliero per utenti normali
AI_DAILY_LIMIT = 2  # Per idee e moodboard
AI_LIGHTING_DAILY_LIMIT = 2  # Per analisi foto

async def check_ai_limit(user_id: str, is_admin: bool, tool_type: str = "general") -> int:
    """Controlla e restituisce le richieste rimanenti"""
    if is_admin:
        return 999  # Admin illimitato
    
    today = datetime.utcnow().strftime("%Y-%m-%d")
    
    # Usa limiti diversi per lighting
    if tool_type == "lighting":
        usage = await db.ai_lighting_usage.find_one({"user_id": user_id, "date": today})
        limit = AI_LIGHTING_DAILY_LIMIT
    else:
        usage = await db.ai_usage.find_one({"user_id": user_id, "date": today})
        limit = AI_DAILY_LIMIT
    
    if not usage:
        return limit
    
    return max(0, limit - usage.get("count", 0))

async def increment_ai_usage(user_id: str, tool_type: str = "general"):
    """Incrementa il contatore di utilizzo AI"""
    today = datetime.utcnow().strftime("%Y-%m-%d")
    
    if tool_type == "lighting":
        collection = db.ai_lighting_usage
    else:
        collection = db.ai_usage
    
    await collection.update_one(
        {"user_id": user_id, "date": today},
        {"$inc": {"count": 1}},
        upsert=True
    )

@app.get("/api/ai/remaining")
async def get_ai_remaining(user: dict = Depends(get_current_user)):
    """Restituisce le richieste AI rimanenti per oggi"""
    is_admin = user.get("email", "").lower() == ADMIN_EMAIL.lower()
    remaining = await check_ai_limit(user["user_id"], is_admin, "general")
    remaining_lighting = await check_ai_limit(user["user_id"], is_admin, "lighting")
    return {
        "remaining": remaining, 
        "limit": AI_DAILY_LIMIT if not is_admin else "unlimited",
        "remaining_lighting": remaining_lighting,
        "limit_lighting": AI_LIGHTING_DAILY_LIMIT if not is_admin else "unlimited"
    }

@app.post("/api/ai/generate")
async def generate_ai_content(request: AIRequest, user: dict = Depends(get_current_user)):
    """Genera contenuto AI (idee shooting o moodboard)"""
    is_admin = user.get("email", "").lower() == ADMIN_EMAIL.lower()
    remaining = await check_ai_limit(user["user_id"], is_admin)
    
    if remaining <= 0 and not is_admin:
        raise HTTPException(
            status_code=429, 
            detail="Hai raggiunto il limite giornaliero di 5 richieste AI. Torna domani!"
        )
    
    if not EMERGENT_LLM_KEY:
        raise HTTPException(status_code=500, detail="AI non configurata")
    
    try:
        # Configura il prompt in base al tipo di tool
        if request.tool_type == "ideas":
            system_message = """Sei un consulente creativo per fotografi professionisti. 
            Genera 5 idee creative e dettagliate per uno shooting fotografico basato sul tema richiesto.
            Per ogni idea includi:
            - Titolo dell'idea
            - Location consigliata
            - Orario migliore (golden hour, blue hour, ecc.)
            - Setup luci suggerito
            - Mood/atmosfera
            - Props o elementi da includere
            Rispondi in italiano in modo professionale ma accessibile."""
        else:  # moodboard
            system_message = """Sei un art director specializzato in fotografia.
            Crea una moodboard testuale dettagliata per il tipo di shooting richiesto.
            Includi:
            - Palette colori (descrivi 4-5 colori con i loro codici hex)
            - Atmosfera generale
            - Stile fotografico di riferimento
            - Abbigliamento/styling suggerito
            - Props e accessori
            - Riferimenti artistici/fotografici
            - Musica di sottofondo suggerita per il set
            Rispondi in italiano in modo professionale e ispirazionale."""
        
        # Crea la chat AI con OpenAI direttamente
        client = OpenAI(api_key=EMERGENT_LLM_KEY)
        
        completion = client.chat.completions.create(
            model="gpt-4.1-mini",
            messages=[
                {"role": "system", "content": system_message},
                {"role": "user", "content": request.prompt}
            ]
        )
        response = completion.choices[0].message.content
        
        # Incrementa il contatore (solo per non-admin)
        if not is_admin:
            await increment_ai_usage(user["user_id"])
        
        new_remaining = await check_ai_limit(user["user_id"], is_admin)
        
        return {
            "content": response,
            "remaining_today": new_remaining
        }
        
    except Exception as e:
        logger.error(f"AI generation error: {e}")
        raise HTTPException(status_code=500, detail=f"Errore nella generazione: {str(e)}")

class AILightingRequest(BaseModel):
    image_base64: str  # Immagine in base64

@app.post("/api/ai/analyze-lighting")
async def analyze_lighting(request: AILightingRequest, user: dict = Depends(get_current_user)):
    """Analizza l'illuminazione di una foto portrait"""
    is_admin = user.get("email", "").lower() == ADMIN_EMAIL.lower()
    remaining = await check_ai_limit(user["user_id"], is_admin, "lighting")
    
    if remaining <= 0 and not is_admin:
        raise HTTPException(
            status_code=429, 
            detail="Hai raggiunto il limite giornaliero di 2 analisi. Torna domani!"
        )
    
    if not EMERGENT_LLM_KEY:
        raise HTTPException(status_code=500, detail="AI non configurata")
    
    try:
        system_message = """Sei un esperto di illuminazione fotografica professionale.
Analizza l'immagine e determina PRIMA DI TUTTO se si tratta di un ritratto fotografico realizzato con luce controllata (studio, flash, softbox, ecc.).

SE NON è un ritratto con luce controllata (es. paesaggio, tramonto, monumento, foto di strada, selfie con luce naturale, foto di oggetti, ecc.), rispondi ESATTAMENTE con:
"La foto caricata non è un portrait realizzato con luce controllata."

SE È un ritratto con luce controllata, fornisci un'analisi dettagliata includendo:

1. **Schema di illuminazione**: (Rembrandt, Butterfly, Loop, Split, Broad, Short, ecc.)
2. **Luce principale (Key Light)**:
   - Posizione (es. 45° a sinistra, dall'alto)
   - Tipo probabile (softbox, beauty dish, ombrello, luce naturale modificata)
   - Qualità (dura/morbida)
3. **Luce di riempimento (Fill Light)**: se presente, posizione e intensità
4. **Luce di contorno (Rim/Hair Light)**: se presente
5. **Sfondo**: come è illuminato
6. **Rapporto di illuminazione stimato**: (es. 2:1, 3:1, 4:1)
7. **Suggerimenti per ricrearlo**: equipaggiamento necessario e setup

Rispondi in italiano in modo tecnico ma comprensibile."""

        # Crea la chat AI con OpenAI direttamente (con supporto immagini)
        client = OpenAI(api_key=EMERGENT_LLM_KEY)
        
        completion = client.chat.completions.create(
            model="gpt-4.1-mini",
            messages=[
                {"role": "system", "content": system_message},
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "Analizza l'illuminazione di questa foto."},
                        {
                            "type": "image_url",
                            "image_url": {
                                "url": f"data:image/jpeg;base64,{request.image_base64}"
                            }
                        }
                    ]
                }
            ]
        )
        response = completion.choices[0].message.content
        
        # Incrementa il contatore (solo per non-admin)
        if not is_admin:
            await increment_ai_usage(user["user_id"], "lighting")
        
        new_remaining = await check_ai_limit(user["user_id"], is_admin, "lighting")
        
        return {
            "content": response,
            "remaining_today": new_remaining
        }
        
    except Exception as e:
        logger.error(f"AI lighting analysis error: {e}")
        raise HTTPException(status_code=500, detail=f"Errore nell'analisi: {str(e)}")

# =============================================================================
# HOME BADGES
# =============================================================================

@app.get("/api/home-badges")
async def get_home_badges():
    """Get active home badges (public endpoint)"""
    try:
        badges = []
        for badge_id in [1, 2]:
            badge = await db.home_badges.find_one({"badge_id": badge_id})
            if badge:
                # Check if badge should auto-expire
                if badge.get("active") and badge.get("auto_expire_24h") and badge.get("activated_at"):
                    activated_at = badge["activated_at"]
                    if datetime.utcnow() - activated_at > timedelta(hours=24):
                        # Auto-deactivate
                        await db.home_badges.update_one(
                            {"badge_id": badge_id},
                            {"$set": {"active": False}}
                        )
                        badge["active"] = False
                
                if badge.get("active"):
                    badges.append({
                        "badge_id": badge["badge_id"],
                        "text": badge.get("text", ""),
                        "link": badge.get("link", ""),
                    })
        
        return {"badges": badges}
    except Exception as e:
        logger.error(f"Error getting home badges: {e}")
        return {"badges": []}

@app.get("/api/admin/home-badges")
async def get_admin_home_badges(current_user: dict = Depends(get_current_user)):
    """Get all home badges for admin (with full details)"""
    if not current_user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Solo admin può gestire i badge")
    
    try:
        badges = []
        for badge_id in [1, 2]:
            badge = await db.home_badges.find_one({"badge_id": badge_id})
            if not badge:
                # Create default badge
                badge = {
                    "badge_id": badge_id,
                    "active": False,
                    "text": "",
                    "link": "",
                    "auto_expire_24h": False,
                    "activated_at": None,
                    "updated_at": datetime.utcnow()
                }
                await db.home_badges.insert_one(badge)
            
            # Check auto-expire status
            expired = False
            if badge.get("active") and badge.get("auto_expire_24h") and badge.get("activated_at"):
                if datetime.utcnow() - badge["activated_at"] > timedelta(hours=24):
                    await db.home_badges.update_one(
                        {"badge_id": badge_id},
                        {"$set": {"active": False}}
                    )
                    badge["active"] = False
                    expired = True
            
            badges.append({
                "badge_id": badge["badge_id"],
                "active": badge.get("active", False),
                "text": badge.get("text", ""),
                "link": badge.get("link", ""),
                "auto_expire_24h": badge.get("auto_expire_24h", False),
                "activated_at": badge.get("activated_at").isoformat() if badge.get("activated_at") else None,
                "updated_at": badge.get("updated_at").isoformat() if badge.get("updated_at") else None,
                "expired": expired,
            })
        
        return {"badges": badges}
    except Exception as e:
        logger.error(f"Error getting admin home badges: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/api/admin/home-badges/{badge_id}")
async def update_home_badge(
    badge_id: int,
    badge_data: HomeBadgeUpdate,
    current_user: dict = Depends(get_current_user)
):
    """Update a home badge (admin only)"""
    if not current_user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Solo admin può gestire i badge")
    
    if badge_id not in [1, 2]:
        raise HTTPException(status_code=400, detail="Badge ID deve essere 1 o 2")
    
    try:
        # Get current badge to check if we're activating it
        current_badge = await db.home_badges.find_one({"badge_id": badge_id})
        was_active = current_badge.get("active", False) if current_badge else False
        
        update_data = {
            "badge_id": badge_id,
            "active": badge_data.active,
            "text": badge_data.text,
            "link": badge_data.link,
            "auto_expire_24h": badge_data.auto_expire_24h,
            "updated_at": datetime.utcnow()
        }
        
        # Set activated_at timestamp when badge is activated
        if badge_data.active and not was_active:
            update_data["activated_at"] = datetime.utcnow()
        elif not badge_data.active:
            update_data["activated_at"] = None
        
        await db.home_badges.update_one(
            {"badge_id": badge_id},
            {"$set": update_data},
            upsert=True
        )
        
        return {
            "success": True,
            "message": f"Badge {badge_id} aggiornato",
            "badge": {
                "badge_id": badge_id,
                "active": badge_data.active,
                "text": badge_data.text,
                "link": badge_data.link,
                "auto_expire_24h": badge_data.auto_expire_24h,
            }
        }
    except Exception as e:
        logger.error(f"Error updating home badge: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# =============================================================================
# HOME BANNERS (Slideshow in home)
# =============================================================================

@app.get("/api/home-banners")
async def get_home_banners():
    """Get all active home banners for slideshow"""
    try:
        banners = await db.home_banners.find({"active": True}).sort("order", 1).to_list(6)
        result = []
        for banner in banners:
            # Se l'immagine è base64 nel DB, usa quella. Altrimenti usa l'URL legacy
            image_data = banner.get("image_base64") or banner.get("image_url", "")
            result.append({
                "id": banner.get("banner_id"),
                "image_url": image_data,
                "link_type": banner.get("link_type", "none"),
                "link_url": banner.get("link_url", ""),
                "order": banner.get("order", 0),
            })
        return result
    except Exception as e:
        logger.error(f"Error fetching home banners: {e}")
        return []

@app.get("/api/admin/home-banners")
async def get_admin_home_banners(current_user: dict = Depends(get_current_user)):
    """Get all home banners for admin (including inactive)"""
    if not current_user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Solo admin")
    
    try:
        banners = await db.home_banners.find().sort("order", 1).to_list(10)
        result = []
        for banner in banners:
            # Se l'immagine è base64 nel DB, usa quella
            image_data = banner.get("image_base64") or banner.get("image_url", "")
            result.append({
                "id": banner.get("banner_id"),
                "image_url": image_data,
                "link_type": banner.get("link_type", "none"),
                "link_url": banner.get("link_url", ""),
                "order": banner.get("order", 0),
                "active": banner.get("active", True),
                "created_at": banner.get("created_at", "").isoformat() if banner.get("created_at") else None,
            })
        return result
    except Exception as e:
        logger.error(f"Error fetching admin home banners: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/admin/home-banners")
async def create_home_banner(
    banner_data: HomeBannerCreate,
    current_user: dict = Depends(get_current_user)
):
    """Create a new home banner - salva immagine come base64 nel DB"""
    if not current_user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Solo admin")
    
    # Check max 6 banners
    count = await db.home_banners.count_documents({})
    if count >= 6:
        raise HTTPException(status_code=400, detail="Massimo 6 banner. Elimina uno esistente prima.")
    
    try:
        banner_id = f"banner_{secrets.token_hex(6)}"
        
        # Salva l'immagine base64 direttamente nel database (persistente)
        image_base64 = banner_data.image_base64
        
        banner = {
            "banner_id": banner_id,
            "image_base64": image_base64,  # Salva base64 nel DB
            "image_url": "",  # Legacy field, vuoto
            "link_type": banner_data.link_type,
            "link_url": banner_data.link_url,
            "order": banner_data.order,
            "active": banner_data.active,
            "created_at": datetime.utcnow(),
        }
        
        await db.home_banners.insert_one(banner)
        
        return {
            "success": True,
            "message": "Banner creato",
            "banner": {
                "id": banner_id,
                "image_url": image_base64,
                "link_type": banner_data.link_type,
                "link_url": banner_data.link_url,
                "order": banner_data.order,
                "active": banner_data.active,
            }
        }
    except Exception as e:
        logger.error(f"Error creating home banner: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/api/admin/home-banners/{banner_id}")
async def update_home_banner(
    banner_id: str,
    banner_data: HomeBannerUpdate,
    current_user: dict = Depends(get_current_user)
):
    """Update a home banner - salva immagine come base64 nel DB"""
    if not current_user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Solo admin")
    
    try:
        update_data = {"updated_at": datetime.utcnow()}
        
        if banner_data.image_base64:
            # Salva la nuova immagine base64 nel database
            update_data["image_base64"] = banner_data.image_base64
            update_data["image_url"] = ""  # Clear legacy field
        
        if banner_data.link_type is not None:
            update_data["link_type"] = banner_data.link_type
        if banner_data.link_url is not None:
            update_data["link_url"] = banner_data.link_url
        if banner_data.order is not None:
            update_data["order"] = banner_data.order
        if banner_data.active is not None:
            update_data["active"] = banner_data.active
        
        result = await db.home_banners.update_one(
            {"banner_id": banner_id},
            {"$set": update_data}
        )
        
        if result.matched_count == 0:
            raise HTTPException(status_code=404, detail="Banner non trovato")
        
        return {"success": True, "message": "Banner aggiornato"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating home banner: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/admin/home-banners/{banner_id}")
async def delete_home_banner(
    banner_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Delete a home banner"""
    if not current_user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Solo admin")
    
    try:
        result = await db.home_banners.delete_one({"banner_id": banner_id})
        
        if result.deleted_count == 0:
            raise HTTPException(status_code=404, detail="Banner non trovato")
        
        return {"success": True, "message": "Banner eliminato"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting home banner: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# =============================================================================
# IMAGE ANALYSIS (Strumento Analisi PRO)
# =============================================================================

from PIL import Image
import io
import base64
from collections import Counter

class ImageAnalysisRequest(BaseModel):
    image_base64: str  # Base64 encoded image

class ImageAnalysisResponse(BaseModel):
    histogram: dict  # r, g, b, lum arrays
    colors: dict  # dominant, palette, temperature, saturation
    exposure: dict  # avgBrightness, shadows, midtones, highlights, clipping

@app.post("/api/analyze-image", response_model=ImageAnalysisResponse)
async def analyze_image(request: ImageAnalysisRequest):
    """
    Analizza un'immagine e restituisce istogramma reale, colori dominanti e dati esposizione.
    Questo endpoint processa l'immagine usando PIL/Pillow per analisi pixel-level.
    """
    try:
        # Decodifica l'immagine base64
        image_data = request.image_base64
        # Rimuovi header se presente (es: "data:image/jpeg;base64,")
        if "," in image_data:
            image_data = image_data.split(",")[1]
        
        image_bytes = base64.b64decode(image_data)
        image = Image.open(io.BytesIO(image_bytes))
        
        # Converti in RGB se necessario
        if image.mode != 'RGB':
            image = image.convert('RGB')
        
        # Ridimensiona per performance (max 800px sul lato lungo)
        max_size = 800
        ratio = min(max_size / image.width, max_size / image.height)
        if ratio < 1:
            new_size = (int(image.width * ratio), int(image.height * ratio))
            image = image.resize(new_size, Image.Resampling.LANCZOS)
        
        # ===== CALCOLO ISTOGRAMMA REALE =====
        # Ottieni i dati dei pixel
        pixels = list(image.getdata())
        width, height = image.size
        total_pixels = width * height
        
        # Inizializza bins (64 bins per canale, come nel frontend)
        num_bins = 64
        r_hist = [0] * num_bins
        g_hist = [0] * num_bins
        b_hist = [0] * num_bins
        lum_hist = [0] * num_bins
        
        # Variabili per analisi colori
        all_colors = []
        brightness_sum = 0
        
        # Processa ogni pixel
        for r, g, b in pixels:
            # Bin index (0-255 -> 0-63)
            r_bin = min(r * num_bins // 256, num_bins - 1)
            g_bin = min(g * num_bins // 256, num_bins - 1)
            b_bin = min(b * num_bins // 256, num_bins - 1)
            
            # Luminosità (formula standard)
            lum = int(0.299 * r + 0.587 * g + 0.114 * b)
            lum_bin = min(lum * num_bins // 256, num_bins - 1)
            
            r_hist[r_bin] += 1
            g_hist[g_bin] += 1
            b_hist[b_bin] += 1
            lum_hist[lum_bin] += 1
            
            brightness_sum += lum
            
            # Quantizza colore per analisi dominante (dividi per 32 per ridurre variazioni)
            quantized = ((r // 32) * 32, (g // 32) * 32, (b // 32) * 32)
            all_colors.append(quantized)
        
        # Normalizza istogrammi (0-1)
        max_r = max(r_hist) if max(r_hist) > 0 else 1
        max_g = max(g_hist) if max(g_hist) > 0 else 1
        max_b = max(b_hist) if max(b_hist) > 0 else 1
        max_lum = max(lum_hist) if max(lum_hist) > 0 else 1
        
        histogram = {
            "r": [v / max_r for v in r_hist],
            "g": [v / max_g for v in g_hist],
            "b": [v / max_b for v in b_hist],
            "lum": [v / max_lum for v in lum_hist],
        }
        
        # ===== ANALISI COLORI =====
        # Trova i colori più comuni
        color_counter = Counter(all_colors)
        top_colors = color_counter.most_common(6)
        
        dominant_rgb = top_colors[0][0] if top_colors else (128, 128, 128)
        
        # Converti in stringa hex
        dominant_hex = '#{:02x}{:02x}{:02x}'.format(*dominant_rgb)
        palette_hex = ['#{:02x}{:02x}{:02x}'.format(*c[0]) for c in top_colors[1:6]]
        
        # Calcola temperatura colore (basato sul rapporto R/B)
        avg_r = sum(p[0] for p in pixels) / total_pixels
        avg_g = sum(p[1] for p in pixels) / total_pixels
        avg_b = sum(p[2] for p in pixels) / total_pixels
        
        # Colore MEDIO dell'immagine (utile per colorimetro e white balance)
        average_hex = '#{:02x}{:02x}{:02x}'.format(int(avg_r), int(avg_g), int(avg_b))
        
        if avg_r > avg_b * 1.1:
            temperature = "caldo"
        elif avg_b > avg_r * 1.1:
            temperature = "freddo"
        else:
            temperature = "neutro"
        
        # Calcola saturazione media
        saturations = []
        for r, g, b in pixels[:10000]:  # Campiona per performance
            max_c = max(r, g, b)
            min_c = min(r, g, b)
            if max_c > 0:
                sat = (max_c - min_c) / max_c * 100
                saturations.append(sat)
        avg_saturation = int(sum(saturations) / len(saturations)) if saturations else 50
        
        colors = {
            "dominant": dominant_hex,
            "average": average_hex,  # Colore MEDIO (per colorimetro/white balance)
            "palette": palette_hex,
            "temperature": temperature,
            "saturation": avg_saturation,
        }
        
        # ===== ANALISI ESPOSIZIONE =====
        avg_brightness = int(brightness_sum / total_pixels)
        
        # Calcola distribuzione zone
        third = num_bins // 3
        shadows_count = sum(lum_hist[:third])
        midtones_count = sum(lum_hist[third:2*third])
        highlights_count = sum(lum_hist[2*third:])
        
        shadows_pct = int(shadows_count / total_pixels * 100)
        midtones_pct = int(midtones_count / total_pixels * 100)
        highlights_pct = int(highlights_count / total_pixels * 100)
        
        # Clipping detection (primi e ultimi 3 bins)
        clipped_shadows = int(sum(lum_hist[:3]) / total_pixels * 100)
        clipped_highlights = int(sum(lum_hist[-3:]) / total_pixels * 100)
        
        exposure = {
            "avgBrightness": avg_brightness,
            "shadows": shadows_pct,
            "midtones": midtones_pct,
            "highlights": highlights_pct,
            "clippedShadows": clipped_shadows,
            "clippedHighlights": clipped_highlights,
        }
        
        return ImageAnalysisResponse(
            histogram=histogram,
            colors=colors,
            exposure=exposure,
        )
        
    except Exception as e:
        logger.error(f"Error analyzing image: {e}")
        raise HTTPException(status_code=500, detail=f"Errore nell'analisi dell'immagine: {str(e)}")

# =============================================================================
# PROJECT DOWNLOAD
# =============================================================================

@app.get("/api/download-project")
async def download_project():
    """Download the complete project as ZIP"""
    zip_path = Path(__file__).parent / "lumina-ingegno-project.zip"
    if not zip_path.exists():
        raise HTTPException(status_code=404, detail="Project ZIP not found")
    return FileResponse(
        path=str(zip_path),
        filename="lumina-ingegno-project.zip",
        media_type="application/zip"
    )

# =============================================================================
# PROMO PRO URL
# =============================================================================

@app.get("/api/promo-url")
async def get_promo_url():
    """Ottieni l'URL della pagina promo PRO"""
    settings = await db.settings.find_one({"type": "promo_pro"})
    if settings and settings.get("url"):
        return {"url": settings["url"]}
    # URL di default se non configurato
    return {"url": "https://luminaingegno.com/pro"}

@app.get("/api/admin/promo-url")
async def admin_get_promo_url(current_user: dict = Depends(get_current_user)):
    """Admin: ottieni URL promo PRO"""
    if not current_user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Accesso negato")
    
    settings = await db.settings.find_one({"type": "promo_pro"})
    if settings:
        return {"url": settings.get("url", "")}
    return {"url": ""}

@app.put("/api/admin/promo-url")
async def admin_update_promo_url(data: dict, current_user: dict = Depends(get_current_user)):
    """Admin: aggiorna URL promo PRO"""
    if not current_user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Accesso negato")
    
    url = data.get("url", "")
    
    await db.settings.update_one(
        {"type": "promo_pro"},
        {"$set": {"url": url, "updated_at": datetime.utcnow()}},
        upsert=True
    )
    
    return {"success": True, "url": url}

# =============================================================================
# STARTUP
# =============================================================================

@app.on_event("startup")
async def startup():
    logger.info("Starting Lumina Ingegno V2 API")
    logger.info(f"Database: {DB_NAME}")
    
    admin = await db.users.find_one({"email": ADMIN_EMAIL.lower()})
    if not admin:
        logger.info(f"Admin will be created on registration: {ADMIN_EMAIL}")
    else:
        logger.info(f"Admin user exists: {ADMIN_EMAIL}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
