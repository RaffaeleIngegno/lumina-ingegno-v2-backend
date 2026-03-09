"""
Lumina Ingegno V2 - Backend API
Completamente nuovo, configurato per Railway + MongoDB Atlas
"""

import os
import secrets
import string
import logging
from datetime import datetime, timedelta
from typing import Optional, List

from fastapi import FastAPI, HTTPException, Depends, Form, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from motor.motor_asyncio import AsyncIOMotorClient
from passlib.context import CryptContext
from jose import JWTError, jwt
import resend
import httpx
from dotenv import load_dotenv

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

# JWT Config
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_DAYS = 30

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Security
security = HTTPBearer(auto_error=False)

# Initialize Resend
if RESEND_API_KEY:
    resend.api_key = RESEND_API_KEY

# MongoDB connection
client = AsyncIOMotorClient(MONGO_URL)
db = client[DB_NAME]

# FastAPI app
app = FastAPI(title="Lumina Ingegno V2 API")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =============================================================================
# MODELS
# =============================================================================

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    name: str

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

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def generate_verification_code() -> str:
    """Generate 6-digit verification code"""
    return ''.join(secrets.choice(string.digits) for _ in range(6))

def generate_referral_code() -> str:
    """Generate referral code: 2 letters + 6 numbers"""
    letters = ''.join(secrets.choice(string.ascii_uppercase) for _ in range(2))
    numbers = ''.join(secrets.choice(string.digits) for _ in range(6))
    return letters + numbers

def generate_user_id() -> str:
    """Generate unique user ID"""
    return f"user_{secrets.token_hex(8)}"

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(days=ACCESS_TOKEN_EXPIRE_DAYS))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Get current authenticated user"""
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
    """Check if user is admin"""
    if not current_user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Accesso negato. Solo admin.")
    return current_user

def user_to_response(user: dict) -> dict:
    """Convert user document to safe response"""
    return {
        "user_id": user.get("user_id"),
        "email": user.get("email"),
        "name": user.get("name"),
        "referral_code": user.get("referral_code"),
        "is_admin": user.get("is_admin", False),
        "plan": user.get("plan", "free"),
        "created_at": user.get("created_at"),
    }

# =============================================================================
# EMAIL FUNCTIONS
# =============================================================================

async def send_verification_email(email: str, code: str, name: str):
    """Send verification email"""
    if not RESEND_API_KEY:
        logger.warning("RESEND_API_KEY not set, skipping email")
        return
    
    try:
        resend.Emails.send({
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
        logger.info(f"Verification email sent to {email}")
    except Exception as e:
        logger.error(f"Error sending email: {e}")

# =============================================================================
# PUSH NOTIFICATIONS
# =============================================================================

async def send_expo_push(token: str, title: str, body: str, data: dict = None):
    """Send push notification via Expo"""
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "https://exp.host/--/api/v2/push/send",
            json={
                "to": token,
                "title": title,
                "body": body,
                "sound": "default",
                "data": data or {}
            }
        )
        return response.json()

# =============================================================================
# API ENDPOINTS
# =============================================================================

@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "message": "Lumina Ingegno V2 API is running"}

# -----------------------------------------------------------------------------
# AUTH ENDPOINTS
# -----------------------------------------------------------------------------

@app.post("/api/auth/register")
async def register(user: UserCreate):
    """Register new user - sends verification code"""
    # Check if email exists
    existing = await db.users.find_one({"email": user.email.lower()})
    if existing and existing.get("is_verified"):
        raise HTTPException(status_code=400, detail="Email già registrata")
    
    # Generate verification code
    code = generate_verification_code()
    expires_at = datetime.utcnow() + timedelta(minutes=10)
    
    # Store pending registration
    await db.pending_registrations.update_one(
        {"email": user.email.lower()},
        {
            "$set": {
                "email": user.email.lower(),
                "password_hash": hash_password(user.password),
                "name": user.name,
                "verification_code": code,
                "code_expires_at": expires_at,
                "created_at": datetime.utcnow()
            }
        },
        upsert=True
    )
    
    # Send verification email
    await send_verification_email(user.email, code, user.name)
    
    return {"message": "Codice di verifica inviato", "email": user.email}

@app.post("/api/auth/verify", response_model=TokenResponse)
async def verify_registration(data: VerifyCode):
    """Verify registration with code"""
    # Find pending registration
    pending = await db.pending_registrations.find_one({"email": data.email.lower()})
    if not pending:
        raise HTTPException(status_code=400, detail="Registrazione non trovata")
    
    # Check code
    if pending.get("verification_code") != data.code:
        raise HTTPException(status_code=400, detail="Codice non valido")
    
    # Check expiration
    if datetime.utcnow() > pending.get("code_expires_at", datetime.utcnow()):
        raise HTTPException(status_code=400, detail="Codice scaduto")
    
    # Create user
    user_id = generate_user_id()
    is_admin = data.email.lower() == ADMIN_EMAIL.lower()
    
    user = {
        "user_id": user_id,
        "email": data.email.lower(),
        "password_hash": pending.get("password_hash"),
        "name": pending.get("name"),
        "referral_code": generate_referral_code(),
        "is_admin": is_admin,
        "is_verified": True,
        "plan": "free",
        "created_at": datetime.utcnow()
    }
    
    await db.users.insert_one(user)
    await db.pending_registrations.delete_one({"email": data.email.lower()})
    
    # Create token
    token = create_access_token({"sub": user_id})
    
    logger.info(f"User registered: {data.email}")
    
    return TokenResponse(
        access_token=token,
        user=user_to_response(user)
    )

@app.post("/api/auth/login", response_model=TokenResponse)
async def login(data: UserLogin):
    """Login user"""
    user = await db.users.find_one({"email": data.email.lower()})
    
    if not user:
        raise HTTPException(status_code=401, detail="Email o password non validi")
    
    if not verify_password(data.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Email o password non validi")
    
    if not user.get("is_verified"):
        raise HTTPException(status_code=401, detail="Account non verificato")
    
    token = create_access_token({"sub": user["user_id"]})
    
    logger.info(f"User logged in: {data.email}")
    
    return TokenResponse(
        access_token=token,
        user=user_to_response(user)
    )

@app.get("/api/auth/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    """Get current user info"""
    return user_to_response(current_user)

# -----------------------------------------------------------------------------
# PUSH TOKEN ENDPOINTS
# -----------------------------------------------------------------------------

@app.post("/api/push-token")
async def register_push_token(
    token: str = Form(...),
    platform: str = Form(...),
    current_user: dict = Depends(get_current_user)
):
    """Register push notification token"""
    await db.users.update_one(
        {"user_id": current_user["user_id"]},
        {"$set": {"push_token": token, "push_platform": platform}}
    )
    logger.info(f"Push token registered for {current_user['email']}")
    return {"message": "Token registrato"}

# -----------------------------------------------------------------------------
# ADMIN ENDPOINTS
# -----------------------------------------------------------------------------

@app.get("/api/admin/users")
async def get_all_users(admin: dict = Depends(get_admin_user)):
    """Get all users (admin only)"""
    users = await db.users.find().to_list(1000)
    return [
        {
            **user_to_response(user),
            "push_token": bool(user.get("push_token")),
        }
        for user in users
    ]

@app.get("/api/admin/users-with-push")
async def get_users_with_push(admin: dict = Depends(get_admin_user)):
    """Get users with push tokens (admin only)"""
    users = await db.users.find({"push_token": {"$exists": True, "$ne": None}}).to_list(1000)
    return [
        {
            "user_id": user.get("user_id"),
            "email": user.get("email"),
            "name": user.get("name"),
            "push_token": user.get("push_token"),
        }
        for user in users
    ]

@app.post("/api/admin/send-notification")
async def send_notification_to_all(
    notification: PushNotification,
    admin: dict = Depends(get_admin_user)
):
    """Send push notification to all users (admin only)"""
    users = await db.users.find({"push_token": {"$exists": True, "$ne": None}}).to_list(1000)
    
    sent = 0
    errors = 0
    
    for user in users:
        try:
            await send_expo_push(
                user["push_token"],
                notification.title,
                notification.body
            )
            sent += 1
        except Exception as e:
            logger.error(f"Error sending push to {user['email']}: {e}")
            errors += 1
    
    return {"sent": sent, "errors": errors, "total": len(users)}

@app.post("/api/admin/send-email-all")
async def send_email_to_all(
    subject: str = Form(...),
    body: str = Form(...),
    admin: dict = Depends(get_admin_user)
):
    """Send email to all users (admin only)"""
    if not RESEND_API_KEY:
        raise HTTPException(status_code=500, detail="Email service not configured")
    
    users = await db.users.find().to_list(1000)
    emails = [user["email"] for user in users if user.get("email")]
    
    sent = 0
    errors = 0
    
    for email in emails:
        try:
            resend.Emails.send({
                "from": "Lumina Ingegno <noreply@raffaeleingegno.com>",
                "to": [email],
                "subject": subject,
                "html": body
            })
            sent += 1
        except Exception as e:
            logger.error(f"Error sending email to {email}: {e}")
            errors += 1
    
    return {"sent": sent, "errors": errors, "total": len(emails)}

# =============================================================================
# STARTUP
# =============================================================================

@app.on_event("startup")
async def startup():
    """Initialize on startup"""
    logger.info(f"Starting Lumina Ingegno V2 API")
    logger.info(f"Database: {DB_NAME}")
    
    # Check if admin exists, create if not
    admin = await db.users.find_one({"email": ADMIN_EMAIL.lower()})
    if not admin:
        logger.info(f"Creating admin user: {ADMIN_EMAIL}")
        # Admin will be created on first registration with admin email
    else:
        logger.info(f"Admin user exists: {ADMIN_EMAIL}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
