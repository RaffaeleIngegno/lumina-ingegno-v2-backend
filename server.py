"""
Lumina Ingegno V2 - Backend API
Configurato per Railway + MongoDB Atlas
Include: Auth, Libri, IAP, Push Notifications, Admin Panel
"""

import os
import secrets
import string
import logging
from datetime import datetime, timedelta
from typing import Optional, List

from fastapi import FastAPI, HTTPException, Depends, Form, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
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
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

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
    return {"status": "healthy", "message": "Lumina Ingegno V2 API is running"}

# -----------------------------------------------------------------------------
# AUTH ENDPOINTS
# -----------------------------------------------------------------------------

@app.post("/api/auth/register")
async def register(user: UserCreate):
    existing = await db.users.find_one({"email": user.email.lower()})
    if existing and existing.get("is_verified"):
        raise HTTPException(status_code=400, detail="Email già registrata")
    
    code = generate_verification_code()
    expires_at = datetime.utcnow() + timedelta(minutes=10)
    
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
    
    user = {
        "user_id": user_id,
        "email": data.email.lower(),
        "password_hash": pending.get("password_hash"),
        "name": pending.get("name"),
        "referral_code": generate_referral_code(),
        "is_admin": is_admin,
        "is_verified": True,
        "plan": "free",
        "purchases": [],
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

@app.post("/api/push-token")
async def register_push_token(
    token: str = Form(...),
    platform: str = Form(...),
    current_user: dict = Depends(get_current_user)
):
    await db.users.update_one(
        {"user_id": current_user["user_id"]},
        {"$set": {"push_token": token, "push_platform": platform}}
    )
    logger.info(f"Push token registered for {current_user['email']}")
    return {"message": "Token registrato"}

# -----------------------------------------------------------------------------
# BOOKS ENDPOINTS
# -----------------------------------------------------------------------------

@app.get("/api/books")
async def get_books(current_user: dict = Depends(get_current_user)):
    """Ottieni lista libri con stato accesso"""
    books = await db.books.find().to_list(100)
    user_purchases = current_user.get("purchases", [])
    has_full_access = "books_full_access" in user_purchases
    
    result = []
    for book in books:
        book_data = {
            "book_id": book.get("book_id"),
            "title": book.get("title"),
            "description": book.get("description"),
            "cover_url": book.get("cover_url"),
            "price": book.get("price", 0),
            "has_access": has_full_access or book.get("book_id") in user_purchases,
        }
        if book_data["has_access"]:
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
    has_access = has_full_access or book_id in user_purchases
    
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
    return [{"news_id": n.get("news_id"), "title": n.get("title"), "content": n.get("content"), 
             "image_url": n.get("image_url"), "created_at": n.get("created_at")} for n in news]

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
    return [{"post_id": p.get("post_id"), "title": p.get("title"), "url": p.get("url"),
             "image_url": p.get("image_url"), "created_at": p.get("created_at")} for p in posts]

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
    users = await db.users.find({"push_token": {"$exists": True, "$ne": None}}).to_list(1000)
    
    sent = 0
    errors = 0
    
    for user in users:
        try:
            await send_expo_push(user["push_token"], notification.title, notification.body)
            sent += 1
        except Exception as e:
            logger.error(f"Error sending push to {user['email']}: {e}")
            errors += 1
    
    return {"sent": sent, "errors": errors, "total": len(users)}

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
        "created_at": datetime.utcnow()
    }
    await db.books.insert_one(book_data)
    return book_data

@app.delete("/api/admin/books/{book_id}")
async def delete_book(book_id: str, admin: dict = Depends(get_admin_user)):
    result = await db.books.delete_one({"book_id": book_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Libro non trovato")
    return {"message": "Libro eliminato"}

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
                <h2>📢 Invia Notifica Push</h2>
                <input type="text" id="notifTitle" placeholder="Titolo notifica">
                <textarea id="notifBody" placeholder="Messaggio"></textarea>
                <button class="btn" onclick="sendNotification()">Invia a tutti gli utenti</button>
                <div id="notifResult"></div>
            </div>

            <!-- Users Tab -->
            <div id="usersTab" class="card hidden">
                <h2>👥 Utenti Registrati</h2>
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
                        <input type="text" id="bookPdf" placeholder="URL PDF">
                        <input type="number" id="bookPrice" placeholder="Prezzo" value="0">
                        <button class="btn" onclick="addBook()">Aggiungi Libro</button>
                    </div>
                    <div>
                        <h3 style="margin-bottom: 15px;">Libri Esistenti</h3>
                        <div id="booksList"></div>
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
            
            // Users list
            document.getElementById('usersList').innerHTML = users.map(u => `
                <div class="user-item">
                    <div class="user-info">
                        <div class="user-name">${u.name} ${u.is_admin ? '<span class="badge badge-admin">Admin</span>' : ''} ${u.has_push_token ? '<span class="badge badge-push">Push</span>' : ''} ${u.plan === 'premium' ? '<span class="badge badge-premium">Premium</span>' : ''}</div>
                        <div class="user-email">${u.email}</div>
                    </div>
                    <div>${u.referral_code}</div>
                </div>
            `).join('');
            
            // Load books
            try {
                const booksRes = await fetch(API_URL + '/api/books', {
                    headers: { 'Authorization': 'Bearer ' + authToken }
                });
                const books = await booksRes.json();
                document.getElementById('booksList').innerHTML = books.length ? books.map(b => `
                    <div class="user-item">
                        <div class="user-info">
                            <div class="user-name">${b.title}</div>
                            <div class="user-email">${b.description || ''}</div>
                        </div>
                        <button class="btn btn-secondary" onclick="deleteBook('${b.book_id}')">🗑️</button>
                    </div>
                `).join('') : '<p style="color:#888">Nessun libro</p>';
            } catch (e) {
                console.log('Error loading books');
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
                <div class="alert alert-success">Notifica inviata a ${data.sent} utenti (${data.errors} errori)</div>
            `;
            document.getElementById('notifTitle').value = '';
            document.getElementById('notifBody').value = '';
        }

        async function addBook() {
            const book = {
                title: document.getElementById('bookTitle').value,
                description: document.getElementById('bookDesc').value,
                cover_url: document.getElementById('bookCover').value,
                pdf_url: document.getElementById('bookPdf').value,
                price: parseFloat(document.getElementById('bookPrice').value) || 0
            };
            
            if (!book.title || !book.cover_url || !book.pdf_url) {
                alert('Compila tutti i campi obbligatori');
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
            document.getElementById('bookPrice').value = '0';
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
# STARTUP
# =============================================================================

@app.on_event("startup")
async def startup():
    logger.info(f"Starting Lumina Ingegno V2 API")
    logger.info(f"Database: {DB_NAME}")
    
    admin = await db.users.find_one({"email": ADMIN_EMAIL.lower()})
    if not admin:
        logger.info(f"Admin will be created on registration: {ADMIN_EMAIL}")
    else:
        logger.info(f"Admin user exists: {ADMIN_EMAIL}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
