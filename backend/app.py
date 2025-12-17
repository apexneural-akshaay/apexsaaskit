import os
from dotenv import load_dotenv
from apex import Client, set_default_client, bootstrap
from apex.email import send_email
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from models import User, Payment
import auth
import payments

load_dotenv()

# Load environment variables from .env
DATABASE_URL = os.getenv('DATABASE_URL')
if not DATABASE_URL:
    raise ValueError("DATABASE_URL must be set in .env file")

SECRET_KEY = os.getenv('SECRET_KEY')
if not SECRET_KEY:
    raise ValueError("SECRET_KEY must be set in .env file")

# SendGrid Configuration
SENDGRID_API_KEY = os.getenv('SENDGRID_API_KEY')
if not SENDGRID_API_KEY:
    raise ValueError("SENDGRID_API_KEY must be set in .env file")

FROM_EMAIL = os.getenv('FROM_EMAIL')
if not FROM_EMAIL:
    raise ValueError("FROM_EMAIL must be set in .env file")

# PayPal Configuration
PAYPAL_CLIENT_ID = os.getenv('PAYPAL_CLIENT_ID')
if not PAYPAL_CLIENT_ID:
    raise ValueError("PAYPAL_CLIENT_ID must be set in .env file")

PAYPAL_CLIENT_SECRET = os.getenv('PAYPAL_CLIENT_SECRET')
if not PAYPAL_CLIENT_SECRET:
    raise ValueError("PAYPAL_CLIENT_SECRET must be set in .env file")

PAYPAL_MODE = os.getenv('PAYPAL_MODE', 'sandbox')

# Frontend URL for CORS and payment redirects
FRONTEND_URL = os.getenv('FRONTEND_URL', 'http://localhost:5173')

# Initialize Apex Client (following documentation pattern)
# Client only accepts: database_url, user_model, secret_key
client = Client(
    database_url=DATABASE_URL,
    user_model=User,
    secret_key=SECRET_KEY,
)

set_default_client(client)

# Create tables only if they don't exist (following reference pattern)
async def init_database():
    """Create tables only if they don't exist, following reference pattern"""
    from apex.infrastructure.database import engine
    from sqlalchemy import text
    
    # Check if users table exists
    async with engine.connect() as conn:
        result = await conn.execute(text("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name = 'users'
            )
        """))
        users_table_exists = result.scalar()
    
    if not users_table_exists:
        # Create tables using async client method (following reference: bootstrap(models=[...]))
        from models import User, Payment
        await client.init_database(models=[User, Payment])
        print("[OK] Created users and payments tables")
    else:
        print("[OK] Tables already exist, skipping creation")

# Create FastAPI app
app = FastAPI(
    title="MicroSaaS API",
    description="Authentication, Payments and Email API",
    version="0.1.0"
)

# Add CORS for frontend (using FRONTEND_URL from .env)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_URL],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pydantic models for requests
class SignupRequest(BaseModel):
    email: EmailStr
    password: str
    password_confirm: str
    first_name: str = None
    last_name: str = None
    username: str = None

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str

class SendEmailRequest(BaseModel):
    to: EmailStr
    subject: str
    body: str
    html: str = None

class CreateOrderRequest(BaseModel):
    amount: float
    currency: str = "USD"
    description: str = "Payment"
    return_url: str = None
    cancel_url: str = None

class CaptureOrderRequest(BaseModel):
    order_id: str

# Authentication Routes - calling functions from auth.py
@app.post("/auth/signup")
async def signup_endpoint(request: SignupRequest):
    """User signup endpoint"""
    try:
        # Validate password confirmation
        if request.password != request.password_confirm:
            raise HTTPException(status_code=400, detail="Passwords do not match")
        
        # Call async signup function
        result = await auth.signup_user(
            email=request.email,
            password=request.password,
            first_name=request.first_name,
            last_name=request.last_name,
            username=request.username
        )
        return result
    except HTTPException:
        raise
    except Exception as e:
        # Log the full error for debugging
        import traceback
        error_detail = str(e)
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Signup failed: {error_detail}")

@app.post("/auth/login")
async def login_endpoint(request: LoginRequest):
    """User login endpoint"""
    try:
        return await auth.login_user(email=request.email, password=request.password)
    except Exception as e:
        raise HTTPException(status_code=401, detail="Invalid credentials")

@app.post("/auth/forgot-password")
async def forgot_password_endpoint(request: ForgotPasswordRequest):
    """Request password reset endpoint"""
    try:
        result = await auth.forgot_password_user(email=request.email)
        if result:
            return result
        else:
            raise HTTPException(status_code=404, detail="User not found")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/auth/reset-password")
async def reset_password_endpoint(request: ResetPasswordRequest):
    """Reset password endpoint"""
    try:
        success = await auth.reset_password_user(token=request.token, new_password=request.new_password)
        if success:
            return {"message": "Password reset successfully"}
        else:
            raise HTTPException(status_code=400, detail="Invalid or expired token")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# Email Routes
@app.post("/email/send")
async def send_email_endpoint(request: SendEmailRequest):
    """Send email using apex.email.send_email"""
    try:
        success = send_email(
            to=request.to,
            subject=request.subject,
            body=request.body,
            html=request.html
        )
        if success:
            return {"message": "Email sent successfully"}
        else:
            raise HTTPException(status_code=500, detail="Failed to send email")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Payment Routes - calling functions from payments.py
@app.post("/payments/create-order")
async def create_order_endpoint(request: CreateOrderRequest):
    """Create PayPal order endpoint"""
    try:
        # Use FRONTEND_URL from .env if return_url/cancel_url not provided
        return_url = request.return_url or f"{FRONTEND_URL}/payment/success"
        cancel_url = request.cancel_url or f"{FRONTEND_URL}/payment/cancel"
        
        return await payments.create_payment_order(
            amount=request.amount,
            currency=request.currency,
            description=request.description,
            return_url=return_url,
            cancel_url=cancel_url
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Payment error: {str(e)}")

@app.post("/payments/capture-order")
async def capture_order_endpoint(request: CaptureOrderRequest):
    """Capture PayPal order endpoint"""
    try:
        return await payments.capture_payment_order(order_id=request.order_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Capture failed: {str(e)}")

@app.get("/payments/order/{order_id}")
async def get_order_endpoint(order_id: str):
    """Get PayPal order status endpoint"""
    try:
        return await payments.get_payment_order(order_id=order_id)
    except Exception as e:
        raise HTTPException(status_code=404, detail=f"Order not found: {str(e)}")

@app.get("/")
async def root():
    return {
        "message": "Welcome to MicroSaaS API",
        "version": "0.1.0",
        "docs": "/docs",
        "redoc": "/redoc"
    }

# Initialize database on startup (create tables only if they don't exist)
@app.on_event("startup")
async def startup_event():
    await init_database()
    print("[OK] Application ready!")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
