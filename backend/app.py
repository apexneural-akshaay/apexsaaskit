import os
from pathlib import Path
from dotenv import load_dotenv
from apex import Client, set_default_client, bootstrap
from apex.email import send_email
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
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

# Files directory for downloadable materials
FILES_DIR = Path(__file__).parent / "files"
FILES_DIR.mkdir(exist_ok=True)  # Create directory if it doesn't exist

# Initialize Apex Client (following documentation pattern)
# Client only accepts: database_url, user_model, secret_key
client = Client(
    database_url=DATABASE_URL,
    user_model=User,
    secret_key=SECRET_KEY,
)

set_default_client(client)

# Helper function to get async database session
def get_db_session():
    """Create async SQLAlchemy session"""
    from apex.infrastructure.database import engine
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
    async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    return async_session()

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
    
    # Add missing columns if they don't exist (for existing databases)
    async with engine.connect() as conn:
        # Check and add payment_method column
        try:
            await conn.execute(text("""
                ALTER TABLE payments 
                ADD COLUMN IF NOT EXISTS payment_method VARCHAR(50) DEFAULT 'paypal' NOT NULL
            """))
        except Exception as e:
            print(f"[INFO] payment_method column: {e}")
        
        # Check and add payment_metadata column
        try:
            await conn.execute(text("""
                ALTER TABLE payments 
                ADD COLUMN IF NOT EXISTS payment_metadata JSONB
            """))
        except Exception as e:
            print(f"[INFO] payment_metadata column: {e}")
        
        # Check and add organization_id column
        try:
            await conn.execute(text("""
                ALTER TABLE payments 
                ADD COLUMN IF NOT EXISTS organization_id UUID
            """))
        except Exception as e:
            print(f"[INFO] organization_id column: {e}")
        
        # Check and add meta column
        try:
            await conn.execute(text("""
                ALTER TABLE payments 
                ADD COLUMN IF NOT EXISTS meta JSONB
            """))
        except Exception as e:
            print(f"[INFO] meta column: {e}")
        
        # Check and add user_email column
        try:
            await conn.execute(text("""
                ALTER TABLE payments 
                ADD COLUMN IF NOT EXISTS user_email VARCHAR(255)
            """))
            await conn.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_payments_user_email ON payments(user_email)
            """))
        except Exception as e:
            print(f"[INFO] user_email column: {e}")
        
        # Make user_id nullable if it's not already
        try:
            await conn.execute(text("""
                ALTER TABLE payments 
                ALTER COLUMN user_id DROP NOT NULL
            """))
        except Exception as e:
            print(f"[INFO] user_id nullable: {e}")
        
        # Make order_id nullable if it's not already
        try:
            await conn.execute(text("""
                ALTER TABLE payments 
                ALTER COLUMN order_id DROP NOT NULL
            """))
        except Exception as e:
            print(f"[INFO] order_id nullable: {e}")
        
        await conn.commit()
    
    print("[OK] Database initialization complete")

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
    user_id: str = None
    user_email: str = None

class CaptureOrderRequest(BaseModel):
    order_id: str
    user_id: str = None
    user_email: str = None

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
        # Validate payment restrictions if user_id is provided
        if request.user_id:
            from apex.infrastructure.database import engine
            from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
            from sqlalchemy import select
            from models import Payment
            
            async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
            async with async_session() as session:
                # Get all completed payments for this user
                stmt = select(Payment).where(
                    Payment.user_id == request.user_id,
                    Payment.status.in_(["completed", "COMPLETED"])
                )
                result = await session.execute(stmt)
                completed_payments = result.scalars().all()
                
                # Check if user has Pro plan ($199)
                has_pro = any(p.amount == 199.0 for p in completed_payments)
                has_starter = any(p.amount == 99.0 for p in completed_payments)
                
                # Validation rules based on foreign key relationship
                if has_pro:
                    raise HTTPException(
                        status_code=400,
                        detail="You already have the Pro plan. No additional payments allowed."
                    )
                
                if request.amount == 99.0 and has_starter:
                    raise HTTPException(
                        status_code=400,
                        detail="You already purchased the Starter plan. You can upgrade to Pro plan."
                    )
                
                if request.amount == 199.0 and has_starter:
                    # Allow upgrade from Starter to Pro
                    print(f"✅ Allowing upgrade from Starter to Pro")
                    pass
        
        # Use FRONTEND_URL from .env if return_url/cancel_url not provided
        # PayPal will append token parameter automatically
        return_url = request.return_url or f"{FRONTEND_URL}/payment/success"
        cancel_url = request.cancel_url or f"{FRONTEND_URL}/payment/cancel"
        
        result = await payments.create_payment_order(
            amount=request.amount,
            currency=request.currency,
            description=request.description,
            return_url=return_url,
            cancel_url=cancel_url,
            user_id=request.user_id,
            user_email=request.user_email
        )
        
        # Append order_id to return_url for frontend
        if result.get("order_id"):
            return_url_with_order = f"{return_url}?order_id={result['order_id']}"
            result["return_url"] = return_url_with_order
        
        return result
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Payment error: {str(e)}")

@app.post("/payments/capture-order")
async def capture_order_endpoint(request: CaptureOrderRequest):
    """Capture PayPal order endpoint"""
    try:
        result = await payments.capture_payment_order(
            order_id=request.order_id,
            user_id=request.user_id
        )
        
        # Debug: log capture result
        print(f"🔍 Capture result: {result}")
        print(f"🔍 Capture result keys: {result.keys() if isinstance(result, dict) else 'Not a dict'}")
        
        # Find payment by order_id and link to logged-in user
        # This ensures payment is linked to the user who generated the link, not PayPal email
        from apex.infrastructure.database import engine
        from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
        from sqlalchemy import select, or_
        from models import User, Payment
        
        async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with async_session() as session:
            # Try to find payment by order_id or paypal_order_id
            # PayPal order_id might be stored in either field
            stmt = select(Payment).where(
                or_(
                    Payment.order_id == request.order_id,
                    Payment.paypal_order_id == request.order_id
                )
            )
            payment_result = await session.execute(stmt)
            payment = payment_result.scalar_one_or_none()
            
            if payment:
                # Link to logged-in user (who generated the payment link)
                # This is the key: link to the user who created the order, not PayPal email
                if request.user_id:
                    payment.user_id = request.user_id
                    print(f"🔗 Linking payment {payment.id} to user {request.user_id}")
                elif request.user_email and not payment.user_id:
                    # If user_id is missing, try to find user by email and link
                    user_stmt = select(User).where(User.email == request.user_email)
                    user_result = await session.execute(user_stmt)
                    user_by_email = user_result.scalar_one_or_none()
                    if user_by_email:
                        payment.user_id = user_by_email.id
                        print(f"🔗 Linking payment {payment.id} to user {user_by_email.id} (found by email {request.user_email})")
                    else:
                        print(f"⚠️ User not found for email {request.user_email}, cannot link payment {payment.id}")
                
                # Store user email if provided
                if request.user_email:
                    payment.user_email = request.user_email
                    print(f"🔗 Storing email {request.user_email} for payment {payment.id}")
                
                # Update status and capture details
                if result.get('status'):
                    payment.status = result.get('status', 'completed').lower()
                if result.get('capture_id'):
                    payment.paypal_capture_id = result['capture_id']
                if result.get('paypal_order_id') and not payment.paypal_order_id:
                    payment.paypal_order_id = result['paypal_order_id']
                
                await session.commit()
                print(f"✅ Payment {payment.id} updated - user_id: {payment.user_id}, email: {payment.user_email}, status: {payment.status}")
            else:
                print(f"⚠️ Payment not found for order_id: {request.order_id}")
                # If payment not found, try to create it (fallback)
                if request.user_id:
                    try:
                        # Try to get amount from capture result, or fetch from order if missing
                        amount = result.get('amount')
                        currency = result.get('currency', 'USD')
                        
                        # If amount is missing, try to fetch order details
                        if not amount:
                            print(f"⚠️ Amount missing in capture result, fetching order details...")
                            try:
                                order_details = await payments.get_payment_order(request.order_id)
                                amount = order_details.get('amount')
                                currency = order_details.get('currency', 'USD')
                                print(f"✅ Fetched order details: amount={amount}, currency={currency}")
                            except Exception as e:
                                print(f"⚠️ Failed to fetch order details: {e}")
                        
                        # Create payment record even if amount is missing (we'll update it later)
                        new_payment = Payment(
                            order_id=request.order_id,
                            paypal_order_id=request.order_id,
                            amount=float(amount) if amount else 0.0,
                            currency=currency,
                            status=result.get('status', 'completed').lower(),
                            user_id=request.user_id,
                            user_email=request.user_email, # Store user email
                            paypal_capture_id=result.get('capture_id'),
                            payment_method="paypal",
                            organization_id=None,  # Apex expects this
                            meta={}  # Apex expects this
                        )
                        session.add(new_payment)
                        await session.commit()
                        print(f"✅ Created new payment record for order_id: {request.order_id}, user_id: {request.user_id}, amount: {amount}")
                    except Exception as e:
                        print(f"❌ Failed to create payment record: {e}")
                        import traceback
                        traceback.print_exc()
                        await session.rollback()
                else:
                    print(f"⚠️ Cannot create payment record: user_id is missing")
        
        return result
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Capture failed: {str(e)}")

@app.get("/payments/order/{order_id}")
async def get_order_endpoint(order_id: str):
    """Get PayPal order status endpoint"""
    try:
        return await payments.get_payment_order(order_id=order_id)
    except Exception as e:
        raise HTTPException(status_code=404, detail=f"Order not found: {str(e)}")

@app.get("/payments/user/{user_id}")
async def get_user_payments_endpoint(user_id: str):
    """Get all payments for a specific user"""
    try:
        from apex.infrastructure.database import engine
        from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
        from sqlalchemy import select, or_
        from models import Payment, User
        
        async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with async_session() as session:
            # First, try to find payments by user_id (foreign key relationship)
            stmt = select(Payment).where(Payment.user_id == user_id).order_by(Payment.created_at.desc())
            result = await session.execute(stmt)
            payments = result.scalars().all()
            
            # If no payments found by user_id, try to find by user_email and link them
            if not payments:
                # Get user email
                user_stmt = select(User).where(User.id == user_id)
                user_result = await session.execute(user_stmt)
                user = user_result.scalar_one_or_none()
                
                if user and user.email:
                    # Find payments by email and link them to user_id
                    email_stmt = select(Payment).where(
                        Payment.user_email == user.email,
                        Payment.user_id.is_(None)  # Only unlinked payments
                    )
                    email_result = await session.execute(email_stmt)
                    unlinked_payments = email_result.scalars().all()
                    
                    if unlinked_payments:
                        print(f"🔗 Found {len(unlinked_payments)} unlinked payments for email {user.email}, linking to user_id {user_id}")
                        for payment in unlinked_payments:
                            payment.user_id = user_id
                        await session.commit()
                        
                        # Fetch again after linking
                        stmt = select(Payment).where(Payment.user_id == user_id).order_by(Payment.created_at.desc())
                        result = await session.execute(stmt)
                        payments = result.scalars().all()
            
            # Convert to dict format
            payments_list = []
            for payment in payments:
                payments_list.append({
                    "id": str(payment.id),
                    "order_id": payment.order_id or payment.paypal_order_id,
                    "paypal_order_id": payment.paypal_order_id,
                    "amount": payment.amount,
                    "currency": payment.currency,
                    "description": payment.description,
                    "status": payment.status,
                    "paypal_capture_id": payment.paypal_capture_id,
                    "created_at": payment.created_at.isoformat() if payment.created_at else None,
                    "user_email": payment.user_email
                })
            
            return {"payments": payments_list}
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed to fetch payments: {str(e)}")

@app.get("/auth/get-user-id")
async def get_user_id_endpoint(email: str):
    """Get user_id by email"""
    try:
        from apex.infrastructure.database import engine
        from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
        from sqlalchemy import select
        from models import User
        
        async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with async_session() as session:
            stmt = select(User).where(User.email == email)
            result = await session.execute(stmt)
            user = result.scalar_one_or_none()
            
            if user:
                return {
                    "user_id": str(user.id),
                    "email": user.email,
                    "first_name": user.first_name,
                    "username": user.username
                }
            else:
                raise HTTPException(status_code=404, detail="User not found")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch user: {str(e)}")

@app.get("/materials/available")
async def get_available_materials(user_id: str):
    """Get list of materials user can download based on their payments"""
    try:
        from apex.infrastructure.database import engine
        from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
        from sqlalchemy import select
        from models import Payment
        
        async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with async_session() as session:
            # Get all completed payments for this user
            stmt = select(Payment).where(
                Payment.user_id == user_id,
                Payment.status.in_(["completed", "COMPLETED"])
            )
            result = await session.execute(stmt)
            completed_payments = result.scalars().all()
            
            # Check which plans user has
            has_starter = any(p.amount == 99.0 for p in completed_payments)
            has_pro = any(p.amount == 199.0 for p in completed_payments)
            
            available_files = []
            
            if has_starter:
                available_files.append({
                    "filename": "ID.pdf",
                    "name": "ID Document",
                    "plan": "Starter"
                })
            
            if has_pro:
                available_files.append({
                    "filename": "AKSHAAY.pdf",
                    "name": "AKSHAAY Resume",
                    "plan": "Pro"
                })
            
            return {
                "has_access": len(available_files) > 0,
                "files": available_files,
                "has_starter": has_starter,
                "has_pro": has_pro
            }
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed to check materials: {str(e)}")

@app.get("/materials/download/{filename}")
async def download_material(filename: str, user_id: str):
    """Download a material file with access control"""
    try:
        # Validate filename to prevent path traversal
        allowed_files = ["ID.pdf", "AKSHAAY.pdf"]
        if filename not in allowed_files:
            raise HTTPException(status_code=400, detail="Invalid file name")
        
        # Check user's payment status
        from apex.infrastructure.database import engine
        from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
        from sqlalchemy import select
        from models import Payment
        
        async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with async_session() as session:
            # Get all completed payments for this user
            stmt = select(Payment).where(
                Payment.user_id == user_id,
                Payment.status.in_(["completed", "COMPLETED"])
            )
            result = await session.execute(stmt)
            completed_payments = result.scalars().all()
            
            # Check which plans user has
            has_starter = any(p.amount == 99.0 for p in completed_payments)
            has_pro = any(p.amount == 199.0 for p in completed_payments)
            
            # Check access based on file and plan
            if filename == "ID.pdf" and not has_starter:
                raise HTTPException(
                    status_code=403,
                    detail="Access denied. You need to purchase the Starter plan ($99) to download this file."
                )
            
            if filename == "AKSHAAY.pdf" and not has_pro:
                raise HTTPException(
                    status_code=403,
                    detail="Access denied. You need to purchase the Pro plan ($199) to download this file."
                )
            
            # File path
            file_path = FILES_DIR / filename
            
            if not file_path.exists():
                raise HTTPException(status_code=404, detail="File not found on server")
            
            # Return file
            return FileResponse(
                path=file_path,
                filename=filename,
                media_type='application/pdf'
            )
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed to download file: {str(e)}")

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
