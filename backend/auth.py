"""
Authentication functions using Apex
Following official Apex documentation patterns
"""
import os
import asyncio
import concurrent.futures
from dotenv import load_dotenv
from apex.auth import signup, login, forgot_password, reset_password
from apex.email import send_email

load_dotenv()

# Frontend URL for password reset links
FRONTEND_URL = os.getenv('FRONTEND_URL', 'http://localhost:5173')

# Create a thread pool executor for running sync Apex functions
_executor = concurrent.futures.ThreadPoolExecutor(max_workers=5)

async def signup_user(email, password, first_name=None, last_name=None, username=None):
    """
    User signup using apex.auth.signup
    Following docs: user = signup(email="...", password="...", first_name="...", last_name="...", username="...")
    """
    try:
        loop = asyncio.get_running_loop()
        user = await loop.run_in_executor(
            _executor,
            lambda: signup(
                email=email,
                password=password,
                first_name=first_name,
                last_name=last_name,
                username=username
            )
        )
        return {
            "message": "User created successfully",
            "user_id": str(user.id),
            "email": user.email,
            "username": user.username if hasattr(user, 'username') else None
        }
    except Exception as e:
        raise Exception(f"Signup error: {str(e)}") from e

async def login_user(email, password):
    """
    User login using apex.auth.login
    Following docs: tokens = login(email="...", password="...")
    """
    loop = asyncio.get_running_loop()
    tokens = await loop.run_in_executor(
        _executor,
        lambda: login(email=email, password=password)
    )
    return {
        "access_token": tokens["access_token"],
        "refresh_token": tokens["refresh_token"],
        "token_type": tokens["token_type"]
    }

async def forgot_password_user(email):
    """
    Request password reset using apex.auth.forgot_password
    Following docs: user, reset_token = forgot_password(email="...")
    """
    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(
        _executor,
        lambda: forgot_password(email=email)
    )
    user, reset_token = result
    
    if user and reset_token:
        # Create reset link
        reset_link = f"{FRONTEND_URL}/reset-password?token={reset_token}"
        
        # Email content with clickable reset link
        email_body = f"""
You requested a password reset for your account.

Click the link below to reset your password:
{reset_link}

If you did not request this password reset, please ignore this email.

This link will expire after a certain period for security reasons.
"""
        
        email_html = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .button {{ display: inline-block; padding: 12px 24px; background-color: #007bff; color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; }}
        .button:hover {{ background-color: #0056b3; }}
        .footer {{ margin-top: 30px; font-size: 12px; color: #666; }}
    </style>
</head>
<body>
    <div class="container">
        <h2>Password Reset Request</h2>
        <p>You requested a password reset for your account.</p>
        <p>Click the button below to reset your password:</p>
        <a href="{reset_link}" class="button">Reset Password</a>
        <p>Or copy and paste this link into your browser:</p>
        <p style="word-break: break-all; color: #007bff;">{reset_link}</p>
        <p>If you did not request this password reset, please ignore this email.</p>
        <p class="footer">This link will expire after a certain period for security reasons.</p>
    </div>
</body>
</html>
"""
        
        # Send email with reset link using apex.email
        await loop.run_in_executor(
            _executor,
            lambda: send_email(
                to=user.email,
                subject="Password Reset Request",
                body=email_body,
                html=email_html
            )
        )
        return {
            "message": "Password reset email sent",
            "reset_token": reset_token  # In production, don't return token
        }
    return None

async def reset_password_user(token, new_password):
    """
    Reset password using token from email link
    Following docs: success = reset_password(token=reset_token, new_password="NewSecurePass123!")
    """
    try:
        if not token:
            raise ValueError("Reset token is required")
        if not new_password or len(new_password) < 8:
            raise ValueError("Password must be at least 8 characters long")
        
        # Call reset_password exactly as shown in docs
        loop = asyncio.get_running_loop()
        success = await loop.run_in_executor(
            _executor,
            lambda: reset_password(token=token, new_password=new_password)
        )
        
        if not success:
            raise ValueError("Invalid or expired reset token")
        
        return success
        
    except ValueError as ve:
        raise
    except Exception as e:
        raise Exception(str(e)) from e