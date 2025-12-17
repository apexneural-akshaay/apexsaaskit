from sqlalchemy import Column, String, Boolean, Integer, Float, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
try:
    from apex import Model, ID, Timestamps, register_model
except ImportError:
    from apex.models import Model, ID, Timestamps, register_model

@register_model
class User(Model, ID, Timestamps):
    __tablename__ = "users"
    email = Column(String(255), unique=True, nullable=False, index=True)
    username = Column(String(100), unique=True, nullable=True, index=True)
    password_hash = Column(String(255), nullable=False)
    first_name = Column(String(100), nullable=True)
    last_name = Column(String(100), nullable=True)
    phone = Column(String(30), nullable=True)
    country = Column(String(100), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    is_verified = Column(Boolean, default=False, nullable=False)
    is_superuser = Column(Boolean, default=False, nullable=False)
    reset_token = Column(String(255), nullable=True, index=True)
    reset_token_expires = Column(String(255), nullable=True)  # Required by Apex but not used in our logic
    login_attempts = Column(Integer, default=0, nullable=False)
    
    # Relationship: one user has many payments
    payments = relationship("Payment", back_populates="user", lazy="selectin")

@register_model
class Payment(Model, ID, Timestamps):
    __tablename__ = "payments"
    user_id = Column(UUID(as_uuid=False), ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True)  # Made nullable for initial creation
    order_id = Column(String(255), unique=True, nullable=True, index=True)  # Made nullable since paypal_order_id is the primary
    amount = Column(Float, nullable=False)
    currency = Column(String(10), default="USD", nullable=False)
    description = Column(String(500), nullable=True)
    status = Column(String(50), default="pending", nullable=False, index=True)
    paypal_order_id = Column(String(255), unique=True, nullable=True, index=True)  # Primary identifier from PayPal
    paypal_capture_id = Column(String(255), nullable=True)
    return_url = Column(String(500), nullable=True)
    cancel_url = Column(String(500), nullable=True)
    approval_url = Column(String(500), nullable=True)
    payment_method = Column(String(50), default="paypal", nullable=False)  # Required by Apex
    payment_metadata = Column(JSONB, nullable=True)  # Required by Apex
    organization_id = Column(UUID(as_uuid=False), nullable=True)  # Required by Apex (can be null)
    meta = Column(JSONB, nullable=True)  # Required by Apex
    user_email = Column(String(255), nullable=True, index=True) # Added for easier querying
    
    # Relationship: each payment belongs to one user
    user = relationship("User", back_populates="payments", lazy="selectin")

