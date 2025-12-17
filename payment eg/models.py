from apex.core.base import Base, UUIDPKMixin, TimestampMixin
from sqlalchemy import Column, String, Numeric, ForeignKey
from sqlalchemy.dialects.postgresql import JSONB, UUID
import uuid
class Payment(Base, UUIDPKMixin, TimestampMixin):
    __tablename__ = "payments"
    paypal_order_id = Column(String(100), unique=True, nullable=False)
    paypal_capture_id = Column(String(100), unique=True, nullable=True)
    amount = Column(Numeric(12, 2), nullable=False)
    currency = Column(String(10), nullable=False, default="USD")
    status = Column(String(50), nullable=False, default="created")
    payment_method = Column(String(50), nullable=False, default="paypal")
    payment_metadata = Column(JSONB, default=dict)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="SET NULL"), nullable=True)







