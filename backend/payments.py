"""
Payment functions using Apex
Following reference/05_payments.py pattern
"""
import asyncio
import concurrent.futures
from apex.payments import create_order, capture_order, get_order

# Create a thread pool executor for running sync Apex functions
_executor = concurrent.futures.ThreadPoolExecutor(max_workers=5)

async def create_payment_order(amount, currency="USD", description="Payment", return_url=None, cancel_url=None):
    """Create PayPal order using apex.payments.create_order"""
    loop = asyncio.get_running_loop()
    order = await loop.run_in_executor(
        _executor,
        lambda: create_order(
            amount=amount,
            currency=currency,
            description=description,
            return_url=return_url,
            cancel_url=cancel_url
        )
    )
    return {
        "order_id": order.get("order_id"),
        "approval_url": order.get("approval_url"),
        "status": order.get("status", "created")
    }

async def capture_payment_order(order_id):
    """Capture PayPal order using apex.payments.capture_order"""
    loop = asyncio.get_running_loop()
    capture = await loop.run_in_executor(
        _executor,
        lambda: capture_order(order_id=order_id)
    )
    return {
        "status": capture.get("status"),
        "capture_id": capture.get("id"),
        "amount": capture.get("amount")
    }

async def get_payment_order(order_id):
    """Get PayPal order status using apex.payments.get_order"""
    loop = asyncio.get_running_loop()
    order = await loop.run_in_executor(
        _executor,
        lambda: get_order(order_id=order_id)
    )
    return {
        "order_id": order.get("id"),
        "status": order.get("status"),
        "amount": order.get("amount"),
        "currency": order.get("currency")
    }
