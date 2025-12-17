import asyncio
import concurrent.futures
from apex.payments import create_order, capture_order, get_order

# Create a thread pool executor for running sync Apex functions
_executor = concurrent.futures.ThreadPoolExecutor(max_workers=5)

async def create_payment_order(amount, currency="USD", description="Payment", return_url=None, cancel_url=None, user_id=None, user_email=None):
    """Create PayPal order using apex.payments.create_order"""
    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(
        _executor,
        lambda: create_order(
            amount=amount,
            currency=currency,
            description=description,
            return_url=return_url,
            cancel_url=cancel_url,
            save_to_db=True  # Save payment to database
        )
    )
    
    # Debug: print the response structure
    print(f"🔍 Payment order response type: {type(result)}")
    print(f"🔍 Payment order response keys: {result.keys() if isinstance(result, dict) else 'Not a dict'}")
    
    # Handle different response structures
    # Apex may return: {'order_id': '...', 'order': {...}, 'payment_id': '...'}
    # OR just the order dict directly
    if isinstance(result, dict):
        # Check if response has 'order' key (wrapped response)
        if 'order' in result:
            order_data = result['order']
            order_id = result.get('order_id') or order_data.get('id')
            payment_id = result.get('payment_id')
        else:
            # Direct order response
            order_data = result
            order_id = result.get('id') or result.get('order_id')
            payment_id = result.get('payment_id')
        
        # Extract approval URL from links
        approval_url = None
        links = order_data.get("links", [])
        print(f"🔍 Found {len(links)} links in order response")
        for link in links:
            rel = link.get("rel")
            href = link.get("href")
            print(f"🔍 Link: rel={rel}, href={href}")
            if rel == "approve":
                approval_url = href
                break
        
        # If no approval URL found, try alternative locations
        if not approval_url:
            # Check if approval_url is directly in the response
            approval_url = order_data.get("approval_url") or result.get("approval_url")
        
        print(f"🔍 Extracted order_id: {order_id}, approval_url: {approval_url}")
        
        if not approval_url:
            # Log the full response for debugging
            print(f"⚠️ No approval URL found. Full response: {result}")
            raise Exception(f"No approval URL in response. Response structure: {list(result.keys()) if isinstance(result, dict) else type(result)}")
        
        return {
            "order_id": order_id,
            "approval_url": approval_url,
            "status": order_data.get("status", "created"),
            "payment_id": payment_id,
            "paypal_order_id": order_id
        }
    else:
        # Unexpected response type
        print(f"❌ Unexpected response type: {type(result)}")
        print(f"❌ Response value: {result}")
        raise Exception(f"Unexpected response type from create_order: {type(result)}")

async def capture_payment_order(order_id, user_id=None):
    """Capture PayPal order using apex.payments.capture_order"""
    loop = asyncio.get_running_loop()
    capture = await loop.run_in_executor(
        _executor,
        lambda: capture_order(
            order_id=order_id,
            update_db=True  # Update payment in database
        )
    )
    
    # Extract capture details
    capture_id = None
    amount = None
    currency = None
    
    # Handle different response formats
    if isinstance(capture, dict):
        capture_id = capture.get("id") or capture.get("capture_id")
        # Try to get amount from capture or purchase_units
        if "amount" in capture:
            amount_info = capture["amount"]
            if isinstance(amount_info, dict):
                amount = amount_info.get("value")
                currency = amount_info.get("currency_code")
        elif "purchase_units" in capture:
            for unit in capture["purchase_units"]:
                if "payments" in unit and "captures" in unit["payments"]:
                    for cap in unit["payments"]["captures"]:
                        capture_id = cap.get("id")
                        if "amount" in cap:
                            amount = cap["amount"].get("value")
                            currency = cap["amount"].get("currency_code")
                        break
    
    return {
        "status": capture.get("status", "completed"),
        "capture_id": capture_id,
        "amount": amount,
        "currency": currency,
        "order_id": order_id,
        "paypal_order_id": capture.get("id") or order_id
    }

async def get_payment_order(order_id):
    """Get PayPal order status using apex.payments.get_order"""
    loop = asyncio.get_running_loop()
    order = await loop.run_in_executor(
        _executor,
        lambda: get_order(order_id=order_id)
    )
    
    # Extract amount and currency from purchase_units
    amount = None
    currency = None
    if "purchase_units" in order:
        for unit in order["purchase_units"]:
            if "amount" in unit:
                amount = unit["amount"].get("value")
                currency = unit["amount"].get("currency_code")
                break
    
    return {
        "order_id": order.get("id") or order_id,
        "status": order.get("status"),
        "amount": amount,
        "currency": currency
    }

