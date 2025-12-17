from app import (
    create_order,
    capture_order,
    get_order,
    create_subscription,
    cancel_subscription,
    get_subscription
)


def example_create_order():
    print("\n" + "=" * 70)
    print("EXAMPLE: Create PayPal Order")
    print("=" * 70)
    
    order = create_order(
        amount=99.99,
        currency="USD",
        description="Premium Plan Subscription",
        return_url="https://yourdomain.com/payment/success",
        cancel_url="https://yourdomain.com/payment/cancel",
        save_to_db=True
    )
    
    print(f"✅ Order created successfully")
    print(f"   Order ID: {order['order_id']}")
    print(f"   Status: {order['order']['status']}")
    
    # Get approval URL
    approval_url = None
    for link in order['order']['links']:
        if link['rel'] == 'approve':
            approval_url = link['href']
            print(f"   Approval URL: {approval_url}")
            print(f"   👆 Redirect user to this URL to approve payment")
            break
    
    if 'payment_id' in order:
        print(f"   Payment ID (saved to DB): {order['payment_id']}")
    
    return order


def example_get_order(order_id: str):
    print("\n" + "=" * 70)
    print("EXAMPLE: Get PayPal Order")
    print("=" * 70)
    
    if not order_id:
        print("⚠️  Skipping - no order ID")
        return None
    
    order = get_order(order_id)
    
    print(f"✅ Order retrieved")
    print(f"   Order ID: {order.get('id', 'N/A')}")
    print(f"   Status: {order.get('status', 'N/A')}")
    print(f"   Amount: {order.get('purchase_units', [{}])[0].get('amount', {}).get('value', 'N/A')}")
    
    return order


def example_capture_order(order_id: str):
    print("\n" + "=" * 70)
    print("EXAMPLE: Capture PayPal Order")
    print("=" * 70)
    
    if not order_id:
        print("⚠️  Skipping - no order ID")
        return None
    
    capture = capture_order(order_id=order_id, update_db=True)
    
    print(f"✅ Order captured")
    print(f"   Status: {capture['capture']['status']}")
    
    # Get capture details
    purchase_units = capture['capture'].get('purchase_units', [])
    if purchase_units:
        payments = purchase_units[0].get('payments', {})
        captures = payments.get('captures', [])
        if captures:
            print(f"   Capture ID: {captures[0].get('id', 'N/A')}")
            print(f"   Amount: {captures[0].get('amount', {}).get('value', 'N/A')} {captures[0].get('amount', {}).get('currency_code', 'N/A')}")
    
    if 'payment_id' in capture:
        print(f"   Payment ID (updated in DB): {capture['payment_id']}")
    
    return capture


def example_create_subscription():
    print("\n" + "=" * 70)
    print("EXAMPLE: Create PayPal Subscription")
    print("=" * 70)
    
    subscription = create_subscription(
        plan_id="P-5ML4271244454362WXNWU5NQ",
        subscriber_email="john@example.com",
        subscriber_first_name="John",
        subscriber_last_name="Doe",
        return_url="https://yourdomain.com/subscription/success",
        cancel_url="https://yourdomain.com/subscription/cancel"
    )
    
    print(f"✅ Subscription created")
    print(f"   Subscription ID: {subscription['id']}")
    print(f"   Status: {subscription['status']}")
    print(f"   Plan ID: {subscription.get('plan_id', 'N/A')}")
    
    # Get approval URL
    approval_url = None
    for link in subscription.get('links', []):
        if link['rel'] == 'approve':
            approval_url = link['href']
            print(f"   Approval URL: {approval_url}")
            print(f"   👆 Redirect user to this URL to approve subscription")
            break
    
    return subscription


def example_get_subscription(subscription_id: str):
    print("\n" + "=" * 70)
    print("EXAMPLE: Get PayPal Subscription")
    print("=" * 70)
    
    if not subscription_id:
        print("⚠️  Skipping - no subscription ID")
        return None
    
    subscription = get_subscription(subscription_id)
    
    print(f"✅ Subscription retrieved")
    print(f"   Subscription ID: {subscription.get('id', 'N/A')}")
    print(f"   Status: {subscription.get('status', 'N/A')}")
    print(f"   Plan ID: {subscription.get('plan_id', 'N/A')}")
    
    subscriber = subscription.get('subscriber', {})
    if subscriber:
        email = subscriber.get('email_address', 'N/A')
        print(f"   Subscriber Email: {email}")
    
    return subscription


def example_cancel_subscription(subscription_id: str):
    print("\n" + "=" * 70)
    print("EXAMPLE: Cancel PayPal Subscription")
    print("=" * 70)
    
    if not subscription_id:
        print("⚠️  Skipping - no subscription ID")
        return None
    
    result = cancel_subscription(subscription_id)
    
    print(f"✅ Subscription cancelled successfully")
    print(f"   Result: {result}")
    
    return result


def example_complete_payment_flow():
    print("\n" + "=" * 70)
    print("EXAMPLE: Complete Payment Flow")
    print("=" * 70)
    
    # Step 1: Create order
    print("\n📝 Step 1: Creating order...")
    order = create_order(
        amount=49.99,
        currency="USD",
        description="Monthly Subscription",
        save_to_db=True
    )
    
    order_id = order['order_id']
    print(f"   ✅ Order created: {order_id}")
    
    # Step 2: Get approval URL
    approval_url = None
    for link in order['order']['links']:
        if link['rel'] == 'approve':
            approval_url = link['href']
            break
    
    print(f"\n📝 Step 2: User approval required")
    print(f"   Approval URL: {approval_url}")
    print(f"   👆 In production, redirect user to this URL")
    print(f"   👆 After approval, proceed to Step 3")
    
    # Step 3: Capture order (after user approves)
    print(f"\n📝 Step 3: Capturing order (after user approval)...")
    print(f"   ⚠️  Note: In real scenario, wait for user to approve first")
    
    # Uncomment below to actually capture (only after user approves):
    # capture = capture_order(order_id=order_id, update_db=True)
    # print(f"   ✅ Order captured: {capture['capture']['status']}")
    
    print(f"\n✅ Complete payment flow demonstrated")


if __name__ == "__main__":
    print("=" * 70)
    print("Apex SaaS Framework - Payment Usage Examples")
    print("=" * 70)
    
    try:
        # Example 1: Create order
        order = example_create_order()
        order_id = order['order_id'] if order else None
        print()
        
        # Example 2: Get order
        order_details = example_get_order(order_id)
        print()
        
        # Example 3: Capture order (uncomment when ready)
        # capture = example_capture_order(order_id)
        # print()
        
        # Example 4: Create subscription
        subscription = example_create_subscription()
        subscription_id = subscription['id'] if subscription else None
        print()
        
        # Example 5: Get subscription
        subscription_details = example_get_subscription(subscription_id)
        print()
        
        # Example 6: Cancel subscription (uncomment when ready)
        # cancel_result = example_cancel_subscription(subscription_id)
        # print()
        
        # Example 7: Complete payment flow
        example_complete_payment_flow()
        print()
        
        print("=" * 70)
        print("All payment examples completed!")
        print("=" * 70)
        print("\n💡 Important Notes:")
        print("   - PayPal orders must be approved by user before capturing")
        print("   - Subscriptions require approval before activation")
        print("   - Make sure PAYPAL_CLIENT_ID and PAYPAL_CLIENT_SECRET are set in .env")
        print("   - Use sandbox mode for testing")
        print("=" * 70)
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()