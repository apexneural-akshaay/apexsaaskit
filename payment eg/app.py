from apex import Client, set_default_client, bootstrap
from apex.sync import _run
from models import Payment
from dotenv import load_dotenv
import os
load_dotenv()
DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql+asyncpg://user:password@localhost:5432/dbname')
SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key-change-in-production-minimum-32-characters')
client = Client(
    database_url=DATABASE_URL,
    user_model=None,
    secret_key=SECRET_KEY
)
set_default_client(client)
try:
    bootstrap(models=[Payment])
    print(":white_check_mark: Database initialized successfully")
except Exception as e:
    print(f":warning:  Database initialization: {e}")
def create_order(amount: float, currency: str = "USD", description: str = None,
                 return_url: str = None, cancel_url: str = None, save_to_db: bool = False):
    async def _create_order():
        return await client.payments.create_order(
            amount=amount,
            currency=currency,
            description=description,
            return_url=return_url,
            cancel_url=cancel_url,
            save_to_db=save_to_db
        )
    return _run(_create_order())
def capture_order(order_id: str, update_db: bool = False):
    async def _capture_order():
        return await client.payments.capture_order(order_id=order_id, update_db=update_db)
    return _run(_capture_order())
def create_subscription(plan_id: str, subscriber_email: str,
                       subscriber_first_name: str = None, subscriber_last_name: str = None,
                       return_url: str = None, cancel_url: str = None):
    subscriber = {
        "email_address": subscriber_email
    }
    if subscriber_first_name or subscriber_last_name:
        subscriber["name"] = {}
        if subscriber_first_name:
            subscriber["name"]["given_name"] = subscriber_first_name
        if subscriber_last_name:
            subscriber["name"]["surname"] = subscriber_last_name
    async def _create_subscription():
        return await client.payments.create_subscription(
            plan_id=plan_id,
            subscriber=subscriber,
            return_url=return_url or os.getenv('PAYPAL_RETURN_URL', 'https://example.com/return'),
            cancel_url=cancel_url or os.getenv('PAYPAL_CANCEL_URL', 'https://example.com/cancel')
        )
    return _run(_create_subscription())
def cancel_subscription(subscription_id: str):
    async def _cancel_subscription():
        return await client.payments.cancel_subscription(subscription_id=subscription_id)
    return _run(_cancel_subscription())
def get_subscription(subscription_id: str):
    async def _get_subscription():
        return await client.payments.get_subscription(subscription_id=subscription_id)
    return _run(_get_subscription())
def get_order(order_id: str):
    async def _get_order():
        return await client.payments.paypal_service.get_order(order_id)
    return _run(_get_order())