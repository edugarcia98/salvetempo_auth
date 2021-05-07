import logging

from celery import shared_task

from allauth.account.models import EmailAddress 
from django.core.exceptions import MultipleObjectsReturned
from rest_framework.request import Request

from .models import User

logger = logging.getLogger(__name__)


@shared_task(max_retries=3, time_limit=300)
def send_email_confirmation_after_register(email: str):
    message = f"[Email: {email}] Sending confirmation email."
    logger.info(message)

    try:
        user = User.objects.get(email__iexact=email)
    except User.DoesNotExist:
        message = f"[Email: {email}] Email not registered in the system."
        logger.error(message)
        raise

    try:
        EmailAddress.objects.add_email(None, user, email, confirm=True)
    except Exception as exc:
        exc_name = type(exc).__name__

        message = (
            f"[User ID: {user.id}] [Email: {email}] [Exception: {exc_name}] "
            f"An unexpected exception occured. [Content: {exc}]"
        )
        logger.error(message)
        raise

    message = f"[User ID: {user.id}] [Email: {email}] Confirmation email sent."
    logger.info(message)
