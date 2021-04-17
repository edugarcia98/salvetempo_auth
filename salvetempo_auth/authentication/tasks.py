from celery import shared_task

from allauth.account.models import EmailAddress 
from django.core.exceptions import MultipleObjectsReturned
from rest_framework.request import Request

from .models import User

@shared_task(max_retries=3, time_limit=300)
def send_email_confirmation_after_register(email: str):
    try:
        user = User.objects.get(email__iexact=email)
    except User.DoesNotExist:
        # TODO: Add logging
        raise
    except MultipleObjectsReturned:
        # TODO: Add logging
        raise

    try:
        EmailAddress.objects.add_email(None, user, email, confirm=True)
    except Exception:
        # TODO: Add logging
        raise
