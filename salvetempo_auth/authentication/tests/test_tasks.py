from allauth.account.models import EmailAddress
from authentication.tasks import send_email_confirmation_after_register
from authentication.tests.factories import UserFactory
from django.test import TestCase

from ..models import User


class TestSendEmailConfirmationAfterRegister(TestCase):
    """
    send_email_confirmation_after_register test cases
    """

    def setUp(self):
        self.email = "test@test.com"
        self.pwd = "some_pwd"

        self.user = User.objects.create_user(self.email, self.pwd)
    
    def test_send_email_confirmation_after_register_user_does_not_exist(self):
        User.objects.all().delete()

        with self.assertRaises(User.DoesNotExist):
            send_email_confirmation_after_register(self.email)
    
    def test_send_email_confirmation_after_register_email_success(self):
        send_email_confirmation_after_register(self.email)

        self.assertEqual(EmailAddress.objects.count(), 1)
