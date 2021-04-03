from django.urls import reverse

from authentication.tests.factories import EmailAddressFactory, UserFactory
from unittest.mock import patch
from rest_framework import status
from rest_framework.test import APITestCase

from ..models import User


class TestJWTLoginView(APITestCase):
    """
    JWTLoginView test cases
    """

    def setUp(self):
        self.resource_url = reverse("login")
        self.headers = {"Content-Type": "application/json"}

        self.email = "test@test.com"
        self.pwd = "some_pwd"

        self.user = User.objects.create_user(self.email, self.pwd)
        self.email_address = EmailAddressFactory(user=self.user)

        self.payload = {
            "email": "test@test.com",
            "password": "some_pwd"
        }
    
    def test_correct_resource_url(self):
        self.assertEqual(self.resource_url, "/api/auth/login/")

    @patch("authentication.views.jwt_response_payload_handler")
    def test_jwt_login_success(self, mocked_token):
        mocked_token.return_value = {"token": "some_jwt_token"}

        response = self.client.post(
            self.resource_url, self.payload, header=self.headers,
        )
        data = response.json()

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(data["token"], "some_jwt_token")
    
    def test_jwt_login_invalid_credentials(self):
        self.payload["password"] = "wrong_pwd"

        response = self.client.post(
            self.resource_url, self.payload, header=self.headers,
        )
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    
    def test_jwt_login_with_no_email_address(self):
        self.email_address.delete()

        response = self.client.post(
            self.resource_url, self.payload, header=self.headers,
        )
        data = response.json()

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(data["error"], "Email address not found.")
    
    def test_jwt_login_email_not_verified(self):
        self.email_address.verified = False
        self.email_address.save()

        response = self.client.post(
            self.resource_url, self.payload, header=self.headers,
        )
        data = response.json()

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(data["error"], "Email not verified.")


class TestRegisterUser(APITestCase):
    """
    Register user test cases
    """

    def setUp(self):
        self.resource_url = reverse("user-register-user")
        self.headers = {"Content-Type": "application/json"}
        self.payload = {
            "email": "test@test.com",
            "password": "EvSfA07to4",
            "password_confirm": "EvSfA07to4",
        }
    
    def test_correct_resource_url(self):
        self.assertEqual(self.resource_url, "/api/auth/user/register/")

    @patch("authentication.views.send_email_confirmation")
    def test_register_user_success(self, mocked_send_email_confirmation):
        response = self.client.post(
            self.resource_url, self.payload, headers=self.headers,
        )
        data = response.json()

        mocked_send_email_confirmation.return_value = True

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn("id", data)
        self.assertEqual(data["email"], "test@test.com")
        self.assertTrue(mocked_send_email_confirmation.called)
    
    @patch("authentication.views.send_email_confirmation")
    def test_register_user_empty_payload(self, mocked_send_email_confirmation):
        empty_payload={}

        response = self.client.post(
            self.resource_url, empty_payload, headers=self.headers,
        )
        data = response.json()

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("email", data)
        self.assertIn("password", data)
        self.assertIn("password_confirm", data)
        self.assertFalse(mocked_send_email_confirmation.called)
    
    @patch("authentication.views.send_email_confirmation")
    def test_register_user_different_passwords(self, mocked_send_email_confirmation):
        self.payload["password_confirm"] = "different_pwd"

        response = self.client.post(
            self.resource_url, self.payload, headers=self.headers,
        )
        data = response.json()

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(data["error"], "Passwords must be equal.")
        self.assertFalse(mocked_send_email_confirmation.called)

    @patch("authentication.views.send_email_confirmation")
    def test_register_user_invalid_password(self, mocked_send_email_confirmation):
        self.payload["password"] = "123"
        self.payload["password_confirm"] = "123"

        response = self.client.post(
            self.resource_url, self.payload, headers=self.headers,
        )
        data = response.json()

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIsInstance(data["error"], list)
        self.assertFalse(mocked_send_email_confirmation.called)

    @patch("authentication.views.send_email_confirmation")
    @patch("authentication.models.UserManager.create_user")
    def test_register_user_unknown_error(
        self, mocked_create_user, mocked_send_email_confirmation
    ):
        mocked_create_user.side_effect = ValueError("Create user value error.")

        response = self.client.post(
            self.resource_url, self.payload, headers=self.headers,
        )
        data = response.json()

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(data["error"], "Create user value error.")
        self.assertFalse(mocked_send_email_confirmation.called)


class TestAlreadySentView(APITestCase):
    """
    Already sent API view test cases
    """

    def setUp(self):
        self.resource_url = reverse("account_email_verification_sent")
        self.headers = {"Content-Type": "application/json"}
    
    def test_correct_resource_url(self):
        self.assertEqual(self.resource_url, "/api/auth/email/confirm/sent/")
    
    def test_already_sent(self):
        response = self.client.get(self.resource_url, headers=self.headers)
        data = response.json()

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(data["message"], "Confirmation email already sent.")


class TestCompleteView(APITestCase):
    """
    Complete API view test cases
    """

    def setUp(self):
        self.resource_url = reverse("account_confirm_complete")
        self.headers = {"Content-Type": "application/json"}
    
    def test_correct_resource_url(self):
        self.assertEqual(self.resource_url, "/api/auth/email/confirm/complete/")
    
    def test_complete(self):
        response = self.client.get(self.resource_url, headers=self.headers)
        data = response.json()

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(data["message"], "Email is activated.")