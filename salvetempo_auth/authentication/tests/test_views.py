import jwt

from datetime import datetime

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

        response = self.client.post(self.resource_url, self.payload)
        data = response.json()

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(data["token"], "some_jwt_token")
    
    def test_jwt_login_invalid_credentials(self):
        self.payload["password"] = "wrong_pwd"

        response = self.client.post(self.resource_url, self.payload)
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    
    def test_jwt_login_with_no_email_address(self):
        self.email_address.delete()

        response = self.client.post(self.resource_url, self.payload)
        data = response.json()

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(data["error"], "Email address not found.")
    
    def test_jwt_login_email_not_verified(self):
        self.email_address.verified = False
        self.email_address.save()

        response = self.client.post(self.resource_url, self.payload)
        data = response.json()

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(data["error"], "Email not verified.")


class TestRegisterUser(APITestCase):
    """
    Register user test cases
    """

    def setUp(self):
        self.resource_url = reverse("user-register-user")
        self.payload = {
            "email": "test@test.com",
            "password": "EvSfA07to4",
            "password_confirm": "EvSfA07to4",
        }
    
    def test_correct_resource_url(self):
        self.assertEqual(self.resource_url, "/api/auth/user/register/")

    @patch("authentication.views.send_email_confirmation_after_register.delay")
    def test_register_user_success(self, mocked_send_email_confirmation):
        response = self.client.post(self.resource_url, self.payload)
        data = response.json()

        mocked_send_email_confirmation.return_value = True

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn("id", data)
        self.assertEqual(data["email"], "test@test.com")
        self.assertTrue(mocked_send_email_confirmation.called)
    
    @patch("authentication.views.send_email_confirmation_after_register.delay")
    def test_register_user_empty_payload(self, mocked_send_email_confirmation):
        empty_payload={}

        response = self.client.post(self.resource_url, empty_payload)
        data = response.json()

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("email", data)
        self.assertIn("password", data)
        self.assertIn("password_confirm", data)
        self.assertFalse(mocked_send_email_confirmation.called)
    
    @patch("authentication.views.send_email_confirmation_after_register.delay")
    def test_register_user_different_passwords(self, mocked_send_email_confirmation):
        self.payload["password_confirm"] = "different_pwd"

        response = self.client.post(self.resource_url, self.payload)
        data = response.json()

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(data["error"], "Passwords must be equal.")
        self.assertFalse(mocked_send_email_confirmation.called)

    @patch("authentication.views.send_email_confirmation_after_register.delay")
    def test_register_user_invalid_password(self, mocked_send_email_confirmation):
        self.payload["password"] = "123"
        self.payload["password_confirm"] = "123"

        response = self.client.post(self.resource_url, self.payload)
        data = response.json()

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIsInstance(data["error"], list)
        self.assertFalse(mocked_send_email_confirmation.called)

    @patch("authentication.views.send_email_confirmation_after_register.delay")
    @patch("authentication.models.UserManager.create_user")
    def test_register_user_unknown_error(
        self, mocked_create_user, mocked_send_email_confirmation,
    ):
        mocked_create_user.side_effect = ValueError("Create user value error.")

        response = self.client.post(self.resource_url, self.payload)
        data = response.json()

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(data["error"], "Create user value error.")
        self.assertFalse(mocked_send_email_confirmation.called)


class TestTokenRefreshTime(APITestCase):
    """
    Token refresh time test cases 
    """

    def setUp(self):
        self.resource_url = reverse("token-refresh-time")

        self.user = UserFactory()
        self.payload = {"foo": "bar"}

        self.headers = {"HTTP_AUTHORIZATION": "Bearer some_token"}
    
    def test_correct_resource_url(self):
        self.assertEqual(self.resource_url, "/api/auth/token/refresh-time/")
    
    @patch(
        "rest_framework_jwt.authentication.BaseJSONWebTokenAuthentication.authenticate"
    )
    def test_refresh_time_get_token_error_not_exists(self, mocked_authenticate):
        self.headers.pop("HTTP_AUTHORIZATION")

        mocked_authenticate.return_value = (self.user, self.payload)

        response = self.client.get(self.resource_url, **self.headers)
        data = response.json()

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(data["error"], "Unable to get JWT token.")
    
    @patch(
        "rest_framework_jwt.authentication.BaseJSONWebTokenAuthentication.authenticate"
    )
    def test_refresh_time_get_token_error_without_prefix(self, mocked_authenticate):
        self.headers["HTTP_AUTHORIZATION"] = "foo"

        mocked_authenticate.return_value = (self.user, self.payload)

        response = self.client.get(self.resource_url, **self.headers)
        data = response.json()

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(data["error"], "Unable to get JWT token.")
    
    @patch(
        "rest_framework_jwt.authentication.BaseJSONWebTokenAuthentication.authenticate"
    )
    def test_refresh_time_decode_token_error(self, mocked_authenticate):
        mocked_authenticate.return_value = (self.user, self.payload)

        response = self.client.get(self.resource_url, **self.headers)
        data = response.json()

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(data["error"], "Unable to decode JWT token.")
    
    @patch("authentication.views.jwt.decode")
    @patch(
        "rest_framework_jwt.authentication.BaseJSONWebTokenAuthentication.authenticate"
    )
    def test_refresh_time_convert_to_datetime_key_error(
        self, mocked_authenticate, mocked_jwt_decode,
    ):
        mocked_authenticate.return_value = (self.user, self.payload)
        mocked_jwt_decode.return_value = {"foo": "bar"}

        response = self.client.get(self.resource_url, **self.headers)
        data = response.json()

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            data["error"], "Some error occured while retrieving refresh time.",
        )
    
    @patch("authentication.views.jwt.decode")
    @patch(
        "rest_framework_jwt.authentication.BaseJSONWebTokenAuthentication.authenticate"
    )
    def test_refresh_time_convert_to_datetime_type_error(
        self, mocked_authenticate, mocked_jwt_decode,
    ):
        mocked_authenticate.return_value = (self.user, self.payload)
        mocked_jwt_decode.return_value = {"exp": "not a timestamp"}

        response = self.client.get(self.resource_url, **self.headers)
        data = response.json()

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            data["error"], "Some error occured while retrieving refresh time.",
        )
    
    @patch("authentication.views.jwt.decode")
    @patch(
        "rest_framework_jwt.authentication.BaseJSONWebTokenAuthentication.authenticate"
    )
    def test_refresh_time_success(self, mocked_authenticate, mocked_jwt_decode):
        mocked_authenticate.return_value = (self.user, self.payload)
        mocked_jwt_decode.return_value = {"exp": 1617846896}

        refresh_token_after = str(datetime(2021, 4, 7, 22, 53, 56))

        response = self.client.get(self.resource_url, **self.headers)
        data = response.json()
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(data["refresh_token_after"], refresh_token_after)


class TestAlreadySentView(APITestCase):
    """
    Already sent API view test cases
    """

    def setUp(self):
        self.resource_url = reverse("account_email_verification_sent")
    
    def test_correct_resource_url(self):
        self.assertEqual(self.resource_url, "/api/auth/email/confirm/sent/")
    
    def test_already_sent(self):
        response = self.client.get(self.resource_url)
        data = response.json()

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(data["message"], "Confirmation email already sent.")


class TestCompleteView(APITestCase):
    """
    Complete API view test cases
    """

    def setUp(self):
        self.resource_url = reverse("account_confirm_complete")
    
    def test_correct_resource_url(self):
        self.assertEqual(self.resource_url, "/api/auth/email/confirm/complete/")
    
    def test_complete(self):
        response = self.client.get(self.resource_url)
        data = response.json()

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(data["message"], "Email is activated.")