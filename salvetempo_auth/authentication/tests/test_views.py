from django.urls import reverse

from unittest.mock import patch
from rest_framework import status
from rest_framework.test import APITestCase


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

    def test_register_user_success(self):
        response = self.client.post(
            self.resource_url, self.payload, headers=self.headers,
        )
        data = response.json()

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn("id", data)
        self.assertEqual(data["email"], "test@test.com")
    
    def test_register_user_empty_payload(self):
        empty_payload={}

        response = self.client.post(
            self.resource_url, empty_payload, headers=self.headers,
        )
        data = response.json()

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("email", data)
        self.assertIn("password", data)
        self.assertIn("password_confirm", data)
    
    def test_register_user_different_passwords(self):
        self.payload["password_confirm"] = "different_pwd"

        response = self.client.post(
            self.resource_url, self.payload, headers=self.headers,
        )
        data = response.json()

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(data["error"], "Passwords must be equal.")

    def test_register_user_invalid_password(self):
        self.payload["password"] = "123"
        self.payload["password_confirm"] = "123"

        response = self.client.post(
            self.resource_url, self.payload, headers=self.headers,
        )
        data = response.json()

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIsInstance(data["error"], list)

    @patch("authentication.models.UserManager.create_user")
    def test_register_user_unknown_error(self, mocked_create_user):
        mocked_create_user.side_effect = ValueError("Create user value error.")

        response = self.client.post(
            self.resource_url, self.payload, headers=self.headers,
        )
        data = response.json()

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(data["error"], "Create user value error.")
