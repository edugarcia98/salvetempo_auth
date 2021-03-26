from authentication.serializers import PasswordResetSerializer, UserSerializer
from django.test import TestCase
from rest_framework.exceptions import ValidationError

from .factories import UserFactory


class TestUserSerializer(TestCase):
    """
    User serializer test cases
    """

    def setUp(self):
        self.payload = {
            "email": "test@test.com",
            "password": "EvSfA07to4",
            "password_confirm": "EvSfA07to4",
        }

        self.user = UserFactory(email="test2@test.com")
    
    def test_serializer_with_empty_payload(self):
        empty_payload = {}

        serializer = UserSerializer(data=empty_payload)

        with self.assertRaises(ValidationError) as exc:
            serializer.is_valid(raise_exception=True)
        
        self.assertIn("email", exc.exception.detail)
        self.assertIn("password", exc.exception.detail)
        self.assertIn("password_confirm", exc.exception.detail)
    
    def test_serializer_with_repeated_email(self):
        self.payload["email"] = "test2@test.com"

        serializer = UserSerializer(data=self.payload)

        with self.assertRaises(ValidationError) as exc:
            serializer.is_valid(raise_exception=True)
        
        self.assertIn("email", exc.exception.detail)
        self.assertNotIn("password", exc.exception.detail)
        self.assertNotIn("password_confirm", exc.exception.detail)
    
    def test_serializer_success_by_payload(self):
        serializer = UserSerializer(data=self.payload)
        serializer.is_valid(raise_exception=True)
        
        data = serializer.data

        self.assertEqual(data["email"], "test@test.com")
    
    def test_serializer_get_by_instance(self):
        serializer = UserSerializer(instance=self.user)

        data = serializer.data
        
        self.assertEqual(data["id"], self.user.id)
        self.assertEqual(data["email"], self.user.email)


class TestPasswordResetSerializer(TestCase):
    """
    Password reset serializer test cases
    """

    def setUp(self):
        self.payload = {"email": "test@test.com"}
        self.user = UserFactory()
    
    def test_serializer_with_empty_payload(self):
        empty_payload = {}

        serializer = PasswordResetSerializer(data=empty_payload)

        with self.assertRaises(ValidationError) as exc:
            serializer_valid = serializer.is_valid(raise_exception=True)
        self.assertIn("email", exc.exception.detail)
    
    def test_serializer_empty_email(self):
        self.payload["email"] = ""
        
        serializer = PasswordResetSerializer(data=self.payload)

        with self.assertRaises(ValidationError) as exc:
            serializer_valid = serializer.is_valid(raise_exception=True)
        self.assertIn("email", exc.exception.detail)
    
    def test_serializer_email_not_registered(self):
        self.payload["email"] = "email.not.exists@test.com"

        serializer = PasswordResetSerializer(data=self.payload)

        with self.assertRaises(ValidationError) as exc:
            serializer_valid = serializer.is_valid(raise_exception=True)
        self.assertEqual(
            str(exc.exception.detail["email"][0]),
            "Email not registered in the system.",
        )

    def test_serializer_success(self):
        serializer = PasswordResetSerializer(data=self.payload)
        serializer_valid = serializer.is_valid(raise_exception=True)

        self.assertTrue(serializer_valid)
