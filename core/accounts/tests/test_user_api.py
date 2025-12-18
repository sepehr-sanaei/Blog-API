# accounts/tests/test_views.py
from rest_framework.test import APITestCase, APIClient
from rest_framework import status

from unittest.mock import patch, ANY
from datetime import timedelta

from django.urls import reverse
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.test import TestCase

from accounts.models import User, OTP


CREATE_USER_API = reverse('accounts:register_user')

def create_user(**params):
    """create and return a new user."""
    return get_user_model().objects.create_user(**params)


class UserApiTest(TestCase):
    """Test features of User api."""
    def setUp(self):
        self.client = APIClient()

    def test_create_user_successful(self):
        """Test creating a new user with api endpoints is successful."""
        payload = {
            "email" : 'test@example.com',
            'password': 'A/@123456'
        }
        res = self.client.post(CREATE_USER_API, payload)
        self.assertEqual(res.status_code, status.HTTP_201_CREATED)
        user = get_user_model().objects.get(email=payload['email'])
        self.assertTrue(user.check_password(payload['password']))
        self.assertNotIn('password', res.data)


class OTPVerificationTests(APITestCase):
    def setUp(self):
        """Set up a user and an OTP for testing."""
        self.user = User.objects.create_user(
            email='testuser@example.com', password='password123'
        )
        self.otp = OTP.objects.create(user=self.user, code='123456')
        self.url = reverse('accounts:otp_verify')

    def test_otp_verification_valid(self):
        """Test OTP verification with valid code."""
        data = {
            'email': self.user.email,
            'otp_code': self.otp.code
        }
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_verified)

    def test_otp_verification_invalid(self):
        """Test OTP verification with an invalid OTP code."""
        data = {
            'email': self.user.email,
            'otp_code': 'wrongcode'
        }
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('Invalid OTP Code!', str(response.data))

    def test_otp_expired(self):
        """Test OTP verification with an expired OTP code."""
        # Force the OTP to be expired by setting expires_at in the past
        self.otp.expires_at = timezone.now() - timedelta(minutes=1)
        self.otp.save()

        data = {
            'email': self.user.email,
            'otp_code': self.otp.code
        }
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('OTP has expired', str(response.data))

    def test_otp_verification_nonexistent_user(self):
        """Test OTP verification with non-existent user email."""
        data = {
            'email': 'nonexistent@example.com',
            'otp_code': '123456'
        }
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('Invalid OTP Code!', str(response.data))