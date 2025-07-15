"""
Serializers for the accounts app, which handle the serialization of user data.
"""
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.core.cache import cache

from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework.exceptions import AuthenticationFailed

from .tasks import send_otp_to_user
from .models import OTP


User = get_user_model()


class UserRegistrationSerializer(serializers.ModelSerializer):
    password1 = serializers.CharField(write_only=True, min_length=8)
    password2 = serializers.CharField(write_only=True, min_length=8)

    class Meta:
        model = User
        fields = ['email', 'password1', 'password2']

    def validate(self, data):
        """Ensure the two passwords match."""
        if data['password1'] != data['password2']:
            raise ValidationError("Passwords do not match.")
        return data

    def create(self, validated_data):
        """Create and return a new user."""
        password = validated_data.pop('password1')
        email = validated_data.pop('email')
        user = User.objects.create_user(email=email, password=password)
        user.save()
        send_otp_to_user(user)
        return user

    def update(self, instance, validated_data):
        """Update authenticated user."""
        password = validated_data.pop('password1', None)
        user = super().update(instance, validated_data)

        if password:
            user.set_password(password)
            user.save()
        return user


class OTPVerificationSerializer(serializers.Serializer):
    """Serializer for OTP."""
    email = serializers.EmailField()
    otp_code = serializers.CharField()

    def validate_otp(self, email, otp_code):
        """Validate the OTP Code."""
        try:
            otp = OTP.objects.get(user__email=email, code=otp_code)
        except OTP.DoesNotExist:
            raise serializers.ValidationError("Invalid OTP Code!")

        if otp.is_expired():
            raise serializers.ValidationError("OTP has expired!")

        return otp


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """
        JWT serializer with is_verified check and
        strict lockout after 5 failed attempts.
    """

    def validate(self, attrs):
        email = attrs.get("email", "").lower()
        lock_key = f"lockout_{email}"
        attempts_key = f"login_attempts_{email}"

        if cache.get(lock_key):
            raise AuthenticationFailed(
                """Too many failed login attempts.
                   Please try again in 5 minutes."""
            )

        try:
            data = super().validate(attrs)

            if not self.user.is_verified:
                raise AuthenticationFailed("User is not verified.")

            cache.delete(attempts_key)
            return data

        except AuthenticationFailed:
            attempts = cache.get(attempts_key, 0) + 1
            cache.set(attempts_key, attempts, timeout=300)

            if attempts >= 5:
                cache.set(lock_key, True, timeout=300)
                cache.delete(attempts_key)
                raise AuthenticationFailed(
                    """Account locked due to too many failed attempts.
                       Try again in 5 minutes."""
                )

            raise AuthenticationFailed("Invalid credentials.")


class ResendOPTSerializer(serializers.Serializer):
    """Serializer for resending OTP."""
    email = serializers.EmailField()

    def validate_email(self, value):
        """Validate email address."""
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError('No user with this email found.')
        return value
