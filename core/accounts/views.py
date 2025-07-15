"""
    Views for the accounts app,
    handling user registration, login, and token management.
"""
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenObtainPairView

from django.contrib.auth import get_user_model
from django.utils import timezone
from django.utils.timezone import timedelta

from .serializers import (
    UserRegistrationSerializer,
    OTPVerificationSerializer,
    CustomTokenObtainPairSerializer,
    ResendOPTSerializer
)
from .models import OTP
from .tasks import send_otp_to_user


User = get_user_model()


class UserRegistrationAPIView(generics.CreateAPIView):
    """
    View for user registration.
    """
    permission_classes = [permissions.AllowAny]
    serializer_class = UserRegistrationSerializer


class OTPVerificationAPIView(generics.GenericAPIView):
    """View for verifying otp code."""
    permission_classes = [permissions.AllowAny]
    serializer_class = OTPVerificationSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            otp_code = serializer.validated_data['otp_code']

            otp = serializer.validate_otp(email, otp_code)

            user = otp.user
            user.is_verified = True
            user.save()

            return Response(
                {"message": "OTP verified successfully."},
                status=status.HTTP_200_OK
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CustomTokenObtainPairView(TokenObtainPairView):
    """Custom view for obtaining jwt token."""
    serializer_class = CustomTokenObtainPairSerializer


class ResendOTPApiView(generics.GenericAPIView):
    """View for resending OTP code."""
    permission_classes = []
    serializer_class = ResendOPTSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            email = serializer.validated_data['email']
            user = User.objects.get(email=email)

            # Prevent frequent resends (every 30 seconds)
            existing_otp = OTP.objects.filter(user=user).last()
            if (
                existing_otp and
                existing_otp.created_at > (
                    timezone.now() - timedelta(seconds=30)
                )
            ):
                return Response(
                    {"detail": "Please wait before requesting a new OTP."},
                    status=status.HTTP_429_TOO_MANY_REQUESTS
                )

            OTP.objects.filter(user=user).delete()
            send_otp_to_user(user)

            return Response(
                {"detail": "OTP resent successfully."},
                status=status.HTTP_200_OK
            )

        return Response(
            serializer.errors,
            status=status.HTTP_400_BAD_REQUEST
        )
