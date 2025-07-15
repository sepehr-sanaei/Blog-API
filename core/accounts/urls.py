"""
URL configuration for accounts app.
"""
from django.urls import path
from rest_framework_simplejwt.views import (
    TokenRefreshView,
    TokenBlacklistView,
    TokenVerifyView
)
from .views import (
    UserRegistrationAPIView,
    OTPVerificationAPIView,
    CustomTokenObtainPairView,
    ResendOTPApiView,
)

app_name = 'accounts'

urlpatterns = [
    path('create/', UserRegistrationAPIView.as_view(), name='register_user'),
    path(
        'jwt/create/', CustomTokenObtainPairView.as_view(), name='jwt_create'
    ),
    path('jwt/refresh/', TokenRefreshView.as_view(), name='jwt_refresh'),
    path('jwt/verify/', TokenVerifyView.as_view(), name='jwt_verify'),
    path('jwt/blacklist/', TokenBlacklistView.as_view(), name='jwt_blacklist'),
    path('otp/verify/', OTPVerificationAPIView.as_view(), name='otp_verify'),
    path('otp/resend/', ResendOTPApiView.as_view(), name='otp_resend'),
]
