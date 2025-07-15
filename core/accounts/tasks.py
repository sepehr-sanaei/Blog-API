from celery import shared_task

from django.core.mail import send_mail

from .models import OTP


@shared_task
def send_otp_email(user_email, otp_code):
    """Send OTP to user email."""
    subject = "Your OTP Code"
    message = f'Your OTP Code is: {otp_code}'
    send_mail(subject, message, 'amazon@gmail.com', [user_email])


def send_otp_to_user(user):
    """Send email using celery."""
    otp = OTP.objects.create(user=user)
    send_otp_email.apply_async((user.email, otp.code))
