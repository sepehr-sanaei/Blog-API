"""
Database models for accounts app.
"""
import random
import string

from django.db import models
from django.utils.translation import gettext_lazy as _
from django.dispatch import receiver
from django.db.models.signals import post_save
from django.utils import timezone
from datetime import timedelta
from django.contrib.auth.models import (
    BaseUserManager,
    AbstractBaseUser,
    PermissionsMixin
)


class UserManager(BaseUserManager):
    """
    Custom user model manager where email is the unique identifiers
    for authentication instead of usernames.
    """

    def create_user(self, email, password, **extra_fields):
        """
        Create and save a User with the given
        email and password and extra data.
        """
        if not email:
            raise ValueError(_("the Email must be set"))
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, email, password, **extra_fields):
        """
        Create and save a SuperUser with the given email and password.
        """
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)
        extra_fields.setdefault("is_verified", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError(_("Superuser must have is_staff=True."))
        if extra_fields.get("is_superuser") is not True:
            raise ValueError(_("Superuser must have is_superuser=True."))
        return self.create_user(email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    """Custom User model for authentication."""
    email = models.EmailField(max_length=255, unique=True)
    is_staff = models.BooleanField(default=False)
    is_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateField(auto_now=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    objects = UserManager()

    def __str__(self):
        """String representation of User model."""
        return self.email


class Profile(models.Model):
    """Database model for profile."""
    user = models.OneToOneField(
        "User",
        on_delete=models.CASCADE,
        related_name='user_profile'
    )
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    bio = models.TextField()
    birth_date = models.DateTimeField(null=True, blank=True)
    country = models.CharField(max_length=255)
    image = models.ImageField(
        upload_to='profile/',
        default='profile/default.jpg'
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def get_full_name(self):
        """return the full name of User."""
        if self.first_name or self.last_name:
            return self.first_name + ' ' + self.last_name
        return 'New User'

    def __str__(self):
        """string representation of Profile model."""
        return self.user.email


@receiver(post_save, sender=User)
def create_profile(sender, instance, created, **kwargs):
    """Create profile automatically when the user is created."""
    if created:
        Profile.objects.create(user=instance, pk=instance.id)


class OTP(models.Model):
    """OTP database model."""
    user = models.ForeignKey(
        "User",
        on_delete=models.CASCADE,
        related_name='otp'
    )
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

    def is_expired(self):
        """Checks if the OTP is expired."""
        return timezone.now() > self.expires_at

    def __str__(self):
        """Sting representation of model."""
        return f'OTP for {self.user.email}'

    def generate_otp_code(self):
        """Generate a random 6-digit OTP code."""
        return ''.join(random.choices(string.digits, k=6))

    def save(self, *args, **kwargs):
        if not self.code:
            self.code = self.generate_otp_code()
        self.expires_at = timezone.now() + timedelta(minutes=2)
        super().save(*args, **kwargs)
