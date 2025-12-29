from django.db import models
from django.contrib.auth.hashers import make_password, check_password
from datetime import timedelta
from .helpers import *

# Create your models here.


class UserModel(models.Model):
    user_id = models.AutoField(primary_key=True)
    username = models.CharField(max_length=50, blank=False, null=False, unique=True)
    password = models.CharField(max_length=250, blank=False, null=False)
    email = models.EmailField(max_length=100, unique=True)
    email_verified = models.BooleanField(default=False)
    phonenumber = models.CharField(max_length=10, unique=True)
    phonenumber_verified = models.BooleanField(default=False)
    created_at = models.DateField(auto_now_add=True)

    def set_password(self, raw_password):
        self.password = make_password(raw_password)

    def check_password(self, raw_password):
        return check_password(raw_password, self.password)

    def __str__(self):
        return self.username


class VerificationUserModel(models.Model):
    username = models.CharField(blank=False, null=False, max_length=100, unique=True)
    password = models.CharField(max_length=250, blank=False, null=False)
    email = models.EmailField(blank=True, null=True, unique=True)
    phonenumber = models.CharField(blank=True, null=True, unique=True)
    otp = models.CharField(max_length=4, blank=True, null=True)
    expires_at = models.DateTimeField()
    resent_count = models.IntegerField(default=0)
    last_resent_at = models.DateTimeField(null=True, blank=True)
    validation_purpose = models.CharField()

    def is_expired(self):
        return timezone.now() > self.expires_at

    def resend_OTP(self):
        self.otp = generate_OTP()
        self.resend_count += 1
        self.last_resent_at = timezone.now()
        self.save()
        self.expires_at = timezone.now() + timedelta(minutes=2)
        return self.otp

    def can_resend_OTP(self):
        if self.resend_count >= 3:
            return False, "Too Many Attempts"

        timediff = timezone.now() - self.last_resent_at

        if timediff.total_seconds() < 30:
            return False, f"Wait for {30 - int(timediff.total_seconds())} seconds"
