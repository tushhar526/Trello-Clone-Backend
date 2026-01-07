from django.db import models
from django.contrib.auth.hashers import make_password, check_password
from datetime import timedelta
from django.db import models
from django.contrib.auth.models import (
    AbstractBaseUser,
    PermissionsMixin,
    BaseUserManager,
)


# Create your models here.
class UserModel(models.Model):
    user_id = models.AutoField(primary_key=True)
    username = models.CharField(max_length=50, blank=False, null=False, unique=True)
    password = models.CharField(max_length=250, blank=False, null=False)
    email = models.EmailField(max_length=100, null=True, blank=True)
    created_at = models.DateField(auto_now_add=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    USERNAME_FIELD = "username"
    REQUIRED_FIELDS = []

    @property
    def is_anonymous(self):
        return False

    @property
    def is_authenticated(self):
        return True

    def has_perm(self, perm, obj=None):
        """Check if user has permission"""
        return self.is_staff

    def has_module_perms(self, app_label):
        """Check if user has module permissions"""
        return self.is_staff

    def set_password(self, raw_password):
        self.password = make_password(raw_password)

    def check_password(self, raw_password):
        return check_password(raw_password, self.password)

    def __str__(self):
        return self.username
