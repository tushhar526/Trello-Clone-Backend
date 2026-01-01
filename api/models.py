from django.db import models
from django.contrib.auth.hashers import make_password, check_password
from datetime import timedelta

# Create your models here.


class UserModel(models.Model):
    user_id = models.AutoField(primary_key=True)
    username = models.CharField(max_length=50, blank=False, null=False, unique=True)
    password = models.CharField(max_length=250, blank=False, null=False)
    email = models.EmailField(max_length=100, unique=True, null=True, blank=True)
    created_at = models.DateField(auto_now_add=True)

    def set_password(self, raw_password):
        self.password = make_password(raw_password)

    def check_password(self, raw_password):
        return check_password(raw_password, self.password)

    def __str__(self):
        return self.username
