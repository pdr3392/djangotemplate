import json

from django.contrib.auth.models import User
from django.db import models
from rest_framework_simplejwt.tokens import RefreshToken


class AppUser(User):
    expires_in = models.DateField()

    def __str__(self):
        string_model = json.dumps(
            {
                "username": self.username,
                "email": self.email,
                "is_active": self.is_active,
                "expires_in": self.expires_in.strftime("%m/%d/%Y, %H:%M:%S"),
            }
        )

        return string_model

    def generate_token(self):
        refresh = RefreshToken.for_user(self)

        return {
            "refresh": str(refresh),
            "access": str(refresh.access_token),
        }
