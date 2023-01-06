from datetime import date, timedelta

import jwt
from django.contrib import auth
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed, NotFound
from rest_framework.validators import UniqueValidator

from user.models import User


class CreateUserSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(
        required=True, validators=[UniqueValidator(queryset=User.objects.all())]
    )

    password = serializers.CharField(
        write_only=True, required=True, validators=[validate_password]
    )
    password2 = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = (
            "username",
            "password",
            "password2",
            "email",
            "first_name",
            "last_name",
        )
        extra_kwargs = {
            "first_name": {"required": True},
            "last_name": {"required": True},
        }

    def validate(self, attrs):
        if attrs["password"] != attrs["password2"]:
            raise serializers.ValidationError(
                {"password": "Password fields must match."}
            )

        return attrs

    def create(self, validated_data):
        yesterday = date.today() - timedelta(days=1)

        user = User.objects.create(
            username=validated_data["username"],
            email=validated_data["email"],
            first_name=validated_data["first_name"],
            last_name=validated_data["last_name"],
            is_active=True,
            expires_in=yesterday,
        )

        user.set_password(validated_data["password"])
        user.save()

        return user


class UpdateUserSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(
        required=False, validators=[UniqueValidator(queryset=User.objects.all())]
    )

    password = serializers.CharField(
        write_only=True, required=False, validators=[validate_password]
    )
    password2 = serializers.CharField(write_only=True, required=False)

    class Meta:
        model = User
        fields = (
            "username",
            "password",
            "password2",
            "email",
            "first_name",
            "last_name",
            "is_active",
        )
        extra_kwargs = {
            "first_name": {"required": False},
            "last_name": {"required": False},
            "username": {"required": False},
            "password": {"required": False},
            "password2": {"required": False},
            "email": {"required": False},
            "is_active": {"required": False},
        }

    def validate(self, attrs):
        headers_items = self.context["request"].META.items()

        token = dict(headers_items)["HTTP_AUTHORIZATION"].split(" ")[1]
        decoded_token = jwt.decode(token, options={"verify_signature": False})

        username = dict(headers_items)["PATH_INFO"].split("/")[-2]

        user = User.objects.filter(username=username)

        if not user.exists():
            raise NotFound("User not found.", 404)

        token_user = User.objects.filter(id=decoded_token["user_id"])

        if not token_user[0] == user[0]:
            raise AuthenticationFailed(
                "You can only change your own profile's information.", 401
            )

        if "password" in attrs:
            if "password2" not in attrs:
                raise serializers.ValidationError(
                    {"password2": "Both fields should be filled."}
                )

            if attrs["password"] != attrs["password2"]:
                raise serializers.ValidationError(
                    {"password": "Password fields didn't match."}
                )

        return attrs

    def update(self, instance, validated_data):
        values_to_parse = {
            "password": validated_data.get("password"),
            "username": validated_data.get("username"),
            "password_two": validated_data.get("password2"),
            "email": validated_data.get("email"),
            "first_name": validated_data.get("first_name"),
            "last_name": validated_data.get("last_name"),
            "is_active": validated_data.get("is_active"),
        }

        if values_to_parse["username"] is not None:
            instance.username = values_to_parse["username"]

        if values_to_parse["is_active"] is not None:
            instance.is_active = bool(values_to_parse["is_active"])

        if values_to_parse["password"] is not None:
            instance.set_password(values_to_parse["password"])

        instance.save()

        return instance


class UserLoginSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=100, min_length=1, write_only=True)
    username = serializers.CharField(max_length=30, min_length=1, write_only=True)
    token = serializers.CharField(max_length=255, min_length=3, read_only=True)

    class Meta:
        model = User
        fields = ["password", "username", "token"]
        extra_kwargs = {
            "username": {"required": True},
            "password": {"required": True},
            "token": {"required": False},
        }

    def create(self, attrs):
        username = attrs.get("username")
        password = attrs.get("password")
        user = auth.authenticate(username=username, password=password)

        if not user:
            raise AuthenticationFailed("Invalid credentials.")

        if not user.is_active:
            raise AuthenticationFailed("Inactive user.")

        account_user = User.objects.filter(username=user.username)

        token = account_user[0].generate_token()

        return {"token": token}
