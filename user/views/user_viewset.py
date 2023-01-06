from rest_framework.permissions import IsAuthenticated
from rest_framework.viewsets import ModelViewSet

from user.models import User
from user.serializers import (
    UserLoginSerializer,
    UpdateUserSerializer,
    CreateUserSerializer,
)


class CreateUserViewSet(ModelViewSet):
    lookup_field = "username"

    serializer_class = CreateUserSerializer
    http_method_names = ["post"]

    def get_queryset(self):
        return User.objects.all().order_by("username")

    def post_queryset(self):
        username = self.kwargs["username"]

        return User.objects.filter(username=username)


class UpdateUserViewSet(ModelViewSet):
    permission_classes = (IsAuthenticated,)
    lookup_field = "username"

    serializer_class = UpdateUserSerializer
    http_method_names = ["put"]

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context["request"] = self.request

        return context

    def get_queryset(self):
        return User.objects.all()

    def put_queryset(self):
        username = self.kwargs["username"]
        return User.objects.filter(username=username)


class UserLoginViewSet(ModelViewSet):
    serializer_class = UserLoginSerializer

    http_method_names = ["post"]
