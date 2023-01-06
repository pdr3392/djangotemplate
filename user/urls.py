from django.urls import path, include
from rest_framework import routers

from user.views import CreateUserViewSet, UserLoginViewSet, UpdateUserViewSet

router = routers.SimpleRouter()
router.register(
    prefix="account/register", viewset=CreateUserViewSet, basename="account_register"
)
router.register(
    prefix="account/update", viewset=UpdateUserViewSet, basename="account_update"
)
router.register(prefix="auth/login", viewset=UserLoginViewSet, basename="auth_login")

urlpatterns = [path("", include(router.urls))]
