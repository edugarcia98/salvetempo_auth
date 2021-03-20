from django.urls import include, path

from rest_framework.routers import DefaultRouter
from rest_framework_jwt.views import (
    obtain_jwt_token,
    refresh_jwt_token,
    verify_jwt_token,
)

from .views import UserViewSet


router = DefaultRouter()
router.register("user", UserViewSet, basename="user")

urlpatterns = [
    path("login/", obtain_jwt_token),
    path("verify-token/", verify_jwt_token),
    path("refresh-token/", refresh_jwt_token),
    path("", include(router.urls)),
]
