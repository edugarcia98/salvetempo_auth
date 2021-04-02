from django.contrib.auth.views import (
    PasswordResetCompleteView,
    PasswordResetConfirmView,
)
from django.urls import include, path

from allauth.account.views import confirm_email
from rest_auth.views import PasswordResetView
from rest_framework.routers import DefaultRouter
from rest_framework_jwt.views import refresh_jwt_token, verify_jwt_token


from .views import already_sent, complete, JWTLoginView, UserViewSet


router = DefaultRouter()
router.register("user", UserViewSet, basename="user")

urlpatterns = [
    # Login and token urls
    path("login/", JWTLoginView.as_view()),
    path("verify-token/", verify_jwt_token),
    path("refresh-token/", refresh_jwt_token),

    # Reset password urls
    path("password/reset/", PasswordResetView.as_view(), name="rest_password_reset"),
    path(
        "password/reset/confirm/<uidb64>/<token>/",
        PasswordResetConfirmView.as_view(),
        name="password_reset_confirm",
    ),
    path(
        "password/reset/complete/",
        PasswordResetCompleteView.as_view(),
        name="password_reset_complete",   
    ),

    # Confirm email urls
    path("email/verify/<key>/", confirm_email, name="account_confirm_email"),
    path("email/confirm/sent/", already_sent, name="account_email_verification_sent"),
    path("email/confirm/complete/", complete, name="account_confirm_complete"),

    # Router urls
    path("", include(router.urls)),
]
