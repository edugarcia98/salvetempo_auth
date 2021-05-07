import jwt
import logging

from allauth.account.models import EmailAddress
from datetime import datetime, timedelta
from django.conf import settings
from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework import status
from rest_framework.decorators import action, api_view
from rest_framework.exceptions import AuthenticationFailed, NotFound, ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.viewsets import ViewSet
from rest_framework_jwt.views import ObtainJSONWebToken
from rest_framework_jwt.utils import jwt_response_payload_handler

from .models import User
from .serializers import UserSerializer
from .tasks import send_email_confirmation_after_register

logger = logging.getLogger(__name__)


class JWTLoginView(ObtainJSONWebToken):
    """
        Rest framework JWT overriden view considering email verification
    """

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid(raise_exception=True):
            user = serializer.object.get("user") or request.user

            message = f"[User ID: {user.id}] Starting login."
            logger.info(message)

            if settings.ACCOUNT_EMAIL_VERIFICATION == "mandatory":
                try:
                    email_address = EmailAddress.objects.get(email=user.email)
                except EmailAddress.DoesNotExist:
                    message = (
                        f"[User ID: {user.id}] [Email: {user.email}] "
                        f"Email address not found."
                    )
                    logger.error(message)

                    raise NotFound(detail={"error": "Email address not found."})
                
                if not email_address.verified:
                    message = (
                        f"[User ID: {user.id}] [Email: {user.email}] "
                        f"Email not verified."
                    )
                    logger.error(message)

                    raise AuthenticationFailed(detail={"error": "Email not verified."})

            token = serializer.object.get("token")
            response_data = jwt_response_payload_handler(token, user, request)

            message = (
                f"[User ID: {user.id}] [Email: {user.email}] "
                f"User successfully logged in."
            )
            logger.info(message)

            return Response(response_data)


class UserViewSet(ViewSet):
    """
        Viewset for User actions
    """

    @action(methods=("POST",), detail=False, url_path="register")
    def register_user(self, request):
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data["email"]
        pwd = serializer.validated_data["password"]
        confirm_pwd = serializer.validated_data["password_confirm"]

        message = f"[Email: {email}] Starting user registration."
        logger.info(message)

        if pwd != confirm_pwd:
            message = (
                f"[Email: {email}] User password and password confirm must be equal."
            )
            logger.error(message)

            raise ValidationError(detail={"error": "Passwords must be equal."})
        
        try:
            user = User.objects.create_user(email, pwd)
        except DjangoValidationError as exc:
            message = (
                f"[Email: {email}] Django validation error while creating user. "
                f"[Content: {exc}]"
            )
            logger.error(message)

            raise ValidationError(detail={"error": list(exc)})
        except Exception as exc:
            exc_name = type(exc).__name__

            message = (
                f"[Email: {email}] [Exception: {exc_name}] "
                f"An unexpected exception occured. [Content: {exc}]"
            )
            logger.error(message)

            raise ValidationError(detail={"error": str(exc)})
        
        send_email_confirmation_after_register.delay(user.email)

        message = f"[Email: {email}] User created."
        logger.info(message)
        
        return Response(UserSerializer(instance=user).data, status.HTTP_201_CREATED)


class TokenRefreshTimeViewSet(ViewSet):
    """
        Viewset for Token Refresh Time action
    """

    permission_classes = (IsAuthenticated, )

    @action(methods=("GET",), detail=False, url_path="refresh-time")
    def refresh_time(self, request):
        logger.info("Retrieving refresh time.")

        try:
            token = request.headers.get("Authorization").split(" ")[1]
        except (AttributeError, IndexError) as exc:
            exc_name = type(exc).__name__

            message = f"{exc_name} occured while retrieving JWT token. [Content: {exc}]"
            logger.error(message)

            raise ValidationError(detail={"error": "Unable to get JWT token."})
        
        try:
            decoded = jwt.decode(token, options={"verify_signature": False})
        except jwt.exceptions.DecodeError as exc:
            message = f"An error occured while decoding JWT token. [Content: {exc}]"
            logger.error(message)

            raise ValidationError(detail={"error": "Unable to decode JWT token."})       

        try:
            refresh_token_after = (
                datetime.fromtimestamp(decoded["exp"]) - timedelta(minutes=1)
            )
        except (KeyError, TypeError) as exc:
            exc_name = type(exc).__name__

            message = (
                f"{exc_name} occurred while converting timestamp to datetime. "
                f"[Content: {exc}]"
            )
            logger.error(message)

            raise ValidationError(
                detail={"error": "Some error occured while retrieving refresh time."}
            )
        
        message = f"Refresh time retrieve. [Datetime: {refresh_token_after}]"
        logger.info(message)

        return Response(
            {"refresh_token_after": str(refresh_token_after)}, status.HTTP_200_OK,
        )


@api_view()
def already_sent(request):
    message = "Confirmation email already sent."
    return Response({"message": message}, status.HTTP_400_BAD_REQUEST)


@api_view()
def complete(request):
    message = "Email is activated."
    return Response({"message": message}, status.HTTP_200_OK)
