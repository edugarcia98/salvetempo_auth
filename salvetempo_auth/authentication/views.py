from allauth.account.models import EmailAddress
from allauth.account.utils import send_email_confirmation
from django.conf import settings
from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework import status
from rest_framework.decorators import action, api_view
from rest_framework.exceptions import AuthenticationFailed, NotFound, ValidationError
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet
from rest_framework_jwt.views import ObtainJSONWebToken
from rest_framework_jwt.utils import jwt_response_payload_handler

from .models import User
from .serializers import UserSerializer


class JWTLoginView(ObtainJSONWebToken):
    """
        Rest framework JWT overriden view considering email verification
    """

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid(raise_exception=True):
            user = serializer.object.get("user") or request.user

            if settings.ACCOUNT_EMAIL_VERIFICATION == "mandatory":
                try:
                    email_address = EmailAddress.objects.get(email=user.email)
                except EmailAddress.DoesNotExist:
                    raise NotFound(detail={"error": "Email address not found."})
                
                if not email_address.verified:
                    raise AuthenticationFailed(detail={"error": "Email not verified."})

            token = serializer.object.get("token")
            response_data = jwt_response_payload_handler(token, user, request)

            return Response(response_data)


class UserViewSet(ModelViewSet):
    """
        Viewset for User actions
    """

    @action(methods=("POST",), detail=False, url_path="register")
    def register_user(self, request):
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        pwd = serializer.validated_data["password"]
        confirm_pwd = serializer.validated_data["password_confirm"]

        if pwd != confirm_pwd:
            raise ValidationError(detail={"error": "Passwords must be equal."})
        
        try:
            user = User.objects.create_user(serializer.validated_data["email"], pwd)
        except DjangoValidationError as exc:
            raise ValidationError(detail={"error": list(exc)})
        except Exception as exc:
            raise ValidationError(detail={"error": str(exc)})
        
        send_email_confirmation(request, user)
        
        return Response(UserSerializer(instance=user).data, status.HTTP_201_CREATED)


@api_view()
def already_sent(request):
    message = "Confirmation email already sent."
    return Response({"message": message}, status.HTTP_400_BAD_REQUEST)


@api_view()
def complete(request):
    message = "Email is activated."
    return Response({"message": message}, status.HTTP_200_OK)
