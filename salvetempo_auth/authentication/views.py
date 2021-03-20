from django.core.exceptions import ValidationError as DjangoValidationError

from rest_framework import status
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet

from .models import User
from .serializers import UserSerializer


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
        
        return Response(UserSerializer(instance=user).data, status.HTTP_201_CREATED)