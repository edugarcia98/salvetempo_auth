from rest_framework import serializers

from .models import User


class UserSerializer(serializers.ModelSerializer):
    password_confirm = serializers.CharField(
        style={"input_type": "password"}, write_only=True,
    )

    class Meta:
        model = User
        fields = ("id", "email", "password", "password_confirm")
        read_only_fields = ("id",)
        extra_kwargs = {
            "password": {"write_only": True},
        }
