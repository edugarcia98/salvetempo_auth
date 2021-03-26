from django.conf import settings
from django.contrib.auth.forms import PasswordResetForm
from rest_framework import serializers
from rest_framework.serializers import ValidationError

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

class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password_reset_form_class = PasswordResetForm

    def validate_email(self, value):
        if not value:
            raise ValidationError("Email must not be empty.")
        
        self.reset_form = self.password_reset_form_class(data=self.initial_data)
        if not self.reset_form.is_valid():
            raise ValidationError("Invalid email data.")
        
        try:
            User.objects.get(email=value)
        except User.DoesNotExist:
            raise ValidationError("Email not registered in the system.")
    
    def save(self):
        request = self.context.get("request")
        self.reset_form.save(
            subject_template_name=(
                f"{settings.TEMPLATES_ROOT}/authentication/reset_password/subject.txt"
            ),
            email_template_name=(
                f"{settings.TEMPLATES_ROOT}/authentication/reset_password/message.txt"
            ),
            use_https=request.is_secure(),
            from_email="FOO",
            request=request,
        )
