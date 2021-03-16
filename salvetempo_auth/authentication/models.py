from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.core.exceptions import ValidationError


class UserManager(BaseUserManager):
    def _validate_user(self, email, password):
        if not email:
            raise ValidationError("User must not have an empty email.")
        if not password:
            raise ValidationError("User must not have an empty password")

    def create_user(self, email, password):
        self._validate_user(email, password)

        user = self.model(email=email)
        user.set_password(password)
        user.save(using=self._db)

        return user

    def create_superuser(self, email, password):
        self._validate_user(email, password)

        user = self.model(email=email, is_admin=True, is_staff=True, is_superuser=True)
        user.set_password(password)
        user.save(using=self._db)

        return user


class User(AbstractBaseUser):
    email = models.EmailField(max_length=254, unique=True, verbose_name="E-mail")
    date_joined = models.DateTimeField(verbose_name="Date joined", auto_now_add=True)
    last_login = models.DateTimeField(verbose_name="Last login", auto_now=True)
    is_active = models.BooleanField(verbose_name="Active", default=True)
    is_admin = models.BooleanField(verbose_name="Admin", default=False)
    is_staff = models.BooleanField(verbose_name="Staff", default=False)
    is_superuser = models.BooleanField(verbose_name="Superuser", default=False)

    USERNAME_FIELD = "email"

    REQUIRED_FIELDS = []

    objects = UserManager()

    def __str__(self):
        return self.email
    
    def has_perm(self, perm, obj=None):
        return self.is_admin

    def has_module_perms(self, app_label):
        return self.is_admin
