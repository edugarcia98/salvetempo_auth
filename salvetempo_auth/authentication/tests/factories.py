from factory.django import DjangoModelFactory

from allauth.account.models import EmailAddress

from ..models import User


class UserFactory(DjangoModelFactory):
    email = "test@test.com"

    class Meta:
        model = User


class EmailAddressFactory(DjangoModelFactory):
    email = "test@test.com"
    verified = True
    primary = True

    class Meta:
        model = EmailAddress
