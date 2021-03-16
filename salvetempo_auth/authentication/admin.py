from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.forms import AdminPasswordChangeForm
from .models import User


class UserAdmin(UserAdmin):
    list_display = (
        "email",
        "date_joined",
        "last_login",
        "is_active",
        "is_admin",
        "is_staff",
        "is_superuser",
    )
    search_fields = ("email",)
    readonly_fields = ("date_joined", "last_login")

    filter_horizontal = ()
    list_filter = ()
    fieldsets = (
        (
            None,
            {"fields": ("email", "password",)},
        ),
        (
            "Permissions",
            {"fields": ("is_active", "is_admin", "is_staff", "is_superuser")},
        ),
    )

    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": ("email", "password1", "password2"),
            }
        ),
    )
    
    ordering = ("email",)

admin.site.register(User, UserAdmin)
