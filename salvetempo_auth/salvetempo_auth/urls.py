from django.contrib import admin
from django.urls import path, include

prefix = "api"

urlpatterns = [
    path("admin/", admin.site.urls),
    path(f"{prefix}/auth/", include("authentication.urls")),
]
