#!/usr/bin/env python3
"""URLs

"""

from django.urls import path, include
from django.contrib.staticfiles.storage import staticfiles_storage
from django.views.generic.base import RedirectView
from rest_framework_jwt.views import obtain_jwt_token, refresh_jwt_token, verify_jwt_token
from core.views import (
    current_user,
    add_api,
    remove_api,
    CreateUser,
    update_user,
    ChangePasswordView,
    register_prefix,
    SearchPrefix
)

urlpatterns = [
    path('favicon.ico', RedirectView.as_view(url=staticfiles_storage.url('img/favicon.ico'))),
    path('users/current_user/', current_user),
    path('users/add_api/', add_api),
    path('users/remove_api/', remove_api),
    path('users/list/', CreateUser.as_view()),
    path('users/update_user/', update_user),
    path('users/token-auth/', obtain_jwt_token),
    path('users/token-refresh/', refresh_jwt_token),
    path('users/token-verify/', verify_jwt_token),
    path('users/change_password/', ChangePasswordView.as_view()),
    path('users/password_reset/', include(
        'django_rest_passwordreset.urls',
        namespace='password_reset')
    ),
    path('users/register_prefix/', register_prefix),
    path('users/prefixes/', SearchPrefix.as_view()),
]
