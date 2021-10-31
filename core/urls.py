from django.urls import path
from .views import current_user, add_api, remove_api, UserList, update_user, index

urlpatterns = [
    path('users/current_user/', current_user),
    path('users/add_api/', add_api),
    path('users/remove_api/', remove_api),
    path('users/list/', UserList.as_view()),
    path('users/update_user/', update_user),
    path('users/', index, name='index'),
]
