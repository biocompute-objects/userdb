from django.contrib import admin
from core.models import ApiInfo, Prefixes, Profile


admin.site.register(ApiInfo)
admin.site.register(Prefixes)
admin.site.register(Profile)