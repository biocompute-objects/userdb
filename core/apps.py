#!/usr/bin/env python3
"""Run code after start-up"""

from django.apps import AppConfig


class CoreConfig(AppConfig):
    """Core"""

    name = "core"
    default_auto_field = "django.db.models.AutoField"
