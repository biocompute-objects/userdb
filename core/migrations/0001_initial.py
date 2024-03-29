# Generated by Django 3.2 on 2021-06-24 00:37

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="Profile",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("public", models.BooleanField(blank=True, default=False)),
                ("affiliation", models.CharField(blank=True, max_length=1000)),
                ("orcid", models.CharField(blank=True, max_length=1000)),
                (
                    "username",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="ApiInfo",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("username", models.CharField(blank=True, max_length=1000)),
                ("hostname", models.CharField(blank=True, max_length=15)),
                (
                    "human_readable_hostname",
                    models.CharField(blank=True, max_length=1000),
                ),
                ("public_hostname", models.CharField(blank=True, max_length=1000)),
                ("token", models.CharField(blank=True, max_length=1000)),
                ("other_info", models.JSONField()),
                (
                    "local_username",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="custom_user",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
        ),
    ]
