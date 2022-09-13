#!/usr/bin/env python3
"""Custom Serializers
"""
from rest_framework import serializers
from rest_framework_jwt.settings import api_settings
from django.contrib.auth.models import User
from django.contrib.auth.models import Group
from core.models import ApiInfo, Profile

# Groups require special processing.
# Source: https://stackoverflow.com/questions/33844003/
#           how-to-serialize-groups-of-a-user-with-django-rest-framework/33844179


class ChangePasswordSerializer(serializers.Serializer):
    """Serializer for password change endpoint.

    * Provideds serializer for an old password and a new password

    :param str old_password: the old password
    :param str new_password: the new password
    """

    model = User
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)


# Profile serializer
class ProfileSerializer(serializers.ModelSerializer):
    """Profile serializer

    username = serializers.SlugRelatedField(slug_field = 'username', queryset = User.objects.all())
    """

    class Meta:
        """Meta"""

        model = Profile
        fields = ("username", "public", "affiliation", "orcid")


# API serializer
class ApiSerializer(serializers.ModelSerializer):
    """API Serializer

    Only if the username on portal and the API are the same...
    """

    class Meta:
        """Meta"""

        model = ApiInfo
        fields = (
            "username",
            "hostname",
            "human_readable_hostname",
            "public_hostname",
            "token",
            "other_info",
        )


class GroupSerializer(serializers.ModelSerializer):
    """Group Serializer"""

    class Meta:
        """Meta"""

        model = Group
        fields = ("name",)


class UserSerializer(serializers.ModelSerializer):
    """User Serializer"""

    apiinfo = ApiSerializer(source="custom_user", many=True)
    groups = GroupSerializer(many=True)
    profile = ProfileSerializer(many=False)

    class Meta:
        """Meta"""

        model = User
        fields = (
            "username",
            "password",
            "first_name",
            "last_name",
            "email",
            "profile",
            "groups",
            "apiinfo",
        )


class UserSerializerWithToken(serializers.ModelSerializer):
    """User Serializer"""

    token = serializers.SerializerMethodField()
    password = serializers.CharField(write_only=True)

    def get_token(self, obj):
        """Get Token"""
        jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
        jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER

        payload = jwt_payload_handler(obj)
        token = jwt_encode_handler(payload)

        return token

    def create(self, validated_data):
        """Create"""
        password = validated_data.pop("password", None)
        instance = self.Meta.model(**validated_data)

        if password is not None:
            instance.set_password(password)
        instance.save()

        return instance

    class Meta:
        "Meta"
        model = User
        fields = (
            "token",
            "username",
            "password",
            "first_name",
            "last_name",
            "email",
            "groups",
        )
