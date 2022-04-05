#!/usr/bin/env python3
"""Model Tests

"""

from django.test import TestCase
from django.contrib.auth.models import User
from django.utils import timezone
from django.urls import reverse
from core.serializers import UserSerializer, UserSerializerWithToken, ChangePasswordSerializer
from core.models import Profile

class UserTests(TestCase):
    """Test for User Creation

    User Creation causes a Profile object to be created as well.
    """

    def create_user(self):
        """Creat Test User

        """

        user_request = {
            'username': 'tester',
            'email': 'test@testing.com',
            'password': 'testing123',
            'profile': {
                'username': 'tester',
                'public': True,
                'affiliation': 'Testing',
                'orcid': 'https://orcid.org/xxxx-xxxx-xxxx-xxxx'
            }
        }

        profile = user_request['profile']
        del user_request['profile']
        serializer = UserSerializerWithToken(data=user_request)
        if serializer.is_valid():
            serializer.save()
            user_object = User.objects.get(username=user_request['username'])
            Profile.objects.create(
                username=user_object,
                public=profile['public'],
                affiliation=profile['affiliation'],
                orcid=profile['orcid'])

            return User.objects.get(username=user_request['username'])
        return None

    def test_user(self):
        """Tests for User

        """

        user = self.create_user()
        self.assertTrue(isinstance(user, User))
        self.assertEqual(user.email, 'test@testing.com')

    def test_profile(self):
        """Tests for Profile

        """
        user = self.create_user()
        profile = Profile.objects.get(username=user.id)
        self.assertTrue(isinstance(profile, Profile))
