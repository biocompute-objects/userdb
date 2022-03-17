#!/usr/bin/env python3
"""Customer user model.
    Source: https://docs.djangoproject.com/en/3.1/topics/auth/customizing/#extending-the-existing-user-model
    Source: https://docs.djangoproject.com/en/3.1/topics/db/models/#many-to-one-relationships
"""

from django.db import models
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.dispatch import receiver
from django.urls import reverse
from django_rest_passwordreset.signals import reset_password_token_created
from rest_framework import status
from rest_framework.response import Response

@receiver(reset_password_token_created)
def password_reset_token_created(sender, instance, reset_password_token, *args, **kwargs):
    """
    Create the token for a password reset.
    """
    email_plaintext_message = "{}?token={}".format(reverse(
        'password_reset:reset-password-request'), reset_password_token.key)

    try:
        send_mail(
            subject='Password reset for BioCompute Portal',
            message= email_plaintext_message,
            html_message=email_plaintext_message,
            from_email='mail_sender@portal.aws.biochemistry.gwu.edu',
            recipient_list=[reset_password_token.user.email],
            fail_silently=False,
        )

    except Exception as error:
        print('activation_link', reset_password_token)
        # print('ERROR: ', error)
        # TODO: Should handle when the send_mail function fails?
        # return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR, data={
        # "message": "Not able to send authentication email: {}".format(error)})
        return Response(status=status.HTTP_201_CREATED,
            data={"message": "Reset token has been requested but email was not sent."\
                f" Check with your database administrator for your token. {error}"})

class Profile(models.Model):
    """
    Modle for storing additional user information
    Public Profile
    User Affiliation
    User ORCID
    """
    username = models.OneToOneField(User, on_delete=models.CASCADE)
    public = models.BooleanField(blank = True, default=False)
    affiliation = models.CharField(blank = True, max_length = 1000)
    orcid = models.CharField(blank = True, max_length = 1000)


class ApiInfo(models.Model):
    """API Information
    API Information is kept separate so that we can use it
    elsewhere easily.
    Set the local user.
    Servers for which the user has keys.
    The username on the server.
    max_length = 15 because hostnames are xxx.xxx.xxx.xxx
    Need to use a human-readable hostname
    Need to know where to make calls.
    "Arbitrarily" long token
    Permissions and other information.
    """

    local_username = models.ForeignKey(
        User,
        on_delete = models.CASCADE,
        related_name = 'custom_user'
    )
    username = models.CharField(blank = True, max_length = 1000)
    hostname = models.CharField(blank = True, max_length = 15)
    human_readable_hostname = models.CharField(blank = True, max_length = 1000)
    public_hostname = models.CharField(blank = True, max_length = 1000)
    token = models.CharField(blank = True, max_length = 1000)
    other_info = models.JSONField()

class Prefixes(models.Model):
    """Prefix Table: core_prefixes

    """
    username = models.CharField(max_length = 100)
    prefix = models.CharField(max_length = 5, primary_key=True, unique=True)
    registration_date = models.DateTimeField()
    registration_certificate = models.CharField(max_length = 1000)