#!/usr/bin/env python3
"""Models

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
    """Profile

    Modle for storing additional user information
    Attributes
    ----------
    username: User
        User name for profile
    public: bool
        Bool to indicate if the user would like their Profile public
    affiliation: str
        User Affiliation
    orcid:
        User ORCID
    """
    username = models.OneToOneField(User, on_delete=models.CASCADE)
    public = models.BooleanField(blank = True, default=False)
    affiliation = models.CharField(blank = True, max_length = 1000)
    orcid = models.CharField(blank = True, max_length = 1000)

    def __str__(self):
        """String for representing the Profile model (in Admin site etc.)."""
        return str(f'{self.username}')

class ApiInfo(models.Model):
    """API Information
    API Information is kept separate so that we can use it elsewhere easily.

    Attributes
    ----------
    username : str
        Set the local user.
    hostname: str
        Servers for which the user has keys. max_length = 15 because
        hostnames are xxx.xxx.xxx.xxx
    human_readable_hostname: str
        The human readable name of the server.
    public_hostname: str
        Public address for the server. Need to know where to make calls.
    token: str
        "Arbitrarily" long token
    other_info: JSON
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

    def __str__(self):
        """String for representing the ApiInfo model (in Admin site etc.)."""
        return str(f'{self.username} at {self.hostname}')

class Prefixes(models.Model):
    """Prefix Table: core_prefixes

    Attributes
    ----------
    username: str
    prefix: str
    registration_date: datetime
    registration_certificate: str
    """

    prefix = models.CharField(max_length = 5, primary_key=True, unique=True)
    username = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        to_field="username"
    )
    registration_date = models.DateTimeField()
    registration_certificate = models.CharField(max_length = 1000)

    def __str__(self):
        """String for representing the Prefix (in Admin site etc.)."""
        return str(self.prefix)
