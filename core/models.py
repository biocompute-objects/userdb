# Customer user model.
# Source: https://docs.djangoproject.com/en/3.1/topics/auth/customizing/#extending-the-existing-user-model
# Source: https://docs.djangoproject.com/en/3.1/topics/db/models/#many-to-one-relationships

from django.db import models
from django.contrib.auth.models import User
from django.dispatch import receiver
from django.urls import reverse
from django_rest_passwordreset.signals import reset_password_token_created
from django.core.mail import send_mail
from rest_framework import status
from rest_framework.response import Response

@receiver(reset_password_token_created)
def password_reset_token_created(sender, instance, reset_password_token, *args, **kwargs):
    """
    Create the token for a password reset.
    """
    email_plaintext_message = "{}?token={}".format(reverse('password_reset:reset-password-request'), reset_password_token.key)

    try:
        send_mail(
            subject='Password reset for BioCompute Portal',
            message= email_plaintext_message,
            html_message=email_plaintext_message,
            from_email='mail_sender@portal.aws.biochemistry.gwu.edu',
            recipient_list=[reset_password_token.user.email],
            fail_silently=False,
        )
        
    except Exception as e:
        print('activation_link', reset_password_token)
        # print('ERROR: ', e)
        # TODO: Should handle when the send_mail function fails?
        # return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR, data={"message": "Not able to send authentication email: {}".format(e)})
        return Response(status=status.HTTP_201_CREATED, data={"message": "Account has been requested. Activation email was not sent. Check with your database administrator for activation of your api account"})

class Profile(models.Model):
    """
    Modle for storing additional user information
    """
    username = models.OneToOneField(User, on_delete=models.CASCADE)
    # Public Profile
    public = models.BooleanField(blank = True, default=False)
    # User Affiliation
    affiliation = models.CharField(blank = True, max_length = 1000)
    # User ORCID    
    orcid = models.CharField(blank = True, max_length = 1000)

# API Information is kept separate so that we can use it
# elsewhere easily.


# API Information
class ApiInfo(models.Model):

    # Set the local user.
    local_username = models.ForeignKey(User, on_delete = models.CASCADE, related_name = 'custom_user')
    
    # Servers for which the user has keys.

    # The username on the server.
    username = models.CharField(blank = True, max_length = 1000)

    # max_length = 15 because hostnames are xxx.xxx.xxx.xxx
    hostname = models.CharField(blank = True, max_length = 15)

    # Need to use a human-readable name
    human_readable_hostname = models.CharField(blank = True, max_length = 1000)
    
    # Need to know where to make calls.
    public_hostname = models.CharField(blank = True, max_length = 1000)

    # "Arbitrarily" long token
    token = models.CharField(blank = True, max_length = 1000)

    # Permissions and other information.
    other_info = models.JSONField()
