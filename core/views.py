#!/usr/bin/env python3
"""Views
"""

import json
import uuid
from datetime import datetime
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework import permissions, status, generics
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.response import Response
from rest_framework.views import APIView
from django.core.serializers import serialize
from django.core.exceptions import ValidationError
from django.http import HttpResponseRedirect, HttpResponse
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.models import User
from core.models import ApiInfo, Profile, Prefixes
from .serializers import ApiSerializer, UserSerializer, UserSerializerWithToken, ChangePasswordSerializer
from datetime import datetime
import uuid
from django.db.models.signals import post_save
from django.dispatch import receiver

class CreateUser(APIView):
    """Create a new user
    
    Create a new user
    """

    permission_classes = (permissions.AllowAny,)
    request_body = openapi.Schema(
        type=openapi.TYPE_OBJECT,
        title="Account Creation Schema",
        description="Account creation schema description.",
        required=['username', 'email', 'password'],
        properties={
            'username': openapi.Schema(type=openapi.TYPE_STRING,
                description='Hostname of the User Database.'),
            'email'   : openapi.Schema(type=openapi.TYPE_STRING,
                description='Email address of user.'),
            'password': openapi.Schema(type=openapi.TYPE_STRING,
                description='Token returned with new user being '),
            'profile' : openapi.Schema(
                type=openapi.TYPE_OBJECT,
                description='Token returned with new user being ', 
                required=['username'],
                properties={
                    'username': openapi.Schema(type=openapi.TYPE_STRING,
                        description='Username for the profile user object. Should be the same as above.'),
                    'public' : openapi.Schema(type=openapi.TYPE_BOOLEAN,
                        description='Boolean to indicate if this users profile is publicly viewable.'),
                    'affiliation': openapi.Schema(type=openapi.TYPE_STRING,
                        description='Affiliation of the User.'),
                    'orcid': openapi.Schema(type=openapi.TYPE_STRING,
                        description='ORCID for the User.')
                } ),
            })

    @swagger_auto_schema(request_body=request_body, responses={
            200: "Account creation is successful.",
            400: "Bad request.",
            403: "Invalid token.",
            409: "Account has already been authenticated or requested.",
            500: "Unable to save the new account or send authentication email."
            }, tags=["Account Management"])

    def post(self, request, format=None):
        """doc"""
        print('request.data: ')
        print('USERNAME: ', request.data['username'], 'EMAIL: ', request.data['email'], 'PASSWORD')

        # Does this user already exist?
        if User.objects.filter(username = request.data['username']).exists():
            # Bad request because the user already exists.
            return Response(status=status.HTTP_409_CONFLICT)

        else:
            profile_object = request.data['profile']
            del request.data['profile'] 
            serializer = UserSerializerWithToken(data=request.data)

            if serializer.is_valid():
                serializer.save()

                user_object = User.objects.get(username=request.data['username'])
                Profile.objects.create(
                        username=user_object,
                        public=profile_object['public'],
                        affiliation=profile_object['affiliation'],
                        orcid=profile_object['orcid'])
    
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ChangePasswordView(generics.UpdateAPIView):
    """
    An endpoint for changing password.
    """
    serializer_class = ChangePasswordSerializer
    model = User

    permission_classes = (permissions.IsAuthenticated,)
    request_body = openapi.Schema(
        type=openapi.TYPE_OBJECT,
        title="Password Change Schema",
        description="Endpoint for changing password.",
        required=['old_password', 'new_password'],
        properties={
            'old_password': openapi.Schema(type=openapi.TYPE_STRING,
                    description='Token returned with new user being '),
            'new_password': openapi.Schema(type=openapi.TYPE_STRING,
                    description='Token returned with new user being ')
        }
    )
    
    @swagger_auto_schema(request_body=request_body, responses={
            200: "Password updated successfully.",
            400: "Bad request.",
            401: "Invalid username/password.",
            500: "Server Error"
            }, tags=["Account Management"])

    def get_object(self, queryset=None):
        """Get Object"""
        obj = self.request.user
        return obj

    def update(self, request, *args, **kwargs):
        """update"""
        self.object = self.get_object()
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            # Check old password
            if not self.object.check_password(serializer.data.get("old_password")):
                return Response({"old_password": ["Wrong password."]}, status=status.HTTP_400_BAD_REQUEST)
            # set_password also hashes the password that the user will get
            self.object.set_password(serializer.data.get("new_password"))
            self.object.save()
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'message': 'Password updated successfully',
                'data': []
            }

            return Response(response)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@swagger_auto_schema(method="get", tags=["Account Management"])
@api_view(['GET'])
def current_user(request):
    """
    Determine the current user by their token, and return their data
    """

    print('HERE')
    serializer = UserSerializer(request.user)

    print('+++++++++++++++')
    print(serializer.data)
    print('+++++++++++++++')

    return Response(serializer.data)

@swagger_auto_schema(method="delete", tags=["API Management"])
@api_view(['DELETE'])
def remove_api(request):
    """
    Remove API information
    Remove an API interface for a user based on their token.
    """

    # Get the user.
    print('U check')
    print(UserSerializer(request.user).data)
    user = UserSerializer(request.user).data['username']

    # TODO: right way to do this?
    # Get the user ID so that we can link across tables.
    user_object = User.objects.get(username=user)

    # Get the bulk information.
    bulk = json.loads(request.body)

    for api in bulk['selected_rows']:
        # TODO: Should also check against the specific server token; needs to be sent from front end
        result = ApiInfo.objects.filter(local_username=user_object, human_readable_hostname=api).delete()
        print(result)

    return Response(UserSerializer(request.user).data, status=status.HTTP_200_OK)

@swagger_auto_schema(method="post", tags=["API Management"])
@api_view(['POST'])
def add_api(request):
    """
    Update a user's information based on their token.
    """

    # Get the user.
    user = UserSerializer(request.user).data['username']
    user_object = User.objects.get(username = user)

    # Get the bulk information.
    bulk = json.loads(request.body)

    # Add the key for the user.
    api_object = ApiInfo(
    	local_username = user_object,
        username = bulk['username'],
    	hostname = bulk['hostname'],
    	human_readable_hostname = bulk['human_readable_hostname'],
        public_hostname = bulk['public_hostname'],
    	token = bulk['token'],
        other_info = bulk['other_info']
    )

    api_object.save()
    return(Response(UserSerializer(request.user).data, status=status.HTTP_201_CREATED))

update_user_schema = openapi.Schema(
    type=openapi.TYPE_OBJECT,
    title="Update User Information",
    description="Update a user's information.",
    required=[],
    properties={
        'first_name': openapi.Schema(type=openapi.TYPE_STRING),
        'last_name': openapi.Schema(type=openapi.TYPE_STRING),
        'email': openapi.Schema(type=openapi.TYPE_STRING),
        'groups': openapi.Schema(type=openapi.TYPE_STRING),
        'password': openapi.Schema(type=openapi.TYPE_STRING),
        'username': openapi.Schema(type=openapi.TYPE_STRING),
        'affiliation': openapi.Schema(type=openapi.TYPE_STRING),
        'orcid': openapi.Schema(type=openapi.TYPE_STRING),
        'public': openapi.Schema(type=openapi.TYPE_STRING)
    }
)
@swagger_auto_schema(method="post", request_body=update_user_schema, tags=["Account Management"])
@api_view(['POST'])
def update_user(request):
    """
    Update a user's information.
    """

    # Get the username
    user = UserSerializer(request.user).data['username']

    # Get the user with associated username
    user_object = User.objects.get(username=user)
    profile_object, created = Profile.objects.get_or_create(username=user_object)
    bulk = json.loads(request.body)
    bulk.pop('username')
    if 'token' in bulk.keys():
        token = bulk.pop('token')
    else:
        token = ""

    for key, value in bulk.items():
        if (key == 'first_name') or (key == 'last_name') or (key == 'email'):
            setattr(user_object, key, value)
        elif (key == 'orcid') or (key == 'affiliation') or (key == 'public'):
            setattr(profile_object, key, value)

    user_object.save()

    profile_object.save()

    # properly formatted response
    return Response({
            'token': token,
            'user' : UserSerializer(request.user).data
            })


def search_db(value):
    """
    Arguments
    ---------
    
    value: string to look for

    Look in the database for a given value.
    Get the entire db.
    """
    if value == 'all':
        whole_db = people = serialize("json", Prefixes.objects.all())
        return whole_db
    whole_db = Prefixes.objects.filter(prefix=value)
    return len(whole_db)

def write_db(values):
    """
    Arguments
    ---------

    values: dictionary with values

    Write the values to the database.
    Call full_clean to make sure we have valid input.
    Source: https://docs.djangoproject.com/en/3.1/ref/models/instances/#validating-objects
    """

    writable = Prefixes(
        username = values['username'],
        prefix = values['prefix'],
        registration_date = values['registration_date'],
        registration_certificate = values['registration_certificate'],
    )
    try:
        writable.full_clean()
        writable.save()
    except ValidationError as error:
        return error

@swagger_auto_schema(method="get", tags=["Prefix Management"])
@api_view(['GET'])
def register_prefix(request_data, username, prefix):
    """
    Base the response on the request method.
    Is the prefix available?
    Prefix is available, so register it.
    """

    if(request_data.method == 'GET'):
        if search_db(prefix) == 0:
            if write_db({
                'username': username,
                'prefix': prefix,
                'registration_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'registration_certificate': uuid.uuid4().hex
            }) is not None:
                return HttpResponse(content='The prefix provided does not match the format required.  Please adjust the prefix and re-submit.', status=400)
            else:
                return HttpResponse(content='Prefix \'' + prefix + '\' successfully registered for e-mail \'' + username + '\'.  Check your e-mail for a registration receipt.', status=201)

        else:
            return HttpResponse(content='Prefix \'' + prefix + '\' was not available.', status=409)

@swagger_auto_schema(method="get", tags=["Prefix Management"])
@api_view(['GET'])
@authentication_classes([])
@permission_classes([])
def view_prefixes(request_data):
    """View Prefixes
    No authentication required to view the list
    """
    prefix_list = search_db(value='all')
    print(prefix_list)
    return HttpResponse(content=prefix_list, status=200)
