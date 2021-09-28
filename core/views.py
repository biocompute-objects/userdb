from django.http import HttpResponseRedirect, HttpResponse
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.models import User
from .models import ApiInfo, Profile
from rest_framework import permissions, status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.views import APIView
from .serializers import ApiSerializer, UserSerializer, UserSerializerWithToken
from django.db.models.signals import post_save
from django.dispatch import receiver

# POST body parsing.
import json, pprint
pp = pprint.PrettyPrinter(indent=2)

def index(request):
    return HttpResponse("Hello, world. You're at the polls index.")

@api_view(['GET'])
def current_user(request):
    """
    Determine the current user by their token, and return their data
    """
    # Get the username 
    user = UserSerializer(request.user).data['username']
    
    print('user', user)
    serializer = UserSerializer(request.user)

    print('+++++++++++++++')
    pp.pprint(serializer.data)
    print('+++++++++++++++')

    return Response(serializer.data)

@api_view(['POST'])
def add_api(request):
    """
    Add API information 

    Update a user's information based on their token.
    
    """
    
    # Get the user.
    print('U check')
    print(UserSerializer(request.user).data)
    user = UserSerializer(request.user).data['username']

    # TODO: right way to do this?
    # Get the user ID so that we can link across tables.
    user_object = User.objects.get(username = user)

    # Get the bulk information.
    bulk = json.loads(request.body)

    # Add the key for the user.
    updated = ApiInfo(
        local_username = user_object,
        username = bulk['username'], 
        hostname = bulk['hostname'], 
        human_readable_hostname = bulk['human_readable_hostname'], 
        public_hostname = bulk['public_hostname'],
        token = bulk['token'],
        other_info = bulk['other_info']
    )
    updated.save()

    print('========')
    print(user)
    print(updated)
    print('=========')
    return(Response(UserSerializer(request.user).data, status=status.HTTP_201_CREATED))


class UserList(APIView):
    """
    Create a new user. It's called 'UserList' because normally we'd have a get
    method here too, for retrieving a list of all User objects.
    """

    permission_classes = (permissions.AllowAny,)

    def post(self, request, format=None):
        
        print('request.data: ')
        print(request.data)
        print('===============')

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
                user_object = User.objects.get(username = request.data['username'])
                Profile.objects.create(
                        username = user_object, 
                        public = profile_object['public'], 
                        affiliation = profile_object['affiliation'],
                        orcid = profile_object['orcid'])
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            
            else:
                print('serializer fail', serializer)
                # The request didn't provide what we needed.
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# (OPTIONAL) Special "one-off" view for an API writing to user
# because 1) we don't want a persisent user-writable account
# outside of the system, and 2) the API has no way of writing
# without the user's token.

# So, write to the table, then change the token.
# We could have gone with a temporary token here, but
# that may be too much too worry about.

@api_view(['POST'])
def update_user(request):
    """
    Update a user's information. Could probably be merged with add_api, or take over add_api
    """

    # Get the username 
    user = UserSerializer(request.user).data['username']

   # Get the user with associated username
    user_object = User.objects.get(username = user)

    # Get ApiInfo associated with user
    api_object = ApiInfo.objects.get(local_username = user_object)
    
    profile_object = Profile.objects.get(username = user_object)

    bulk = json.loads(request.body)

    bulk.pop('username')
    if 'token' in bulk.keys():
        token = bulk.pop('token')
    else: 
        token = ""

    for key, value in bulk.items():
        print(key, ':', value)
        if (key == 'first_name') or (key == 'last_name') or (key == 'email'):
            setattr(user_object, key,value)
        elif (key == 'orcid') or (key == 'affiliation') or (key == 'public'):
            setattr(profile_object, key, value)
        else:
            old_info = api_object.other_info
            old_info[key] = value

            setattr(api_object, 'other_info', old_info)

    user_object.save()

    api_object.save()
    
    profile_object.save()

    # properly formatted response
    return Response({
          'token': token,
          'user': UserSerializer(request.user).data
          })
