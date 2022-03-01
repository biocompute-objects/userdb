import json
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework import permissions, status, generics
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.views import APIView
from django.http import HttpResponseRedirect, HttpResponse
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.models import User
from .models import ApiInfo, Profile
from .serializers import ApiSerializer, UserSerializer, UserSerializerWithToken, ChangePasswordSerializer

from django.db.models.signals import post_save
from django.dispatch import receiver

class CreateUser(APIView):
    """
    Create a new user
    
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
            
            else:

                # The request didn't provide what we needed.
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
        obj = self.request.user
        return obj

    def update(self, request, *args, **kwargs):
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
    import pdb; pdb.set_trace()
    for api in bulk['selected_rows']:
        '''
        {'_state': <django.db.models.base.ModelState object at 0x1028e1340>, 'id': 2,
        'local_username_id': 4, 'username': 'Test53', 'hostname': 'beta.portal.aws.biochemistry.gwu.edu',
        'human_readable_hostname': 'BCO Server (Default)', 'public_hostname': 'http://127.0.0.1:8000',
        'token': '27ab0a38ff99decb885e7e1b525abdbfd641da18',
        'other_info': {'permissions': {'user': {}, 'groups': {'bco_drafter': {}, 'bco_publisher': {'bco': ['add_BCO', 'change_BCO', 'delete_BCO', 'draft_BCO', 'publish_BCO', 'view_BCO']}, 'Test53': {}}}, 'account_creation': '2021-10-28 02:09:13.061908+00:00', 'account_expiration': ''}}
        '''
        # TODO: Should also check against the specific server token; needs to be sent from front end
        result = ApiInfo.objects.filter(local_username=user_object, human_readable_hostname=api).delete()
        print(result)

    print('========')
    print(user)
    print('=========')
    return (Response(UserSerializer(request.user).data, status=status.HTTP_200_OK))

@swagger_auto_schema(method="post", tags=["API Management"])
@api_view(['POST'])
def add_api(request):
    """
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

    print('========')
    print(user)
    print(api_object)
    print('=========')
    return(Response(UserSerializer(request.user).data, status=status.HTTP_201_CREATED))


@swagger_auto_schema(method="post", tags=["Account Management"])
@api_view(['POST'])
def update_user(request):
    """
    Update a user's information. Could probably be merged with add_api, or take over add_api
    """

    # Get the username
    user = UserSerializer(request.user).data['username']

    # Get the user with associated username
    user_object = User.objects.get(username=user)

    try:
        profile_object = Profile.objects.get(username=user_object)
    except:
        profile_object = Profile.objects.create(username=user_object)

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


# (OPTIONAL) Special "one-off" view for an API writing to user
# because 1) we don't want a persisent user-writable account
# outside of the system, and 2) the API has no way of writing
# without the user's token.

# So, write to the table, then change the token.
# We could have gone with a temporary token here, but
# that may be too much too worry about.