from django.http import HttpResponseRedirect
from django.contrib.auth.models import User
from .models import ApiInfo
from rest_framework import permissions, status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.views import APIView
from .serializers import ApiSerializer, UserSerializer, UserSerializerWithToken

# POST body parsing.
import json


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


@api_view(['POST', 'DELETE'])
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
            
            serializer = UserSerializerWithToken(data=request.data)
            
            if serializer.is_valid():
                serializer.save()
                
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            
            else:

                # The request didn't provide what we needed.
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# (OPTIONAL) Special "one-off" view for an API writing to user
# because 1) we don't want a persisent user-writable account
# outside of the system, and 2) the API has no way of writing
# without the user's token.

# So, write to the table, then change the token.
# We could have gone with a temporary token here, but
# that may be too much too worry about.
