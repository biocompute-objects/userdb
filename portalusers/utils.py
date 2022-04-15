#!/usr/bin/env python3
"""Utils
"""

import json
import requests
from core.serializers import UserSerializer
from core.models import ApiInfo

def update_api_info(api):
    """Update API info"""

    url = api['public_hostname']+'/api/accounts/describe/'
    token = api['token']
    header =  {'Authorization': f'Token {token}'}
    response = requests.post(url, headers=header)
    return json.loads(response.text)

def my_jwt_response_handler(token, user=None, request=None):
    """JWT

    BAD SOLUTION!!!
    Couldn't get the groups to work quite right, so a bit hacky here.
    TODO: refer to API code for a cleaner way to do this.
    """

    user_info = UserSerializer(user, context={'request': request}).data
    for api in user_info['apiinfo']:
        updated_api = update_api_info(api)
        new = ApiInfo.objects.get(token=updated_api['token'])
        new.other_info = updated_api['other_info']
        new.save()
        # print(new.other_info)

    user_info['groups'] = [list(i.items())[0][1] for i in user_info['groups']]

    return {'token': token, 'user': user_info}
