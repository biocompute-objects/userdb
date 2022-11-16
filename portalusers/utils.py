#!/usr/bin/env python3
"""Utils
"""

import json
import datetime
import requests
from rest_framework import status
from rest_framework.response import Response
from core.serializers import UserSerializer
from core.models import ApiInfo


def update_api_info(api):
    """Update API info"""

    url = api["public_hostname"] + "/api/accounts/describe/"
    token = api["token"]
    header = {"Authorization": f"Token {token}"}

    try:
        response = requests.post(url, headers=header)
    except requests.exceptions.ConnectionError:
        return Response(
            status=status.HTTP_503_SERVICE_UNAVAILABLE, data="ConnectionError"
        )

    if response.status_code == 401:
        return Response(
            status=status.HTTP_401_UNAUTHORIZED, data=json.loads(response.text)
        )
    if response.status_code is 400:
        return Response(
            status=status.HTTP_400_BAD_REQUEST, data=json.loads(response.text)
        )

    return Response(status=status.HTTP_200_OK, data=json.loads(response.text))


def my_jwt_response_handler(token, user=None, request=None):
    """JWT

    BAD SOLUTION!!!
    Couldn't get the groups to work quite right, so a bit hacky here.
    TODO: refer to API code for a cleaner way to do this.
    """

    user_info = UserSerializer(user, context={"request": request}).data
    for api in user_info["apiinfo"]:
        api_object = ApiInfo.objects.get(token=api["token"])
        api_update = update_api_info(api)
        if api_update.status_code == 200:
            api_object.other_info = api_update.data["other_info"]
            api_object.other_info[
                "last_update"
            ] = f"{datetime.datetime.utcnow().isoformat()[:-2]}Z"
        api_object.other_info["status"] = api_update.status_code
        api_object.save()

    # print(api_object.other_info)
    user_info["groups"] = [list(i.items())[0][1] for i in user_info["groups"]]

    return {"token": token, "user": user_info}
