# -*- coding: utf-8 -*-
# Copyright 2019 The Matrix.org Foundation C.I.C.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import re
import logging

from twisted.internet import defer

from synapse.api.errors import SynapseError
from synapse.http.servlet import (
    RestServlet,
    assert_params_in_dict,
    parse_integer,
    parse_json_object_from_request,
)
from synapse.rest.admin import (
    assert_requester_is_admin,
    assert_user_is_admin,
    historical_admin_path_patterns,
)
from synapse.types import UserID

logger = logging.getLogger(__name__)


class UsersRestServlet(RestServlet):
    PATTERNS = historical_admin_path_patterns("/users$")

    """Get request to list all local users.
    This needs user to have administrator access in Synapse.

    GET /_synapse/admin/v1/users?access_token=admin_access_token&start=0&limit=10

    returns:
        200 OK with list of users if success otherwise an error.

    The parameters `start` and `limit` are optional if you want to use pagination.
    """

    def __init__(self, hs):
        self.hs = hs
        self.auth = hs.get_auth()
        self.handlers = hs.get_handlers()

    @defer.inlineCallbacks
    def on_GET(self, request):
        yield assert_requester_is_admin(self.auth, request)

        order = "name"  # order by name in user table
        start = parse_integer(request, "start")
        limit = parse_integer(request, "limit")

        ret = None
        if (start != None and limit != None):
            logger.info("limit: %s, start: %s", limit, start)
            ret = yield self.handlers.admin_handler.get_users_paginate(order, start, limit)
        else:
            ret = yield self.handlers.admin_handler.get_users()
        return (200, ret)


class UserAdminServlet(RestServlet):
    """
    Get or set whether or not a user is a server administrator.

    Note that only local users can be server administrators, and that an
    administrator may not demote themselves.

    Only server administrators can use this API.

    Examples:
        * Get
            GET /_synapse/admin/v1/users/@nonadmin:example.com/admin
            response on success:
                {
                    "admin": false
                }
        * Set
            PUT /_synapse/admin/v1/users/@reivilibre:librepush.net/admin
            request body:
                {
                    "admin": true
                }
            response on success:
                {}
    """

    PATTERNS = (re.compile("^/_synapse/admin/v1/users/(?P<user_id>@[^/]*)/admin$"),)

    def __init__(self, hs):
        self.hs = hs
        self.auth = hs.get_auth()
        self.handlers = hs.get_handlers()

    @defer.inlineCallbacks
    def on_GET(self, request, user_id):
        yield assert_requester_is_admin(self.auth, request)

        target_user = UserID.from_string(user_id)

        if not self.hs.is_mine(target_user):
            raise SynapseError(400, "Only local users can be admins of this homeserver")

        is_admin = yield self.handlers.admin_handler.get_user_server_admin(target_user)
        is_admin = bool(is_admin)

        return (200, {"admin": is_admin})

    @defer.inlineCallbacks
    def on_PUT(self, request, user_id):
        requester = yield self.auth.get_user_by_req(request)
        yield assert_user_is_admin(self.auth, requester.user)
        auth_user = requester.user

        target_user = UserID.from_string(user_id)

        body = parse_json_object_from_request(request)

        assert_params_in_dict(body, ["admin"])

        if not self.hs.is_mine(target_user):
            raise SynapseError(400, "Only local users can be admins of this homeserver")

        set_admin_to = bool(body["admin"])

        if target_user == auth_user and not set_admin_to:
            raise SynapseError(400, "You may not demote yourself.")

        yield self.handlers.admin_handler.set_user_server_admin(
            target_user, set_admin_to
        )

        return (200, {})
