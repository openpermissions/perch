# -*- coding: utf-8 -*-
# Copyright 2016 Open Permissions Platform Coalition
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
from __future__ import unicode_literals
from copy import deepcopy
from functools import partial

import couch
import pytest
from mock import patch
from tornado.ioloop import IOLoop
from tornado.httpclient import HTTPError

from perch import Organisation, Service, Repository, UserOrganisation, User
from ..util import make_future

USER = {
    '_id': 'user0',
    'type': 'user',
    'email': 'user0@mail.test',
    'password': User.hash_password('password0'),
    'state': 'approved',
    'role': 'user',
    'has_agreed_to_terms': True,
    'organisations': {}
}

sys_role = [
    ('administrator', True),
    ('user', False)
]

org_user_role = [
    ({
        'state': 'pending',
        'role': 'user'
    }, False),
    ({
        'state': 'approved',
        'role': 'user'
    }, False),
    ({
        'state': 'rejected',
        'role': 'user'
    }, False),
    ({
        'state': 'deactivated',
        'role': 'user'
    }, False),
]

org_admin_role = [
    ({
        'state': 'pending',
        'role': 'administrator'
    }, False),
    ({
        'state': 'approved',
        'role': 'administrator'
    }, True),
    ({
        'state': 'rejected',
        'role': 'administrator'
    }, False),
    ({
        'state': 'deactivated',
        'role': 'administrator'
    }, False)
]

class TestOrganisation():
    organisation = Organisation(id='org0')

    @pytest.mark.parametrize("role,expected", sys_role)
    def test_can_approve(self, role, expected):
        u = deepcopy(USER)
        u['role'] = role
        user = User(**u)
        func = partial(self.organisation.can_approve, user)
        result = IOLoop.instance().run_sync(func)
        assert result == expected

class TestService():

    @pytest.mark.parametrize("role,expected", sys_role)
    def test_can_approve_external(self, role, expected):
        service = Service(id='serv0', service_type="external")
        u = deepcopy(USER)
        u['role'] = role
        user = User(**u)
        func = partial(service.can_approve, user)
        result = IOLoop.instance().run_sync(func)
        # External services should always be approvable
        assert result is True

    @pytest.mark.parametrize("role,expected", sys_role)
    def test_can_approve_external_provided(self, role, expected):
        service = Service(id='serv0', service_type="repository")
        u = deepcopy(USER)
        u['role'] = role
        user = User(**u)
        func = partial(service.can_approve, user, service_type='external')
        result = IOLoop.instance().run_sync(func)
        # External services should always be approvable
        assert result is True

    @pytest.mark.parametrize("role,expected", sys_role)
    def test_can_approve_non_external(self, role, expected):
        service = Service(id='serv0', service_type="repository")
        u = deepcopy(USER)
        u['role'] = role
        user = User(**u)
        func = partial(service.can_approve, user)
        result = IOLoop.instance().run_sync(func)
        assert result == expected

    @pytest.mark.parametrize("role,expected", sys_role)
    def test_can_approve_non_external_provided(self, role, expected):
        service = Service(id='serv0', service_type="external")
        u = deepcopy(USER)
        u['role'] = role
        user = User(**u)
        func = partial(service.can_approve, user, service_type='repository')
        result = IOLoop.instance().run_sync(func)
        assert result == expected

class TestRepository():
    repo = Repository(id='repo0', organistaion_id='org1', service_id='serv0')
    service = Service(id='serv0', organisation_id='org0')

    def test_can_approve_existing_service(self):
        with patch.object(Service, 'get', return_value=make_future(self.service)) as mock_response:
            user = User(**USER)
            func = partial(self.repo.can_approve, user)
            IOLoop.instance().run_sync(func)
            mock_response.assert_called_once_with('serv0')

    def test_can_approve_service_provided(self):
        with patch.object(Service, 'get', return_value=make_future(self.service)) as mock_response:
            user = User(**USER)
            func = partial(self.repo.can_approve, user, service_id='serv1')
            IOLoop.instance().run_sync(func)
            mock_response.assert_called_once_with('serv1')

    @pytest.mark.parametrize("role,expected", sys_role)
    def test_can_approve_no_org(self, role, expected):
        with patch.object(Service, 'get', return_value=make_future(self.service)):
            u = deepcopy(USER)
            u['role'] = role
            user = User(**u)
            func = partial(self.repo.can_approve, user)
            result = IOLoop.instance().run_sync(func)
            assert result == expected

    @pytest.mark.parametrize("org_info,expected", org_user_role)
    def test_can_approve_user_joins(self, org_info, expected):
        with patch.object(Service, 'get', return_value=make_future(self.service)):
            u = deepcopy(USER)
            u['organisations']['org0'] = org_info
            user = User(**u)
            func = partial(self.repo.can_approve, user)
            result = IOLoop.instance().run_sync(func)
            assert result == expected

    @pytest.mark.parametrize("org_info,expected", org_admin_role)
    def test_can_approve_repo_admin_joins(self, org_info, expected):
        with patch.object(Service, 'get', return_value=make_future(self.service)):
            u = deepcopy(USER)
            u['organisations']['org0'] = org_info
            user = User(**u)
            func = partial(self.repo.can_approve, user)
            result = IOLoop.instance().run_sync(func)
            assert result == expected

    @pytest.mark.parametrize("org_info,expected", org_admin_role)
    def test_can_approve_srv_admin_joins(self, org_info, expected):
        with patch.object(Service, 'get', return_value=make_future(self.service)):
            u = deepcopy(USER)
            u['organisations']['org1'] = org_info
            user = User(**u)
            func = partial(self.repo.can_approve, user)
            result = IOLoop.instance().run_sync(func)
            assert result is False

    def test_can_approve_no_service(self):
        with patch.object(Service, 'get', side_effect=couch.NotFound(HTTPError(404, 'Not Found'))):
            user = User(**USER)
            func = partial(self.repo.can_approve, user)
            result = IOLoop.instance().run_sync(func)
            assert result is False


class TestUserOrganisation():
    user_org = UserOrganisation(organisation_id='org0')

    @pytest.mark.parametrize("org_info,expected", sys_role)
    def test_can_approve_no_org(self, org_info, expected):
        u = deepcopy(USER)
        u['role'] = org_info
        user = User(**u)
        func = partial(self.user_org.can_approve, user)
        result = IOLoop.instance().run_sync(func)
        assert result == expected


    @pytest.mark.parametrize("org_info,expected", org_user_role)
    def test_can_approve_user_joins(self, org_info, expected):
        u = deepcopy(USER)
        u['organisations']['org0'] = org_info
        user = User(**u)
        func = partial(self.user_org.can_approve, user)
        result = IOLoop.instance().run_sync(func)
        assert result == expected

    @pytest.mark.parametrize("org_info,expected", org_admin_role)
    def test_can_approve_admin_joins(self, org_info, expected):
        u = deepcopy(USER)
        u['organisations']['org0'] = org_info
        user = User(**u)
        func = partial(self.user_org.can_approve, user)
        result = IOLoop.instance().run_sync(func)
        assert result == expected


