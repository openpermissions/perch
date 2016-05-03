# -*- coding: utf-8 -*-
# Copyright 2016 Open Permissions Platform Coalition
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from __future__ import unicode_literals

from mock import patch
from tornado.testing import AsyncTestCase, gen_test

from perch import User, Organisation, Service
from .util import make_future


class CreateOrganisation(AsyncTestCase):
    @gen_test
    def test_create_organisation(self):
        user = User()
        with patch.object(Organisation, '_save', return_value=make_future(None)):
            org = yield Organisation.create(user,
                                            name='testorg',
                                            created_by='testuser')
            assert org.name == 'testorg'
            assert org.created_by == 'testuser'

    @gen_test
    def test_create_organisation_as_admin(self):
        orgs = {'global': {'state': 'approved', 'role': 'administrator'}}
        user = User(password='password', organisations=orgs, id='uid')
        with patch.object(Organisation, '_save', return_value=make_future(None)):
            with patch.object(Service, 'create', return_value=make_future(Service())):
                org = yield Organisation.create(user,
                                                name='testorg',
                                                created_by='testuser',
                                                id='testorgid')
                assert org.name == 'testorg'
                assert org.created_by == 'testuser'
                assert org.state.name == 'approved'


class CheckOrganisationDefaults(AsyncTestCase):
    @gen_test
    def test_get_organisation_defaults(self):
        user = User(password='password', id='uid')
        with patch.object(Organisation, '_save', return_value=make_future(None)):
            org = yield Organisation.create(user,
                                            name='testorg',
                                            created_by='testuser')
            assert org.repositories == {}
            assert org.services == {}
            assert org.state.name == 'pending'
            assert org.type == 'organisation'
            assert org.star_rating == 0


    @gen_test
    def test_get_required_fields_with_defaults(self):
        test_org = Organisation(name='testorg', created_by='test')
        expected_org_defaults = {
            'services': {},
            'type': 'organisation',
            'state': 'pending',
            'star_rating': 0,
            'repositories': {}
        }
        returned_defaults = test_org.get_required_fields_with_defaults()
        assert expected_org_defaults == returned_defaults
