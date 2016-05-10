# -*- coding: utf-8 -*-
# Copyright 2016 Open Permissions Platform Coalition
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from __future__ import unicode_literals

import pytest
from mock import patch
from tornado.testing import AsyncTestCase, gen_test

from perch import User, Organisation, Service
from voluptuous import MultipleInvalid
from .util import make_future


TEST_REFERENCE_LINKS = {
    'valid': {
        'links': {'id1': 'https://id1.com', 'id2': 'https://id2.com'},
        'redirect_id_type': 'id1'
    },
    'valid2': {
        'links': {'id1': 'https://id1.com', 'id2': 'https://id2.com'},
        'redirect_id_type': 'id2'
    },
    'missing_id_type_in_links': {
        'links': {'id1': 'https://id1.com', 'id2': 'https://id2.com'},
        'redirect_id_type': 'id3'
    },
    'invalid_url': {
        'links': {'id1': 'notavalidurl', 'id2': 'https://id2.com'}
    },
    'missing_links': {
        'redirect_id_type': 'id1'
    },
    'extra_keys': {
        'links': {},
        'extra1': 'test1'
    }
}


def validate_schema(obj):
    return obj.schema(obj._resource)


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


class CheckOrganisationLinks(AsyncTestCase):
    @gen_test
    def test_create_org_with_empty_reference_links(self):
        reference_links = {}
        user = User()
        with patch.object(Organisation, '_save', return_value=make_future(None)):
            org = yield Organisation.create(user,
                                            name='testorg',
                                            created_by='testuser',
                                            reference_links=reference_links)
            validate_schema(org)
            assert org.reference_links == {}

    @gen_test
    def test_create_org_with_reference_links_empty_links(self):
        reference_links = {'links': {}}
        user = User()
        with patch.object(Organisation, '_save', return_value=make_future(None)):
            org = yield Organisation.create(user,
                                            name='testorg',
                                            created_by='testuser',
                                            reference_links=reference_links)
            validate_schema(org)
            assert org.reference_links == {'links': {}}

    @gen_test
    def test_create_org_with_redirect_id_type(self):
        reference_links = TEST_REFERENCE_LINKS['valid']
        user = User()
        with patch.object(Organisation, '_save', return_value=make_future(None)):
            org = yield Organisation.create(user,
                                            name='testorg',
                                            created_by='testuser',
                                            reference_links=reference_links)
            validate_schema(org)
            assert org.reference_links['redirect_id_type'] == 'id1'
            assert org.reference_links['links']['id1'] == 'https://id1.com'
            assert org.reference_links['links']['id2'] == 'https://id2.com'

    @gen_test
    def test_create_org_with_non_existent_redirect_id_type(self):
        user = User()
        reference_links = TEST_REFERENCE_LINKS['missing_links']
        with patch.object(Organisation, '_save', return_value=make_future(None)):
            with pytest.raises(MultipleInvalid) as exc:
                org = yield Organisation.create(user,
                                                name='testorg',
                                                created_by='testuser',
                                                reference_links=reference_links)
                validate_schema(org)
            msg = 'Redirect ID type must point to one of the links\' ID types'
            assert exc.value.error_message == msg

    @gen_test
    def test_create_org_with_reference_links_with_extra_keys(self):
        user = User()
        reference_links = TEST_REFERENCE_LINKS['extra_keys']
        with patch.object(Organisation, '_save', return_value=make_future(None)):
            with pytest.raises(MultipleInvalid) as exc:
                org = yield Organisation.create(user,
                                                name='testorg',
                                                created_by='testuser',
                                                reference_links=reference_links)
                validate_schema(org)
            assert exc.value.error_message == 'Key extra1 is not allowed'

    @gen_test
    def test_create_org_with_invalid_reference_url(self):
        user = User()
        reference_links = TEST_REFERENCE_LINKS['invalid_url']
        with patch.object(Organisation, '_save', return_value=make_future(None)):
            with pytest.raises(MultipleInvalid) as exc:
                org = yield Organisation.create(user,
                                                name='testorg',
                                                created_by='testuser',
                                                reference_links=reference_links)
                validate_schema(org)
            assert exc.value.error_message == 'Missing URL scheme'

    @gen_test
    def test_update_redirect_id_type(self):
        orgs = {'testorgid': {'state': 'approved', 'role': 'administrator'}}
        user = User(password='testpass', id='testuserid', organisations=orgs)
        reference_links = TEST_REFERENCE_LINKS['valid']
        updated_reference_links = TEST_REFERENCE_LINKS['valid2']
        with patch.object(Organisation, '_save', return_value=make_future(None)):
            org = yield Organisation.create(user,
                                            _id='testorgid',
                                            name='testorg',
                                            created_by='testuser',
                                            reference_links=reference_links)
            validate_schema(org)
            yield org.update(user, reference_links=updated_reference_links)
            validate_schema(org)

    @gen_test
    def test_update_non_existent_redirect_id_type(self):
        orgs = {'testorgid': {'state': 'approved', 'role': 'administrator'}}
        user = User(password='testpass', id='testuserid', organisations=orgs)
        reference_links = TEST_REFERENCE_LINKS['valid']
        updated_reference_links = TEST_REFERENCE_LINKS['missing_id_type_in_links']
        with patch.object(Organisation, '_save', return_value=make_future(None)):
            org = yield Organisation.create(user,
                                            _id='testorgid',
                                            name='testorg',
                                            created_by='testuser',
                                            reference_links=reference_links)
            validate_schema(org)

            with pytest.raises(MultipleInvalid) as exc:
                yield org.update(user, reference_links=updated_reference_links)
                validate_schema(org)
            msg = 'Redirect ID type must point to one of the links\' ID types'
            assert exc.value.error_message == msg

    @gen_test
    def test_update_reference_links_with_extra_keys(self):
        orgs = {'testorgid': {'state': 'approved', 'role': 'administrator'}}
        user = User(password='testpass', id='testuserid', organisations=orgs)
        reference_links = TEST_REFERENCE_LINKS['valid']
        updated_reference_links = TEST_REFERENCE_LINKS['extra_keys']
        with patch.object(Organisation, '_save', return_value=make_future(None)):
            org = yield Organisation.create(user,
                                            _id='testorgid',
                                            name='testorg',
                                            created_by='testuser',
                                            reference_links=reference_links)
            validate_schema(org)

            with pytest.raises(MultipleInvalid) as exc:
                yield org.update(user, reference_links=updated_reference_links)
                validate_schema(org)
            assert exc.value.error_message == 'Key extra1 is not allowed'
