# -*- coding: utf-8 -*-
# Copyright 2016 Open Permissions Platform Coalition
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy of
# the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import unicode_literals

import couch
import pytest
from tornado.testing import AsyncTestCase, gen_test

import perch
from perch import views
from ..util import patch_view


ORGANISATIONS = [{
    '_id': 'org1',
    'type': 'organisation',
    'created_by': 'me',
    'name': 'an organisation',
    'services': {
        'service1': {
            'name': 'a service',
            'location': 'http://my.test',
            'service_type': 'external',
            'state': perch.State.approved.name,
        },
        'service2': {
            'name': 'a service without location',
            'service_type': 'external',
            'state': perch.State.approved.name
        },
        'service3': {
            'name': 'a deactivated service',
            'service_type': 'external',
            'location': 'http://inactive.test',
            'state': perch.State.deactivated.name
        }
    }
}]


_patches = []


def setup_module():
    to_patch = [
        views.service_location,
        views.active_service_location
    ]

    for view in to_patch:
        patched = patch_view(view, ORGANISATIONS)
        patched.start()
        _patches.append(patched)


def teardown_module():
    for patched in _patches:
        patched.stop()


class TestGetByLocation(AsyncTestCase):
    @gen_test
    def test_get_by_location(self):
        service = yield perch.Service.get_by_location('http://my.test')

        assert service.id == 'service1'
        assert service.parent
        assert service.parent.id == 'org1'

    @gen_test
    def test_not_found(self):
        with pytest.raises(couch.NotFound):
            yield perch.Service.get_by_location('http://does.not.exist')

    @gen_test
    def test_without_deactivated(self):
        with pytest.raises(couch.NotFound):
            yield perch.Service.get_by_location('http://inactive.test')

    @gen_test
    def test_including_deactivated(self):
        service = yield perch.Service.get_by_location('http://inactive.test',
                                                      include_deactivated=True)

        assert service.id == 'service3'
        assert service.parent
        assert service.parent.id == 'org1'
