# -*- coding: utf-8 -*- Copyright 2016 Open Permissions Platform Coalition
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

from perch import views


def test_service_and_repository_view():
    doc = {
        '_id': 'org1',
        'type': 'organisation',
        'services': {
            's1': {
                'name': 'service1'
            },
            's2': {
                'name': 'service2'
            },
        },
        'repositories': {
            'r1': {
                'name': 'repo1'
            },
            'r2': {
                'name': 'repo2'
            }
        }
    }

    results = sorted([x for x in views.service_and_repository(doc)])
    expected = [
        ('r1', {'id': 'r1', 'organisation_id': 'org1', 'name': 'repo1'}),
        ('r2', {'id': 'r2', 'organisation_id': 'org1', 'name': 'repo2'}),
        ('s1', {'id': 's1', 'organisation_id': 'org1', 'name': 'service1'}),
        ('s2', {'id': 's2', 'organisation_id': 'org1', 'name': 'service2'}),
    ]

    assert results == expected


def test_service_and_repository_view_type():
    results = [x for x in views.service_and_repository({'type': 'user'})]

    assert results == []
