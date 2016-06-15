# -*- coding: utf-8 -*-
# Copyright 2016 Open Permissions Platform Coalition
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License. You may
# obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
# License for the specific language governing permissions and limitations under
# the License.
from __future__ import unicode_literals
from collections import defaultdict

from mock import call, patch
from tornado.testing import AsyncTestCase, gen_test

import perch
from ..util import patch_db, patch_view


class ResourceA(perch.Document):
    resource_type = 'ResourceA'


class SubResourceB(perch.SubResource):
    resource_type = 'SubResourceB'
    parent_resource = ResourceA
    parent_key = 'b'


class SubResourceC(perch.SubResource):
    resource_type = 'SubResourceC'
    parent_resource = ResourceA
    parent_key = 'c'


class ResourceD(perch.Document):
    resource_type = 'ResourceD'


class TestMigrations(AsyncTestCase):
    def setUp(self):
        self._migrations_patch = patch(
            'perch.migrate._migrations',
            defaultdict(perch.migrate.migration_registry))
        self._migrations_patch.start()
        super(TestMigrations, self).setUp()

    def tearDown(self):
        self._migrations_patch.stop()
        super(TestMigrations, self).setUp()

    @patch_view(perch.views.resource_version, [ResourceA(_id='1')._resource])
    @patch_db(ResourceA)
    @gen_test
    def test_initial_migration(self, db_client):
        func = lambda x: x
        perch.migrate.migration(ResourceA, 'v1')(func)

        yield perch.migrate.run_migrations(perch.migrate._migrations)

        expected = {
            '_id': '1',
            'type': ResourceA.resource_type,
            'doc_version': 'v1'
        }

        db_client().save_doc.assert_called_once_with(expected)

    @patch_view(perch.views.resource_version,
                [ResourceA(_id='1', doc_version='v1')._resource])
    @patch_db(ResourceA)
    @gen_test
    def test_already_migrated(self, db_client):
        func = lambda x: x
        perch.migrate.migration(ResourceA, 'v1')(func)

        yield perch.migrate.run_migrations(perch.migrate._migrations)

        assert not db_client().save_doc.called

    @patch_view(perch.views.resource_version,
                [ResourceA(_id='1', doc_version='v1')._resource])
    @patch_db(ResourceA)
    @gen_test
    def test_has_previous_migration(self, db_client):
        func = lambda x: x
        perch.migrate.migration(ResourceA, 'v1')(func)
        perch.migrate.migration(ResourceA, 'v2', previous_version='v1')(func)

        yield perch.migrate.run_migrations(perch.migrate._migrations)

        expected = {
            '_id': '1',
            'type': ResourceA.resource_type,
            'doc_version': 'v2'
        }

        db_client().save_doc.assert_called_once_with(expected)

    @patch_view(perch.views.resource_version,
                [ResourceA(_id='1', b={'b1': {}})._resource])
    @patch_db(ResourceA)
    @gen_test
    def test_migrate_subresource(self, db_client):
        def func(b):
            b.test = 1
            return b

        perch.migrate.migration(SubResourceB, 'v1')(func)

        yield perch.migrate.run_migrations(perch.migrate._migrations)

        expected = {
            '_id': '1',
            'type': ResourceA.resource_type,
            'doc_version': 'v1',
            'b': {'b1': {'test': 1}}
        }

        db_client().save_doc.assert_called_once_with(expected)

    @patch_view(perch.views.resource_version,
                [ResourceA(_id='1', b={'b1': {}, 'b2': {}})._resource,
                 ResourceA(_id='2', doc_version='v1')._resource,
                 ResourceA(_id='3', doc_version='v3', b={'b3': {}})._resource,
                 ResourceD(_id='4')._resource])
    @patch_db(ResourceD)
    @patch_db(ResourceA)
    @gen_test
    def test_multiple_resources(self, client_a, client_d):
        def func(thing):
            thing.test = getattr(thing, 'test', 0) + 1
            return thing

        perch.migrate.migration(ResourceA, 'v1')(func)
        perch.migrate.migration(SubResourceB, 'v2')(func)

        perch.migrate.migration(ResourceA, 'v3', previous_version='v1')(func)
        perch.migrate.migration(SubResourceB, 'v4', previous_version='v1')(func)

        perch.migrate.migration(ResourceD, 'v1')(func)

        yield perch.migrate.run_migrations(perch.migrate._migrations)

        expected = [
            call({
                '_id': '1',
                'type': ResourceA.resource_type,
                'doc_version': 'v3',  # sub resources are migrated first
                'test': 2,
                'b': {
                    'b1': {'test': 2},
                    'b2': {'test': 2},
                }
            }),
            call({
                '_id': '2',
                'type': ResourceA.resource_type,
                'doc_version': 'v3',
                'test': 1
            }),
        ]

        assert client_a().save_doc.call_args_list == expected
        assert client_d().save_doc.call_args_list == [
            call({
                '_id': '4',
                'type': ResourceD.resource_type,
                'doc_version': 'v1',
                'test': 1
            })
        ]
