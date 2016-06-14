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
from collections import defaultdict

from mock import patch

import perch
from perch.migrate import migration_registry


class A(perch.Document):
    resource_type = 'A'


class B(perch.Document):
    resource_type = 'B'


class C(perch.SubResource):
    resource_type = 'C'
    parent_resource = A


class D(perch.SubResource):
    resource_type = 'D'
    parent_resource = C


def _migration_registry():
    return defaultdict(migration_registry)


def test_register_migration():
    def func(doc):
        pass

    with patch('perch.migrate._migrations', _migration_registry()) as migrations:
        m = perch.migrate.migration(A, 'v1')(func)

    expected = {
        A: {
            '': {
                'migrations': [m],
                'subresources': {}
            }
        }
    }

    assert isinstance(m, perch.migrate.Migration)
    assert m.version == 'v1'
    assert m.previous_version == ''
    assert migrations == expected


def test_register_multiple_migrations():
    with patch('perch.migrate._migrations', _migration_registry()) as migrations:
        first = perch.migrate.migration(A, 'v1')(lambda: 1)
        second = perch.migrate.migration(A, 'v2', first.version)(lambda: 1)
        third = perch.migrate.migration(A, 'v3', second.version)(lambda: 1)
        fourth = perch.migrate.migration(B, 'v1')(lambda: 1)
        fifth = perch.migrate.migration(B, 'v2', fourth.version)(lambda: 1)

    expected = {
        A: {
            '': {
                'migrations': [first],
                'subresources': {}
            },
            first.version: {
                'migrations': [second],
                'subresources': {}
            },
            second.version: {
                'migrations': [third],
                'subresources': {}
            }
        },
        B: {
            '': {
                'migrations': [fourth],
                'subresources': {}
            },
            fourth.version: {
                'migrations': [fifth],
                'subresources': {}
            }
        }
    }

    assert migrations == expected


def test_register_subresource_migration():
    with patch('perch.migrate._migrations', _migration_registry()) as migrations:
        m = perch.migrate.migration(D, 'v1')(lambda: 1)

    expected = {
        A: {
            '': {
                'migrations': [],
                'subresources': {
                    C: {
                        'migrations': [],
                        'subresources': {
                            D: {
                                'migrations': [m],
                                'subresources': {}
                            }
                        }
                    }
                }
            }
        }
    }

    assert migrations == expected


def test_register_fork():
    with patch('perch.migrate._migrations', _migration_registry()) as migrations:
        first = perch.migrate.migration(A, 'v2', 'v1')(lambda: 1)
        second = perch.migrate.migration(A, 'v3', 'v1')(lambda: 1)

    expected = {
        A: {
            'v1': {
                'migrations': [first, second],
                'subresources': {}
            }
        }
    }

    assert migrations == expected
