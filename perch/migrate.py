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
import importlib
import pkgutil
from collections import defaultdict


__all__ = ['migration', 'Migration', 'collect', 'run_migrations']


def migration_registry():
    return defaultdict(lambda: {
        'migrations': defaultdict(list),
        'subresources': migration_registry()
    })

_migrations = migration_registry()


class Migration(object):
    def __init__(self, func, resource, version, previous_version=''):
        self.func = func
        self.resource = resource
        self.previous_version = previous_version
        self.version = version

    def register(self):
        migrations = self._get_migrations()
        migrations[self.previous_version].append(self)

    @classmethod
    def _get_parents(cls, resource):
        parents = []

        if hasattr(resource, 'parent_resource'):
            parents = cls._get_parents(resource.parent_resource)
            parents.append(resource.parent_resource)

        return parents

    def _get_migrations(self):
        parents = self._get_parents(self.resource)
        m = _migrations

        for p in parents:
            m = m[p]['subresources']

        return m[self.resource]['migrations']

    def __call__(self, doc):
        return self.func(doc)

    def __unicode__(self):
        return "<Migrate {} {} to {}>".format(
            self.resource.resource_type, self.previous_version, self.version)

    def __str__(self):
        return self.__unicode__()

    def __repr__(self):
        return unicode(self)


def migration(resource, version, previous_version=''):
    """Register a migration function"""
    def decorator(func):
        m = Migration(func, resource, version, previous_version)
        m.register()

        return m

    return decorator


def collect(package='perch.migrations'):
    """
    Import all modules inside the perch.migrations package and return the
    registered migrations
    """
    package = importlib.import_module(package)

    for loader, name, is_pkg in pkgutil.walk_packages(package.__path__):
        importlib.import_module(package.__name__ + '.' + name)

    return _migrations


def run_migrations(migrations):
    """
    Run migrations for a resource type

    :param: a dicitionary of migrations
    """
    pass
