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
import logging
import os
import pkgutil
from collections import defaultdict
from functools import wraps
from uuid import uuid4

from tornado.gen import coroutine

from .views import resource_version


__all__ = ['migration', 'Migration', 'collect', 'run_migrations']

MIGRATION_TEMPLATE = """
from __future__ import unicode_literals
import perch

VERSION = '{version}'
PREVIOUS_VERSION = '{previous_version}'


@perch.migrate.migration({resource_path}, VERSION, PREVIOUS_VERSION)
def migrate_{resource_type}(instance):
    # do stuff here

    return instance
"""


def migration_registry():
    return defaultdict(lambda: {
        'migrations': [],
        'subresources': migration_registry()
    })

_migrations = defaultdict(migration_registry)


class Migration(object):
    def __init__(self, func, resource, version, previous_version=''):
        self.func = func
        self.resource = resource
        self.previous_version = previous_version
        self.version = version

    def register(self):
        migrations = self._get_migrations()
        migrations['migrations'].append(self)

    def _get_migrations(self):
        if not hasattr(self.resource, 'parent_resources'):
            return _migrations[self.resource][self.previous_version]

        parents = self.resource.parent_resources()
        m = _migrations[parents[0]][self.previous_version]
        for p in parents[1:] + [self.resource]:
            m = m['subresources'][p]

        return m

    def __call__(self, instance):
        """
        Apply a migration

        :param instance: a perch.Document or perch.SubResource instance
        """
        logging.info('Migrating {} {}{} to {}'.format(
            instance.resource_type,
            instance.id,
            ' from ' + self.previous_version if self.previous_version else '',
            self.version
        ))

        return self.func(instance)

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
        @wraps(func)
        def wrapper(*args, **kwargs):
            migrated = func(*args, **kwargs)

            return migrated

        m = Migration(wrapper, resource, version, previous_version)
        m.register()

        return m

    return decorator


def create(resource_path, previous_version=None, package='perch.migrations'):
    """Create a new migration"""
    pkg, obj = resource_path.rsplit('.', 1)
    module = importlib.import_module(pkg)
    resource = getattr(module, obj)
    version = uuid4().hex
    target_module = importlib.import_module(package)
    target_dir = os.path.dirname(target_module.__file__)
    target_file = os.path.join(target_dir, resource.resource_type + '_' + version + '.py')

    with open(target_file, 'w') as f:
        f.write(MIGRATION_TEMPLATE.format(
            resource_path=resource_path,
            resource_type=resource.resource_type,
            version=version,
            previous_version=previous_version or '',
        ))

    return target_file


def collect(package='perch.migrations'):
    """
    Import all modules inside the perch.migrations package and return the
    registered migrations
    """
    package = importlib.import_module(package)

    for loader, name, is_pkg in pkgutil.walk_packages(package.__path__):
        importlib.import_module(package.__name__ + '.' + name)

    return _migrations


@coroutine
def run_migrations(migrations):
    """
    Run migrations for a resource type

    :param: a dicitionary of migrations
    """
    for resource, resource_migrations in migrations.items():
        for version in resource_migrations:
            to_migrate = yield resource_version.get(
                key=[resource.resource_type, version],
                include_docs=True)

            for x in to_migrate['rows']:
                instance = resource(**x['doc'])
                instance = _migrate_resource(
                    instance,
                    resource_migrations,
                    version
                )

                yield instance._save()


def _migrate_resource(instance, migrations, version=''):
    """
    Migrate a resource instance

    Subresources are migrated first, then the resource is recursively migrated

    :param instance: a perch.Document instance
    :param migrations: the migrations for a resource
    :param version: the current resource version to migrate
    """
    if version not in migrations:
        return instance

    instance = _migrate_subresources(
        instance,
        migrations[version]['subresources']
    )

    for migration in migrations[version]['migrations']:
        instance = migration(instance)
        instance._resource['doc_version'] = unicode(migration.version)

        instance = _migrate_resource(
            instance,
            migrations,
            version=migration.version
        )

    return instance


def _migrate_subresources(parent, migrations):
    """
    Migrate a resource's subresources

    :param parent: the parent perch.Document instance
    :param migrations: the migrations for a resource
    """
    for subresource, resource_migrations in migrations.items():
        parent = _migrate_subresource(
            subresource,
            parent,
            resource_migrations
        )

    return parent


def _migrate_subresource(subresource, parent, migrations):
    """
    Migrate a resource's subresource

    :param subresource: the perch.SubResource instance
    :param parent: the parent perch.Document instance
    :param migrations: the migrations for a resource
    """
    for key, doc in getattr(parent, subresource.parent_key, {}).items():
        for migration in migrations['migrations']:
            instance = migration(subresource(id=key, **doc))
            parent._resource['doc_version'] = unicode(migration.version)

            instance = _migrate_subresources(
                instance,
                migrations['subresources']
            )

        doc = instance._resource
        doc.pop('id', None)
        doc.pop(instance.resource_type + '_id', None)

        getattr(parent, subresource.parent_key)[key] = doc

    return parent
