#!/usr/bin/env python
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
import logging
from functools import partial

import click
from tornado.ioloop import IOLoop
from tornado.options import options

from . import migrate


@click.group()
def cli():
    pass


@click.group()
def migrations():
    pass


@click.command()
@click.option('--migrations_path', help='Python path to migrations package, e.g. perch.migrations')
@click.option('--previous', help='The previous version of the resource to migrate')
@click.argument('resource')
def create(resource, previous=None, migrations_path=None):
    """Create an empty migration for a resource"""
    if migrations_path:
        file_path = migrate.create(resource, previous_version=previous, package=migrations_path)
    else:
        file_path = migrate.create(resource, previous_version=previous)

    click.secho('Created migration file: ' + file_path, fg='green')

@click.command()
@click.option('--port', help='The database port')
@click.option('--url', help='The database URL')
@click.option('--migrations_path', help='Python path to migrations package, e.g. perch.migrations')
def run(migrations_path=None, url=None, port=None):
    """Run migrations"""
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    if url:
        url = str(url).rstrip('/')
        options.url_registry_db = url

    if port:
        options.db_port = int(port)

    if migrations_path:
        migrations = migrate.collect(migrations_path)
    else:
        migrations = migrate.collect()

    func = partial(migrate.run_migrations, migrations)
    IOLoop.instance().run_sync(func)

migrations.add_command(create)
migrations.add_command(run)

cli.add_command(migrations)


if __name__ == '__main__':
    cli()
