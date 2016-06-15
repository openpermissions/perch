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

import inspect
from collections import defaultdict
from functools import partial

from tornado.gen import coroutine, Return
from tornado.options import options
import couch

from . import exceptions


_views = defaultdict(list)


class View(object):

    def __init__(self, db_name, func):
        """
        Wraps a map function, adding a get method.
        :param: db_name: name of database
        :param: func: map function
        """
        self.db_name = db_name
        self.func = func

    @property
    def name(self):
        return self.func.func_name

    def __call__(self, doc):
        return self.func(doc)

    def register(self):
        """Register the view so that can be loaded into Couch"""
        _views[self.db_name].append(self.create_design_doc())

    def create_design_doc(self):
        """Create a design document from a Python map function"""
        source = [x for x in inspect.getsourcelines(self.func)[0]
                  if not x.startswith('@')]

        doc = {
            '_id': '_design/{}'.format(self.name),
            'language': 'python',
            'views': {
                self.name: {
                    'map': ''.join(source)
                }
            }
        }

        return doc

    @coroutine
    def get(self, **kwargs):
        """
        Queries database for results of view
        :return:
        """
        db_url = ':'.join([options.url_registry_db, str(options.db_port)])
        db = couch.AsyncCouch(db_name=self.db_name, couch_url=db_url)

        result = yield db.view(
            design_doc_name=self.name,
            view_name=self.name,
            **kwargs)

        raise Return(result)

    @coroutine
    def first(self, **kwargs):
        """
        Queries database for first result of view
        :return:
        """
        result = yield self.get(**kwargs)

        if not result['rows']:
            raise exceptions.NotFound()

        raise Return(result['rows'][0])

    @coroutine
    def values(self, **kwargs):
        """Get the view's values"""
        result = yield self.get(**kwargs)

        if not result['rows']:
            raise Return([])

        raise Return([x['value'] for x in result['rows']])


def view(db_name):
    """
    Register a map function as a view

    Currently, only a single map function can be created for each view

    NOTE: the map function source is saved in CouchDB, so it cannot depend on
    anything outside the function's scope.

    :param db_name: the database name
    """
    def decorator(func):
        v = View(db_name, func)
        v.register()
        return v
    return decorator


def load_design_docs():
    """
    Load design docs for registered views
    """
    url = ':'.join([options.url_registry_db, str(options.db_port)])
    client = partial(couch.BlockingCouch, couch_url=url)

    for name, docs in _views.items():
        db = client(db_name=name)
        views = []

        for doc in docs:
            try:
                current_doc = db.get_doc(doc['_id'])

                # use the current _rev if not provided
                if '_rev' not in doc:
                    doc['_rev'] = current_doc['_rev']
            except couch.NotFound:
                pass

            views.append(doc)

        db.save_docs(views)


@view('registry')
def resource_version(doc):
    """View for querying resources by version (used for data migrations)"""
    yield (doc.get('type'), doc.get('doc_version', '')), doc['_id']


@view('registry')
def active_users(doc):
    """View for getting users"""
    if doc.get('type') == 'user' and doc.get('state') != 'deactivated':
        yield doc.get('email'), doc['_id']


@view('registry')
def users(doc):
    """View for getting users"""
    if doc.get('type') == 'user':
        yield doc.get('email'), doc['_id']


@view('registry')
def active_user_organisations_resource(doc):
    """Get user.organisations subresouces"""
    if doc.get('type') == 'user' and doc.get('state') != 'deactivated':
        for org_id, resource in doc.get('organisations', {}).items():
            if resource['state'] != 'deactivated':
                resource['id'] = org_id
                resource['user_id'] = doc['_id']
                yield [doc['_id'], org_id], resource


@view('registry')
def user_organisations_resource(doc):
    """Get user.organisations subresouces"""
    if doc.get('type') == 'user':
        for org_id, resource in doc.get('organisations', {}).items():
            resource['id'] = org_id
            resource['user_id'] = doc['_id']
            yield [doc['_id'], org_id], resource


@view('registry')
def active_joined_organisations(doc):
    """View for getting organisations associated with a user"""
    if doc.get('type') == 'user' and doc.get('state') != 'deactivated':
        for org_id, state in doc.get('organisations', {}).items():
            if state['state'] == 'deactivated':
                continue

            org = {'_id': org_id}
            yield [doc['_id'], None], org

            try:
                yield [doc['_id'], state['state']], org
            except KeyError:
                pass


@view('registry')
def joined_organisations(doc):
    """View for getting organisations associated with a user"""
    if doc.get('type') == 'user':
        for org_id, state in doc.get('organisations', {}).items():
            org = {'_id': org_id}
            yield [doc['_id'], None], org

            try:
                yield [doc['_id'], state['state']], org
            except KeyError:
                pass


@view('registry')
def organisation_members(doc):
    """Lookup users that have joined an organisation"""
    if doc.get('type') == 'user':
        for org_id in doc.get('organisations', {}):
            yield org_id, doc['_id']


@view('registry')
def admin_emails(doc):
    """View for an orginsation's admin email addresses"""
    if doc.get('type') == 'user' and doc.get('state') != 'deactivated':
        for org_id, state in doc.get('organisations', {}).items():
            if state.get('role') == 'administrator' and state.get('state') != 'deactivated':
                yield org_id, doc['email']


@view('registry')
def active_organisations(doc):
    """View for getting active organisations"""
    if doc.get('type') == 'organisation' and doc.get('state') != 'deactivated':
        yield doc.get('state'), doc['_id']


@view('registry')
def organisations(doc):
    """View for getting organisations"""
    if doc.get('type') == 'organisation':
        yield doc.get('state'), doc['_id']


@view('registry')
def organisation_name(doc):
    """View for getting organisations by their name"""
    if doc.get('type') == 'organisation':
        yield doc.get('name'), doc['_id']


@view('registry')
def reference_links(doc):
    """Get reference links"""
    if doc.get('type') == 'organisation' and doc.get('state') != 'deactivated':
        for asset_id_type, link in doc.get('reference_links', {}).get('links', {}).items():
            value = {
                'organisation_id': doc['_id'],
                'link': link
            }
            yield asset_id_type, value


@view('registry')
def active_services(doc):
    """View for getting active services"""
    if doc.get('state') != 'deactivated':
        for service_id, service in doc.get('services', {}).items():
            if service.get('state') != 'deactivated':
                service_type = service.get('service_type')
                org = doc['_id']
                service['id'] = service_id
                service['organisation_id'] = org

                yield service_id, service
                yield [service_type, org], service
                yield [service_type, None], service
                yield [None, org], service
                yield [None, None], service


@view('registry')
def services(doc):
    """View for getting services"""
    for service_id, service in doc.get('services', {}).items():
        service_type = service.get('service_type')
        org = doc['_id']
        service['id'] = service_id
        service['organisation_id'] = org

        yield service_id, service
        yield [service_type, org], service
        yield [service_type, None], service
        yield [None, org], service
        yield [None, None], service


@view('registry')
def active_service_location(doc):
    """View for getting active service by location"""
    if doc.get('state') != 'deactivated':
        for service_id, service in doc.get('services', {}).items():
            if service.get('state') != 'deactivated':
                service['id'] = service_id
                service['organisation_id'] = doc['_id']

                location = service.get('location', None)
                if location:
                    yield location, service


@view('registry')
def service_location(doc):
    """View for getting service by location"""
    for service_id, service in doc.get('services', {}).items():
        service['id'] = service_id
        service['organisation_id'] = doc['_id']

        location = service.get('location', None)
        if location:
            yield location, service


@view('registry')
def service_name(doc):
    """View for getting service by name"""
    for service_id, service in doc.get('services', {}).items():
        service['id'] = service_id
        service['organisation_id'] = doc['_id']

        name = service.get('name', None)
        if name:
            yield name, service


@view('registry')
def oauth_secrets(doc):
    """View for OAuth secrets"""
    if doc.get('type') == 'oauth_client_credentials':
        yield doc.get('client_id'), doc['_id']


@view('registry')
def oauth_client(doc):
    """View for getting OAuth clients using the secret"""
    if doc.get('type') == 'oauth_client_credentials':
        yield [doc['_id'], doc['client_id']], doc['_id']


@view('registry')
def active_repositories(doc):
    """View for getting active repositories"""
    if doc.get('state') != 'deactivated':
        for repository_id, repo in doc.get('repositories', {}).items():
            if repo.get('state') != 'deactivated':
                repo['id'] = repository_id
                repo['organisation_id'] = doc['_id']

                yield repository_id, repo


@view('registry')
def repositories(doc):
    """View for getting repositories"""
    for repository_id, repo in doc.get('repositories', {}).items():
        repo['id'] = repository_id
        repo['organisation_id'] = doc['_id']

        yield repository_id, repo


@view('registry')
def repository_name(doc):
    """View for checking repository name is unique"""
    for repository_id, repo in doc.get('repositories', {}).items():
        repo['id'] = repository_id
        repo['organisation_id'] = doc['_id']

        name = repo.get('name', None)
        if name:
            yield name, repository_id


@view('registry')
def service_and_repository(doc):
    """
    View for looking up services and repositories by their ID

    Used in the auth service
    """
    if doc.get('type') == 'organisation' and doc.get('state') != 'deactivated':
        for repository_id, repo in doc.get('repositories', {}).items():
            if repo.get('state') != 'deactivated':
                repo['id'] = repository_id
                repo['organisation_id'] = doc['_id']

                yield repository_id, repo

        for service_id, service in doc.get('services', {}).items():
            if service.get('state') != 'deactivated':
                service['id'] = service_id
                service['organisation_id'] = doc['_id']

                yield service_id, service
