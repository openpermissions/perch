# -*- coding: utf-8 -*-
# Copyright 2016 Open Permissions Platform Coalition
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
from __future__ import unicode_literals

import random
import string
import uuid
from copy import deepcopy
from collections import defaultdict
from operator import itemgetter

import couch
from tornado.gen import coroutine, Return
from tornado.options import options, define
from voluptuous import (All, Any, Extra, In, Invalid, Length, MultipleInvalid,
                        Range, Required, Schema, ALLOW_EXTRA)

from . import views, exceptions, validators
from .model import format_error, Document, SubResource, State, VALID_STATES
from .validators import MetaSchema, partial_schema


__all__ = ['Organisation', 'Service', 'Repository', 'OAuthSecret']

define('min_length_organisation_name', default=3)
define('max_length_organisation_name', default=512)
define('min_length_service_name', default=3)
define('max_length_service_name', default=128)
define('min_length_repository_name', default=3)
define('max_length_repository_name', default=512)

SERVICE_TYPES = {
    'external',
    'authentication',
    'identity',
    'index',
    'onboarding',
    'query',
    'repository',
    'resolution',
    'transformation',
}
PERMISSIONS = ['-', 'r', 'w', 'rw']


class Organisation(Document):
    resource_type = 'organisation'
    db_name = 'registry'
    internal_fields = Document.internal_fields + ['services', 'repositories']
    read_only_fields = ['created_by']

    @classmethod
    def schema(cls, doc):
        name_length = Length(min=options.min_length_organisation_name,
                             max=options.max_length_organisation_name)

        filtered_fields = ['id', 'organisation_id']

        schema = Schema({
            Required('name'): All(unicode, name_length),
            Required('state', default=State.default.value): In(VALID_STATES),
            Required('created_by'): unicode,
            Required('type', default=cls.resource_type): cls.resource_type,
            Required('star_rating', default=0): Range(0, 5),
            Required('services', default={}): {
                Extra: partial_schema(Service.schema, filtered_fields)
            },
            Required('repositories', default={}): {
                Extra: partial_schema(Repository.schema, filtered_fields)
            },
            '_id': unicode,
            '_rev': unicode,
            'description': unicode,
            'address': unicode,
            'email': Any(validators.valid_email, ''),
            'phone': unicode,
            'website': unicode,
            'facebook': unicode,
            'twitter': unicode,
            'google_plus': unicode,
            'instagram': unicode,
            'youtube': unicode,
            'linkedin': unicode,
            'myspace': unicode,
            'reference_links': {Extra: validators.validate_url},
            'logo': Any(validators.validate_url, '', None),
            'modal_header_text': unicode,
            'modal_footer_text': unicode,
            'modal_link_text': unicode,
            'modal_link_url': Any(validators.validate_url, '', None)
        })

        return schema(doc)

    @classmethod
    @coroutine
    def create(cls, user, **kwargs):
        if user.is_admin():
            kwargs['state'] = State.approved.value
            organisation = yield super(Organisation, cls).create(user, **kwargs)
            # create default service
            service = yield Service.create(
                user,
                created_by=user.id,
                name=unicode(uuid.uuid4().hex),
                service_type='external',
                organisation_id=organisation.id
            )
            organisation.services[service.id] = service._resource
        else:
            # Force star rating to be 0 if the user is not an admin
            kwargs['star_rating'] = 0
            organisation = yield super(Organisation, cls).create(user, **kwargs)

        raise Return(organisation)

    @coroutine
    def check_unique(self):
        result = yield views.organisation_name.values(key=self.name)

        org_id = getattr(self, 'id', None)
        orgs = {x for x in result if x != org_id and x}

        if orgs:
            raise exceptions.ValidationError(
                "Organisation with name '{}' already exists".format(self.name))

    @classmethod
    @coroutine
    def all(cls, state=None):
        """
        Get all organisations

        :param state: State of organisation
        :returns: list of Organisation instances
        :raises: SocketError, CouchException
        """
        if state and state not in VALID_STATES:
            raise exceptions.ValidationError('Invalid "state"')
        elif state:
            organisations = yield views.organisations.get(key=state,
                                                          include_docs=True)
        else:
            organisations = yield views.organisations.get(include_docs=True)

        raise Return([cls(**org['doc']) for org in organisations['rows']])

    @classmethod
    @coroutine
    def user_organisations(cls, user_id, join_state=None):
        """
        Get organisations that the user has joined

        :param user_id: the user ID
        :param join_state: the user's "join" state
        :returns: list of Organisation instances
        :raises: SocketError, CouchException
        """
        if join_state and join_state not in VALID_STATES:
            raise exceptions.ValidationError('Invalid "state"')

        organisations = yield views.joined_organisations.get(
            key=[user_id, join_state], include_docs=True)

        raise Return([cls(**org['doc']) for org in organisations['rows']])

    @coroutine
    def can_update(self, user, **data):
        """
        Global admin's can always update an organisation.

        Organisation admin's and creators can update if the organisation is
        approved, but may not update the following fields:

            - star_rating
            - state

        :param user: a User
        :param data: data that the user wants to update
        :returns: bool, set of fields that the user was not authorized to update
        """
        if user.is_admin():
            return True, set([])

        org_admin = (self.state == State.approved.value and
                     user.is_org_admin(self.id))
        creator = self.created_by == user.id
        if org_admin or creator:
            fields = {'star_rating', 'state'} & set(data.keys())
            if fields:
                return False, fields
            else:
                return True, set([])

        return False, set([])

    @coroutine
    def can_delete(self, user):
        """Must be admin or org admin to delete"""
        raise Return(user.is_org_admin(self.id))

all_permission_schema = Schema({
    'type': 'all',
    'permission': In(PERMISSIONS),
    'value': None
}, required=True)
organisation_permission_schema = all_permission_schema.extend({
    'type': 'organisation_id',
    'permission': In(PERMISSIONS),
    'value': unicode
})
service_type_permission_schema = all_permission_schema.extend({
    'type': 'service_type',
    'permission': In(PERMISSIONS),
    'value': In(SERVICE_TYPES)
})


def group_permissions(permissions):
    """
    Groups a permissions list

    Returns a dictionary, with permission types as keys and sets of entities
    with access to the resource as values, e.g.:

        {
            'organisation_id': {
                'org1': set(['rw', 'r', 'w']),
                'org2': set(['-']),
                'org3': set(['r', 'w']),
            },
            'all': set(['r'])
        }

    'org1' has 'rw' access to the resource, 'org2' is denied access and 'org3'
    has 'r' & 'w' access (the same as 'rw'). Note that 'rw' will always result
    in 'rw', 'r' & 'w' in the set to make checks easier.

    If present in the resource's permissions, the 'all' permission type is an
    exception in that it's value is just a set instead of a dictionary.

    :param permissions: a list of permissions
    :returns: defaultdict
    """
    groups = defaultdict(lambda: defaultdict(set))

    for p in sorted(permissions, key=itemgetter('type')):
        permission_set = groups[p['type']][p.get('value')]
        permission_set.add(p['permission'])

        if p['permission'] == 'rw':
            permission_set.update({'r', 'w'})

    # the 'all' permission type always has None as the value
    groups['all'] = groups['all'][None]

    return groups

service_name_length = Length(min=options.min_length_service_name,
                             max=options.max_length_service_name)


def validate_service_schema(v):
    if v['service_type'] == 'external':
        v['state'] = State.approved.value
    else:
        if 'location' not in v:
            raise Invalid('location is required')

    return v


class Service(SubResource):
    resource_type = 'service'
    parent_resource = Organisation
    parent_key = 'services'
    read_only_fields = ['created_by']
    view = views.services

    default_permission = [{'type': 'all', 'value': None, 'permission': 'rw'}]
    schema = MetaSchema({
        Required('id', default=lambda: unicode(uuid.uuid4().hex)): unicode,
        Required('name'): All(unicode, service_name_length),
        Required('organisation_id'): unicode,
        Required('permissions', default=default_permission): [Any(
            all_permission_schema,
            organisation_permission_schema,
            service_type_permission_schema
        )],
        Required('type', default=resource_type): resource_type,
        Required('created_by'): unicode,
        Required('service_type'): In(SERVICE_TYPES),
        Required('state', default=State.pending.value): In(VALID_STATES),
        'location': validators.validate_url
    }, validate_service_schema)

    @coroutine
    def check_unique(self):
        """Check the service's name and location are unique"""
        errors = []
        service_id = getattr(self, 'id', None)
        fields = [('location', views.service_location),
                  ('name', views.service_name)]

        for field, view in fields:
            value = getattr(self, field, None)
            if not value:
                continue

            result = yield view.values(key=value)
            matched = {x['id'] for x in result if x['id'] != service_id}
            if matched:
                errors.append("Service with {} '{}' already exists"
                              .format(field, value))

        if errors:
            raise exceptions.ValidationError(errors)

    def clean(self, user=None):
        """Remove internal fields"""
        doc = self._resource
        internal_fields = deepcopy(self.internal_fields)
        if user is None or not user.is_user(self.organisation_id):
            internal_fields.append('permissions')

        result = {k: v for k, v in doc.iteritems() if k not in internal_fields}

        return result

    @classmethod
    @coroutine
    def get_by_location(cls, location):
        """Get a service by it's location"""
        result = yield views.service_location.first(key=location)
        raise Return(cls(**result['value']))

    @classmethod
    @coroutine
    def all(cls, service_type=None, organisation_id=None):
        """
        Get all resources

        :returns: list of Resource instances
        :raises: SocketError, CouchException
        """
        resources = yield cls.view.get(key=[service_type, organisation_id])
        # TODO: shouldn't this include the doc as the parent?
        raise Return([cls(**resource['value']) for resource in resources['rows']])

    @classmethod
    @coroutine
    def create(cls, user, **kwargs):
        is_external = kwargs.get('service_type') == 'external'
        is_org_admin = user.is_org_admin(kwargs.get('organisation_id'))
        if is_org_admin or is_external:
            kwargs['state'] = State.approved.value
        else:
            kwargs['state'] = State.pending.value

        resource = yield super(Service, cls).create(user, **kwargs)

        if resource.state == State.approved.value:
            yield OAuthSecret.create(user, client_id=resource.id)

        raise Return(resource)

    @classmethod
    @coroutine
    def can_create(cls, user, **kwargs):
        raise Return(user.is_user(kwargs['organisation_id']))

    @coroutine
    def update(self, user, **kwargs):
        previous_state = self.state
        yield super(Service, self).update(user, **kwargs)

        approved = self.state == State.approved.value
        was_pending = previous_state == State.pending.value
        if approved and was_pending:
            secrets = yield OAuthSecret.view.get(key=self.id)
            if not secrets['rows']:
                yield OAuthSecret.create(user, client_id=self.id)

    @coroutine
    def can_update(self, user, **kwargs):
        """Users may not update state or service_type"""
        if user.is_admin():
            raise Return((True, set([])))

        is_creator = self.created_by == user.id
        if not (user.is_org_admin(self.organisation_id) or is_creator):
            raise Return((False, set([])))

        fields = {'state', 'service_type', 'organisation_id'} & set(kwargs.keys())
        if fields:
            raise Return((False, fields))
        else:
            raise Return((True, set([])))

    @coroutine
    def can_delete(self, user):
        """Must be admin or org admin to delete"""
        raise Return(user.is_org_admin(self.organisation_id))

    @classmethod
    @coroutine
    def authenticate(cls, client_id, secret):
        """
        Authenticate a client using it's secret

        :param client_id: the client / service ID
        :param secret: the client secret
        :returns: a Service instance
        """
        result = yield views.oauth_client.get(key=[secret, client_id])
        if not result['rows']:
            raise Return()

        service = yield Service.get(client_id)
        raise Return(service)

    def authorized(self, requested_access, resource):
        """
        Check whether the service is authorized to access the resource

        :param requested_access: "r", "w", or "rw"
        :param resource: a Resource or SubResource with "permissions" attribute
        :returns: True if has access, False otherwise
        """
        if {self.state, resource.state} != {State.approved.value}:
            return False

        permissions = group_permissions(getattr(resource, 'permissions', []))

        org_permissions = permissions['organisation_id'][self.organisation_id]
        type_permissions = permissions['service_type'][self.service_type]
        all_permissions = permissions['all']

        for permission_set in [org_permissions, type_permissions, all_permissions]:
            if '-' in permission_set:
                return False
            elif set([x for x in requested_access]).issubset(permission_set):
                return True

        return False


class Repository(SubResource):
    resource_type = 'repository'
    parent_resource = Organisation
    parent_key = 'repositories'
    read_only_fields = ['created_by']
    view = views.repositories

    _repository_name_length = Length(min=options.min_length_repository_name,
                                     max=options.max_length_repository_name)

    schema = Schema({
        Required('id', default=lambda: unicode(uuid.uuid4().hex)): unicode,
        Required('name'): All(unicode, _repository_name_length),
        Required('service_id'): unicode,
        Required('organisation_id'): unicode,
        Required('state', default=State.pending.value): In(VALID_STATES),
        Required('type', default=resource_type): resource_type,
        Required('created_by'): unicode,
        Required('permissions'): [Any(
            all_permission_schema,
            organisation_permission_schema
        )],
    })

    def clean(self, user=None):
        """Remove internal fields"""
        doc = self._resource
        internal_fields = deepcopy(self.internal_fields)
        if user is None or not user.is_user(self.organisation_id):
            internal_fields.append('permissions')

        result = {k: v for k, v in doc.iteritems() if k not in internal_fields}

        return result

    @property
    def default_permissions(self):
        default_permissions = [
            {'type': 'all', 'value': None, 'permission': 'r'},
        ]

        if 'organisation_id' in self._resource:
            default_permissions.append({
                'type': 'organisation_id',
                'value': self.organisation_id,
                'permission': 'rw'
            })

        return default_permissions

    @coroutine
    def validate(self):
        """Validate the resource"""
        if not self._resource.get('permissions'):
            self.permissions = self.default_permissions

        try:
            # update _resource so have default values from the schema
            self._resource = self.schema(self._resource)
        except MultipleInvalid as e:
            errors = [format_error(err, self.resource_type) for err in e.errors]
            raise exceptions.ValidationError({'errors': errors})

        yield self.check_service()
        yield self.check_unique()

    @coroutine
    def check_service(self):
        """Check the service exists and is a repository service"""
        try:
            service = yield Service.get(self.service_id)
        except couch.NotFound:
            raise exceptions.ValidationError('Service {} not found'
                                             .format(self.service_id))

        if service.service_type != 'repository':
            raise exceptions.ValidationError('{} is not a repository service'
                                             .format(self.service_id))

        if service.state != State.approved.value:
            raise exceptions.ValidationError('{} is not an approved service'
                                             .format(self.service_id))

    @coroutine
    def check_unique(self):
        """Check the repository's name is unique"""
        result = yield views.repository_name.values(key=self.name)
        repo_id = getattr(self, 'id', None)
        repos = {x for x in result if x != repo_id and x}

        if repos:
            raise exceptions.ValidationError(
                "Repository with name '{}' already exists".format(self.name))

    @coroutine
    def update(self, user, **kwargs):
        service_id = kwargs.get('service_id')
        if service_id:
            try:
                service = yield Service.get(service_id)
                if not (service.organisation_id == self.organisation_id or
                        user.is_org_admin(service.organisation_id)):
                    kwargs['state'] = State.pending.value
            except couch.NotFound:
                pass

        yield super(Repository, self).update(user, **kwargs)

    @coroutine
    def can_update(self, user, **kwargs):
        """
        Global admin's can change anything

        If the user is an organiastion administrator or created the repository,
        they may change any field other than "state" and "organisation_id"

        If the user is a service administrator the user may change the "state"
        but no other fields. If the service is not approved then a
        repository may not be added to it.
        """
        if user.is_admin():
            raise Return((True, set([])))

        is_creator = self.created_by == user.id
        if user.is_org_admin(self.organisation_id) or is_creator:
            fields = set([])
            if 'organisation_id' in kwargs:
                fields.add('organisation_id')

            if 'state' in kwargs:
                updating_service = ('service_id' in kwargs
                                    and kwargs['state'] == State.pending.value)
                if not updating_service:
                    fields.add('state')

            if fields:
                raise Return((False, fields))
            else:
                raise Return((True, set([])))

        try:
            service = yield Service.get(self.service_id)

            if service.state != State.approved.value:
                raise Return((False, {'service_id'}))

            if user.is_org_admin(service.organisation_id):
                fields = set(kwargs) - {'state'}
                if fields:
                    raise Return((False, fields))
        except couch.NotFound:
            # will be handled in Repository.validate
            pass

        raise Return((False, set([])))

    @classmethod
    @coroutine
    def create(cls, user, **kwargs):
        service_id = kwargs.get('service_id')
        if service_id:
            try:
                service = yield Service.get(service_id)
                if user.is_org_admin(service.organisation_id):
                    kwargs['state'] = State.approved.value
            except couch.NotFound:
                # handled later
                pass

        resource = yield super(Repository, cls).create(user, **kwargs)
        raise Return(resource)

    @classmethod
    @coroutine
    def can_create(cls, user, **kwargs):
        return user.is_user(kwargs.get('organisation_id'))

    @coroutine
    def can_delete(self, user):
        """
        Approved repositories cannot be deleted

        Must be admin or org admin to delete
        """
        if self.state == State.approved.value:
            raise Return(False)

        can_delete, _ = yield self.can_update(user)
        raise Return(can_delete)

    @coroutine
    def with_relations(self, user=None):
        """
        Return a cleaned dictionary including relations

        :returns: a Repository instance
        """
        repository = self.clean(user=user)
        try:
            repository['organisation'] = self.parent.clean()
        except AttributeError:
            try:
                self._parent = yield self.parent_resource.get(self.parent_id)
                repository['organisation'] = self.parent.clean()
            except couch.NotFound:
                repository['organisation'] = {'id': self.parent_id}

        service_id = self.service_id
        organisation_services = getattr(self.parent, Service.parent_key, {})
        if service_id in organisation_services:
            repository['service'] = organisation_services[service_id]
        else:
            try:
                # TODO: cache this lookup
                service = yield Service.get(service_id)
                repository['service'] = service.clean(user=user)
            except couch.NotFound:
                # just include the service ID if cannot find the service
                repository['service'] = {'id': service_id}

        del repository['service_id']
        del repository['organisation_id']

        raise Return(repository)


def generate_secret(length=30):
    """
    Generate an ASCII secret using random.SysRandom

    Based on oauthlib's common.generate_token function
    """
    rand = random.SystemRandom()
    ascii_characters = string.ascii_letters + string.digits

    return ''.join(rand.choice(ascii_characters) for _ in range(length))


class OAuthSecret(Document):
    db_name = 'registry'
    resource_type = 'oauth_client_credentials'
    view = views.oauth_secrets

    schema = Schema({
        Required('_id', default=generate_secret): unicode,
        Required('client_id'): unicode,
        Required('type', default=resource_type): resource_type,
        '_rev': unicode
    })

    @classmethod
    @coroutine
    def can_create(cls, user, **kwargs):
        service = yield Service.get(kwargs['client_id'])
        creator = service.created_by == user.id
        can_create = user.is_org_admin(service.organisation_id) or creator
        approved = service.state == State.approved.value

        raise Return(can_create and approved)

    @coroutine
    def can_delete(self, user):
        service = yield Service.get(self.client_id)
        creator = service.created_by == user.id
        raise Return(user.is_org_admin(service.organisation_id) or creator)

    @property
    def secret(self):
        return self._id

    @classmethod
    @coroutine
    def client_secrets(cls, client_id):
        """
        Get the client's secrets using the client_id

        :param client_id: the client ID, e.g. a service ID
        :returns: list OAuthSecret instances
        """
        secrets = yield cls.view.get(key=client_id, include_docs=True)
        raise Return([cls(**secret['doc']) for secret in secrets['rows']])

    @classmethod
    @coroutine
    def delete_all_secrets(cls, user, client_id):
        """Delete all of the client's credentials"""
        can_delete = yield cls(client_id=client_id).can_delete(user)
        if not can_delete:
            raise exceptions.Unauthorized('User may not delete {} secrets'
                                          .format(client_id))

        results = yield cls.view.get(key=client_id, include_docs=True)

        if results['rows']:
            db = cls.db_client()

            docs = [{
                '_rev': doc['doc']['_rev'],
                '_id': doc['doc']['_id'],
                '_deleted': True
            } for doc in results['rows']]

            yield db.save_docs(docs)
