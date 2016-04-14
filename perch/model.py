# -*- coding: utf-8 -*-
# Copyright 2016 Open Permissions Platform Coalition
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from __future__ import unicode_literals

from copy import deepcopy
from enum import Enum

import couch
from tornado.gen import coroutine, Return
from tornado.options import options
from voluptuous import MultipleInvalid, Schema, ALLOW_EXTRA

from . import exceptions


class State(Enum):
    approved = 'approved'
    pending = 'pending'
    rejected = 'rejected'
    default = pending

VALID_STATES = {state.value for state in State}


def format_error(invalid, doc_type):
    """
    format the error message using the voluptuous.Invalid object
    :param invalid: voluptuous.Invalid instance
    :param doc_type: type of the object, e.g. Organisation, User
    """
    # using string for checking is probably not ideal,
    # but voluptuous does not have specific sub error
    # types for these errors
    if invalid.error_message == 'extra keys not allowed':
        msg = "Key '{}' is not allowed".format(invalid.path[0])
    elif invalid.error_message == 'required key not provided':
        msg = "{} '{}' is missing".format(doc_type, invalid.path[0])
    else:
        msg = invalid.message
    return {'message': msg, 'field': str(invalid.path[0])}


class Document(object):
    internal_fields = ['type', '_id', '_rev']
    _resource = {}
    schema = Schema({
        '_id': unicode,
        '_rev': unicode
    }, extra=ALLOW_EXTRA)
    # read only fields can not be changed after the resource has been created
    read_only_fields = []

    def __init__(self, **kwargs):
        self._resource = deepcopy(kwargs)
        self._resource['type'] = self.resource_type

    def __getattr__(self, attr):
        try:
            return self._resource[attr]
        except KeyError:
            raise AttributeError(attr)

    def __setattr__(self, attr, value):
        if attr in dir(self):
            object.__setattr__(self, attr, value)
        elif attr in self._read_only and attr in self._resource:
            raise exceptions.ValidationError('{} may not be modified'
                                             .format(attr))
        else:
            self._resource[attr] = value

    def __delattr__(self, attr):
        if attr in dir(self):
            raise AttributeError('"{}" is cannot be deleted'.format(attr))
        elif attr in self._read_only and attr in self._resource:
            raise exceptions.ValidationError('{} may not be modified'
                                             .format(attr))

        try:
            del self._resource[attr]
        except KeyError:
            raise AttributeError(attr)

    @property
    def _read_only(self):
        return set(self.read_only_fields) | {'_id', '_rev', 'type'}

    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, value):
        self._id = value

    @coroutine
    def validate(self):
        """Validate the resource using it's voluptuous schema"""
        try:
            # update _resource so have default values from the schema
            self._resource = self.schema(self._resource)
        except MultipleInvalid as e:
            errors = [format_error(err, self.resource_type) for err in e.errors]
            raise exceptions.ValidationError({'errors': errors})

        yield self.check_unique()

    @coroutine
    def check_unique(self):
        """
        Override this method to check the resource is unique

        If a unique field isn't unique raise a ValidationError
        """
        pass

    @classmethod
    def db_client(cls):
        db_url = ':'.join([options.url_registry_db, str(options.db_port)])
        return couch.AsyncCouch(db_name=cls.db_name, couch_url=db_url)

    @classmethod
    @coroutine
    def get(cls, resource_id):
        """
        Get a resource

        :param resource_id: a resource's ID
        :returns: Document instance
        :raises: SocketError, CouchException
        """
        resource = yield cls.db_client().get_doc(resource_id)

        if resource.get('type') != cls.resource_type:
            raise exceptions.NotFound()

        raise Return(cls(**resource))

    @classmethod
    @coroutine
    def all(cls):
        """
        Get all resources

        :returns: list of Document instances
        :raises: SocketError, CouchException
        """
        resources = yield cls.view.get(include_docs=True)
        raise Return([cls(**resource['doc']) for resource in resources['rows']])

    @classmethod
    @coroutine
    def create(cls, user, **kwargs):
        if user:
            can_create = yield cls.can_create(user, **kwargs)
        else:
            can_create = False

        if not can_create:
            err = 'User is not authorised to create this resource'
            raise exceptions.Unauthorized(err)

        resource = cls(**kwargs)
        yield resource._save()

        raise Return(resource)

    @coroutine
    def update(self, user, **kwargs):
        if user:
            can_update, fields = yield self.can_update(user, **kwargs)
        else:
            can_update = False
            fields = []

        if not can_update:
            if fields:
                msg = "User cannot update field '{}'"
                err = [{
                    'field': x,
                    'message': msg.format(x)
                } for x in fields]
                raise exceptions.Unauthorized({'errors': err})
            else:
                err = 'User is not authorised to update this resource'
                raise exceptions.Unauthorized(err)

        read_only_fields = set(kwargs.keys()) & set(self._resource.keys()) & self._read_only
        if read_only_fields:
            msg = '{} may not be modified'
            errors = [msg.format(x) for x in read_only_fields]
            raise exceptions.ValidationError(errors)

        self._resource.update(kwargs)
        yield self._save()

    @coroutine
    def _save(self):
        """
        Save the resource

        It's better to use the create, updated & delete methods intsead of
        modifying an instance and calling save, because then we call the
        can_create, can_update & can_delete methods to check whether a user
        is permitted to make the changes.
        """
        yield self.validate()

        db = self.db_client()
        saved = yield db.save_doc(self._resource)

        # Allow couch to create Document IDs
        if '_id' not in self._resource:
            self._resource['_id'] = saved['id']

    @coroutine
    def save_subresource(self, subresource):
        """
        Save the sub-resource

        NOTE: Currently assumes subresources are stored within a dictionary,
        keyed with the subresource's ID
        """
        data = deepcopy(subresource._resource)
        data.pop('id', None)
        data.pop(self.resource_type + '_id', None)

        subresources = getattr(self, subresource.parent_key, {})
        subresources[subresource.id] = data
        setattr(self, subresource.parent_key, subresources)

        yield self._save()

    @coroutine
    def delete(self, user):
        """Delete a resource"""
        if user:
            can_delete = yield self.can_delete(user)
        else:
            can_delete = False

        if not can_delete:
            raise exceptions.Unauthorized('User may not delete the resource')

        doc = {
            '_id': self.id,
            '_deleted': True
        }

        try:
            doc['_rev'] = self._rev
        except AttributeError:
            pass

        db = self.db_client()
        yield db.save_doc(doc)

        self._resource = doc

    @coroutine
    def delete_subresource(self, subresource):
        """
        Delete the sub-resource

        NOTE: Currently assumes subresources are stored within a dictionary,
        keyed with the subresource's ID
        """
        subresources = getattr(self, subresource.parent_key, {})
        del subresources[subresource.id]
        yield self._save()

    def clean(self):
        """Remove internal fields"""
        doc = self._resource
        result = {k: v for k, v in doc.iteritems() if k not in
                  self.internal_fields}

        if '_id' in doc and 'id' not in result:
            result['id'] = doc['_id']

        return result

    @classmethod
    @coroutine
    def can_create(cls, user, **data):
        """Check if a user is authorized to create a resource"""
        raise Return(True)

    @coroutine
    def can_update(self, user, **data):
        """Check if a user is authorized to update a resource"""
        raise Return((True, set([])))

    @coroutine
    def can_read(self, user):
        """Check if a user is authorized to read a resource"""
        raise Return(True)

    @coroutine
    def can_delete(self, user):
        """Check if a user is authorized to delete a resource"""
        raise Return(True)


class SubResource(Document):
    _parent = None
    schema = Schema({'id': unicode}, extra=ALLOW_EXTRA)

    def __init__(self, parent=None, **kwargs):
        self._resource = kwargs
        if parent:
            self._parent = parent

    @property
    def _read_only(self):
        return set(self.read_only_fields) | {'id', 'type'}

    @property
    def parent_id(self):
        return getattr(self, self.parent_resource.resource_type + '_id')

    @property
    def parent(self):
        return self._parent

    @property
    def id(self):
        try:
            return self._resource['id']
        except KeyError:
            raise AttributeError('id')

    @id.setter
    def id(self, value):
        self._resource['id'] = value

    @coroutine
    def _save(self):
        """Save the sub-resource within the parent resource"""
        yield self.validate()

        try:
            self._parent = yield self.parent_resource.get(self.parent_id)
        except couch.NotFound:
            msg = '{}_id {} not found'.format(
                self.parent_resource.resource_type,
                self.parent_id)
            raise exceptions.ValidationError(msg)

        yield self._parent.save_subresource(self)

    @classmethod
    @coroutine
    def get(cls, resource_id):
        """
        Get a resource

        :param resource_id: the resource ID
        :returns: a SubResource instance
        :raises: SocketError, CouchException
        """
        resource = yield cls.view.first(key=resource_id, include_docs=True)
        parent = cls.parent_resource(**resource['doc'])

        raise Return(cls(parent=parent, **resource['value']))

    @classmethod
    @coroutine
    def all(cls):
        """
        Get all sub-resources

        :returns: list of SubResource instances
        :raises: SocketError, CouchException
        """
        resources = yield cls.view.get(include_docs=True)
        result = []

        for resource in resources['rows']:
            parent = cls.parent_resource(**resource['doc'])
            result.append(cls(parent=parent, **resource['value']))

        raise Return(result)

    @coroutine
    def delete(self, user):
        """Delete a sub-resource"""
        if user:
            can_delete = yield self.can_delete(user)
        else:
            can_delete = False

        if not can_delete:
            raise exceptions.Unauthorized('User may not delete the resource')

        try:
            self._parent = yield self.parent_resource.get(self.parent_id)
        except couch.NotFound:
            msg = '{}_id {} not found'.format(
                self.parent_resource.resource_type,
                self.parent_id)
            raise exceptions.ValidationError(msg)

        yield self._parent.delete_subresource(self)
