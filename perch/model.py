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
from operator import attrgetter

import couch
from tornado.gen import coroutine, Return
from tornado.options import options
from voluptuous import MultipleInvalid, Schema, ALLOW_EXTRA, Required, Undefined

from . import exceptions


__all__ = ['State', 'Document', 'SubResource']


class State(Enum):
    """
    Resource states, the enum values represent the priority of the state.

    For example, rejected has higher priority than approved
    """
    approved = 0
    pending = 1
    rejected = 2
    deactivated = 3


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
    resource_type = None
    schema = Schema({
        '_id': unicode,
        '_rev': unicode
    }, extra=ALLOW_EXTRA)
    # read only fields can not be changed after the resource has been created
    read_only_fields = []

    default_state = State.pending
    editable_states = [State.approved, State.pending]

    # State transitions that can be performed by users with permission to update resource
    state_transitions = {
        None: [State.pending.name],
        State.pending.name: [State.deactivated.name],
        State.approved.name: [State.deactivated.name],
        State.rejected.name: [State.deactivated.name],
        State.deactivated.name: [State.pending.name]
    }

    # State transitions that can be performed by users with permission to approve resource
    # These are in addition to regular state_transitions
    approval_state_transitions = {
        None: [State.approved.name],
        State.pending.name: [State.approved.name, State.rejected.name],
        State.deactivated.name: [State.approved.name],
    }

    def __init__(self, **kwargs):
        self._resource = deepcopy(kwargs)
        self._resource['type'] = self.resource_type

    def __getattr__(self, attr):
        try:
            if attr in self._resource:
                return self._resource[attr]
            else:
                defaults = self.get_required_fields_with_defaults()
                return defaults[attr]
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

    @property
    def editable(self):
        return self.state in self.editable_states

    @coroutine
    def validate(self):
        """Validate the resource using its voluptuous schema"""
        try:
            # update _resource to have default values from the schema
            self._resource = self.schema(self._resource)
        except MultipleInvalid as e:
            errors = [format_error(err, self.resource_type) for err in e.errors]
            raise exceptions.ValidationError({'errors': errors})

        yield self.check_unique()

    def get_required_fields_with_defaults(self):
        defaults = {}
        required_keys = set(
            key for key in self.schema.schema if isinstance(key, Required))
        for key in required_keys:
            if not isinstance(key.default, Undefined):
                defaults[unicode(key)] = key.default()
        return defaults

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
    def get(cls, resource_id, include_deactivated=False):
        """
        Get a resource

        :param resource_id: a resource's ID
        :param include_deactivated: Include deactivated resources in response

        :returns: Document instance
        :raises: SocketError, CouchException
        """
        resource = yield cls.db_client().get_doc(resource_id)

        if resource.get('type') != cls.resource_type:
            raise exceptions.NotFound()

        if not include_deactivated and resource.get('state') == State.deactivated.name:
            raise exceptions.NotFound()

        raise Return(cls(**resource))

    @classmethod
    @coroutine
    def all(cls, include_deactivated=False):
        """
        Get all resources
        :param include_deactivated: Include deactivated resources in response

        :returns: list of Document instances
        :raises: SocketError, CouchException
        """
        if include_deactivated:
            resources = yield cls.view.get(include_docs=True)
        else:
            resources = yield cls.active_view.get(include_docs=True)
        raise Return([cls(**resource['doc']) for resource in resources['rows']])

    @classmethod
    @coroutine
    def create(cls, user, **kwargs):
        resource = cls(**kwargs)

        if user:
            can_create = yield cls.can_create(user, **kwargs)
            can_approve = yield resource.can_approve(user, **kwargs)
        else:
            can_create = False
            can_approve = False

        if not can_create:
            err = 'User is not authorised to create this resource'
            raise exceptions.Unauthorized(err)

        # If user can approve resource and has not specified a state, approve on creation
        if 'state' not in kwargs and can_approve:
            resource._resource.update({'state': State.approved.name})

        can_set_state = yield resource.validate_state_transition(user, None, resource._resource.get('state'), **kwargs)
        if not can_set_state:
            err = [{
                'field': 'state',
                'message': 'Cannot set initial state as {}'.format(resource._resource.get('state'))
            }]
            raise exceptions.Unauthorized({'errors': err})

        yield resource._save()

        raise Return(resource)

    @coroutine
    def validate_state_transition(self, user, start_state, end_state, **kwargs):
        """
        Validate whether user can transition resource from start state to end state
        :param user
        :param start_state
        :param end_state
        :return: bool
        """
        if start_state == end_state:
            raise Return(True)

        transitions = self.state_transitions.get(start_state, [])

        approved_transitions = []
        can_approve = yield self.can_approve(user, **kwargs)
        if can_approve:
            approved_transitions = self.approval_state_transitions.get(start_state, [])

        if end_state not in transitions and end_state not in approved_transitions:
            raise Return(False)

        raise Return(True)

    @coroutine
    def update(self, user, **kwargs):
        if user:
            can_update, fields = yield self.can_update(user, **kwargs)
        else:
            can_update = False
            fields = []

        new_state = getattr(State, kwargs.get('state', ''), self.state)
        can_edit = {self.state, new_state}.intersection(set(self.editable_states))
        if not can_edit:
            err = 'User is not authorised to update resource with state {}'.format(new_state.name)
            raise exceptions.Unauthorized(err)

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

        fields_to_update = set(kwargs.keys()) & set(self._resource.keys())

        state_field_update = fields_to_update & {'state'}

        if state_field_update:
            can_transition = yield self.validate_state_transition(user, self._resource.get('state'),
                                                                  kwargs['state'], **kwargs)
            if not can_transition:
                err = [{
                    'field': 'state',
                    'message': ('Cannot transition from {} state to {} state'
                                .format(self.state.name, kwargs['state']))
                }]
                raise exceptions.Unauthorized({'errors': err})

        read_only_fields = fields_to_update & self._read_only
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
    def can_approve(self, user, **data):
        """Check if a user is authorized to approve a resource"""
        raise Return(False)

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
        raise Return(False)

    @property
    def state(self):
        """Get the Document's state"""
        state = self._resource.get('state', self.default_state)

        if state in State:
            return state
        else:
            return getattr(State, state)

    @state.setter
    def state(self, value):
        self._resource['state'] = value

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

    @coroutine
    def get_parent(self):
        """
        Get the parent resource from the database

        The get, create & update methods will populate the parent for you. Use
        this method in the cases where parent has not been populated.
        """
        if not self._parent:
            self._parent = yield self.parent_resource.get(self.parent_id)

        raise Return(self._parent)

    @property
    def id(self):
        try:
            return self._resource['id']
        except KeyError:
            raise AttributeError('id')

    @id.setter
    def id(self, value):
        self._resource['id'] = value

    @classmethod
    @coroutine
    def create(cls, user, **kwargs):
        """If parent resource is not an editable state, should not be able to create."""
        parent_id = kwargs.get(cls.parent_resource.resource_type + '_id')
        try:
            parent = yield cls.parent_resource.get(parent_id)
        except couch.NotFound:
            msg = 'Parent {} with id {} not found'.format(
                cls.parent_resource.resource_type,
                parent_id)
            raise exceptions.ValidationError(msg)

        if not parent.editable:
            err = 'Cannot create child of {} resource'.format(parent.state.name)
            raise exceptions.Unauthorized(err)

        resource = yield super(SubResource, cls).create(user, **kwargs)
        resource._parent = parent

        raise Return(resource)

    @coroutine
    def update(self, user, **kwargs):
        """If parent resource is not an editable state, should not be able to update"""
        yield self.get_parent()

        if not self.parent.editable:
            err = 'Cannot update child of {} resource'.format(self.parent.state.name)
            raise exceptions.Unauthorized(err)

        yield super(SubResource, self).update(user, **kwargs)

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
    def get(cls, resource_id, include_deactivated=False):
        """
        Get a resource

        :param resource_id: the resource ID
        :param include_deactivated: Include deactivated resources in response
        :returns: a SubResource instance
        :raises: SocketError, CouchException
        """
        if include_deactivated:
            resource = yield cls.view.first(key=resource_id, include_docs=True)
        else:
            resource = yield cls.active_view.first(key=resource_id, include_docs=True)
        parent = cls.parent_resource(**resource['doc'])

        raise Return(cls(parent=parent, **resource['value']))

    @classmethod
    @coroutine
    def all(cls, include_deactivated=False):
        """
        Get all sub-resources
        :param include_deactivated: Include deactivated resources in response

        :returns: list of SubResource instances
        :raises: SocketError, CouchException
        """
        if include_deactivated:
            resources = yield cls.view.get(include_docs=True)
        else:
            resources = yield cls.active_view.get(include_docs=True)

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
            parent = yield self.get_parent()
        except couch.NotFound:
            msg = '{}_id {} not found'.format(
                self.parent_resource.resource_type,
                self.parent_id)
            raise exceptions.ValidationError(msg)

        yield parent.delete_subresource(self)

    @property
    def state(self):
        """
        Get the SubResource state

        If the parents state has a higher priority, then it overrides the
        SubResource state

        ..note:: This assumes that self.parent is populated
        """
        state = self._resource.get('state', self.default_state)
        if state not in State:
            state = getattr(State, state)

        if not self.parent:
            raise Exception('Unable to check the parent state')

        parent_state = self.parent.state

        return max([state, parent_state], key=attrgetter('value'))
