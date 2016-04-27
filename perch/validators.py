# -*- coding: utf-8 -*-
# Copyright 2016 Open Permissions Platform Coalition
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Voluptuous validotor functions"""
import re
from urlparse import urlsplit

from voluptuous import AllInvalid, Invalid, Schema, ALLOW_EXTRA

from .model import State


class MetaSchema(object):
    """
    Schema must pass all validators. Useful for cases where a field depends on
    the value of another field

    Similar to using All with a schema and vaildator function, e.g.
    All(Schema({'x': int, 'y': int}), x_greater_than_y)

    >>> validate = MetaSchema({'x': '10'}, Coerce(int))
    >>> validate('10')
    10
    """

    def __init__(self, schema, *validators, **kwargs):
        self.validators = validators
        self.msg = kwargs.pop('msg', None)
        self._schema = Schema(schema)
        self._schemas = [Schema(val, **kwargs) for val in validators]

    @property
    def schema(self):
        return self._schema.schema

    def __call__(self, v):
        try:
            v = self._schema(v)
            for schema in self._schemas:
                v = schema(v)
        except Invalid as e:
            raise e if self.msg is None else AllInvalid(self.msg)

        return v


def partial_schema(schema, filtered_fields):
    """
    Validator for part of a schema, ignoring some fields

    :param schema: the Schema
    :param filtered_fields: fields to filter out
    """
    return Schema({
        k: v for k, v in schema.schema.items()
        if getattr(k, 'schema', k) not in filtered_fields
    }, extra=ALLOW_EXTRA)


def valid_email(email):
    """Validate email."""
    if "@" not in email:
        raise Invalid('This email is invalid.')
    return email


def validate_url(url):
    """Validate URL is valid

    NOTE: only support http & https
    """
    schemes = ['http', 'https']
    netloc_re = re.compile(
        r'^'
        r'(?:\S+(?::\S*)?@)?'  # user:pass auth
        r'(?:[a-z0-9]|[a-z0-9][a-z0-9\-]{0,61}[a-z0-9])'
        r'(?:\.(?:[a-z0-9]|[a-z0-9][a-z0-9\-]{0,61}[a-z0-9]))*'  # host
        r'(?::[0-9]{2,5})?'  # port
        r'$', re.IGNORECASE
    )

    try:
        scheme, netloc, path, query, fragment = urlsplit(url)
    except ValueError:
        raise Invalid('Invalid URL')

    if scheme not in schemes:
        raise Invalid('Missing URL scheme')

    if not netloc_re.search(netloc):
        raise Invalid('Invalid URL')

    return url


VALID_STATES = {x.name for x in State}
VALID_USER_STATES = {x.name for x in [State.approved, State.deactivated]}


def validate_state(state):
    return _validate_state(state, VALID_STATES)

def validate_user_state(state):
    return _validate_state(state, VALID_USER_STATES)

def _validate_state(state, valid_states):
    """Validate a state string"""
    if state in State:
        return state.name
    elif state in valid_states:
        return state
    else:
        raise Invalid('Invalid state')
