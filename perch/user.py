# -*- coding: utf-8 -*-
# Copyright 2016 Open Permissions Platform Coalition
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
from __future__ import unicode_literals

import uuid
from datetime import datetime, timedelta
from enum import Enum

import couch
from dateutil import parser
from passlib.hash import pbkdf2_sha256
from tornado.gen import coroutine, Return
from tornado.options import options, define
from voluptuous import All, Extra, In, Length, Required, Schema

from . import views, exceptions, validators
from .model import Document, SubResource, State, VALID_STATES
from .organisation import Organisation


__all__ = ['User', 'UserOrganisation', 'Token']

GLOBAL = 'global'

define('min_length_password', default=3)
define('max_length_password', default=128)
define('token_ttl', default=86400)


class User(Document):
    resource_type = 'user'
    view = views.users
    db_name = 'registry'
    internal_fields = (Document.internal_fields +
                       ['password', 'verification_hash'])
    read_only_fields = ['created_by']

    class roles(Enum):
        administrator = 'administrator'
        user = 'user'
        default = user

    @classmethod
    def schema(cls, doc):
        default_global = {
            GLOBAL: {
                'join_state': State.approved.value,
                'role': cls.roles.default.value
            }
        }
        orgs_schema = Schema({
            Extra: {
                'join_state': In(VALID_STATES),
                'role': In([x.value for x in cls.roles])
            }
        }, required=True)

        password_length = Length(min=options.min_length_password,
                                 max=options.max_length_password)

        schema = Schema({
            '_id': unicode,
            '_rev': unicode,
            Required('type', default=cls.resource_type): cls.resource_type,
            Required('email'): validators.valid_email,
            Required('password'): All(unicode, password_length),
            Required('has_agreed_to_terms'): True,
            Required('organisations', default=default_global): orgs_schema,
            Required('verified', default=False): bool,
            'first_name': unicode,
            'last_name': unicode,
            'phone': unicode,
            'verification_hash': unicode,
            'actor': unicode  # only used in fixtures, should it be removed?
        })

        return schema(doc)

    @coroutine
    def check_unique(self):
        """Check the user's email is unique"""
        emails = yield self.view.values(key=self.email)
        user_id = getattr(self, 'id', None)
        users = {x for x in emails if x != user_id and x}

        if users:
            raise exceptions.ValidationError(
                "User with email '{}' already exists".format(self.email))

    @classmethod
    @coroutine
    def create(cls, user, password, **kwargs):
        kwargs['verified'] = False
        kwargs['verification_hash'] = unicode(uuid.uuid4().hex)

        resource = cls(password=cls.hash_password(password), **kwargs)
        yield resource._save()

        raise Return(resource)

    @staticmethod
    def hash_password(plain_text):
        """Hash a plain text password"""
        # NOTE: despite the name this is a one-way hash not a reversible cypher
        hashed = pbkdf2_sha256.encrypt(plain_text, rounds=8000, salt_size=10)
        return unicode(hashed)

    def verify_password(self, password):
        """Verify the password matches the hash"""
        return pbkdf2_sha256.verify(password, self.password)

    @coroutine
    def change_password(self, previous, new_password):
        """
        Change the user's password and save to the database

        :param previous: plain text previous password
        :param new_password: plain text new password
        :raises: ValidationError
        """
        if not self.verify_password(previous):
            raise exceptions.Unauthorized('Incorrect password')

        if len(new_password) < options.min_length_password:
            msg = ('Passwords must be at least {} characters'
                   .format(options.min_length_password))
            raise exceptions.ValidationError(msg)

        if len(new_password) > options.max_length_password:
            msg = ('Passwords must be at no more than {} characters'
                   .format(options.max_length_password))
            raise exceptions.ValidationError(msg)

        self.password = self.hash_password(new_password)
        yield self._save()

    @classmethod
    @coroutine
    def login(cls, email, password):
        """
        Log in a user

        :param email: the user's email address
        :param password: the user's password
        :returns: (User, token)
        :raises: SocketError, CouchException
        """
        try:
            doc = yield cls.view.first(key=email, include_docs=True)
        except couch.NotFound:
            raise exceptions.Unauthorized('Unknown email address')

        user = cls(**doc['doc'])

        verified = user.verify_password(password)
        if not verified:
            raise exceptions.Unauthorized('Invalid password')

        token = yield Token.create(user)
        raise Return((user, token.id))

    @classmethod
    @coroutine
    def verify(cls, user_id, verification_hash):
        """
        Verify a user using the verification hash

        The verification hash is removed from the user once verified

        :param user_id: the user ID
        :param verification_hash: the verification hash
        :returns: a User instance
        """
        user = yield cls.get(user_id)
        if user.verified:
            raise Return(user)

        # NOTE: if the user is not verified and doesn't have a verification
        # hash, then this will result in an error
        # TODO: do we need to handle this scenario?
        if user.verification_hash != verification_hash:
            raise exceptions.ValidationError('Invalid verification hash')

        del user.verification_hash
        user.verified = True
        yield user._save()

        raise Return(user)

    def is_admin(self):
        """Is the user a "global" administrator"""
        return self._has_role('global', self.roles.administrator)

    def is_org_admin(self, organisation_id):
        """Is the user authorized to administrate the organisation"""
        return (self._has_role(organisation_id, self.roles.administrator) or
                self.is_admin())

    def is_user(self, organisation_id):
        """Is the user authorized to administrate the organisation"""
        return (self._has_role(organisation_id, self.roles.user) or
                self.is_org_admin(organisation_id))

    def _has_role(self, organisation_id, role):
        """Check the user's role for the organisation"""
        if organisation_id is None:
            return False

        try:
            org = self.organisations.get(organisation_id, {})
            user_role = org.get('role')
            state = org.get('join_state')
        except AttributeError:
            return False

        return user_role == role.value and state == State.approved.value

    @coroutine
    def can_delete(self, user):
        """Admin or user can delete a user"""
        raise Return(user.id == self.id or user.is_admin())

    @classmethod
    @coroutine
    def remove_organisation_from_all(cls, organisation_id):
        """Remove an organisation from all users"""
        users = yield views.organisation_members.get(key=organisation_id,
                                                     include_docs=True)
        users = [x['doc'] for x in users['rows']]
        for user in users:
            del user['organisations'][organisation_id]

        db = cls.db_client()
        yield db.save_docs(users)


class Token(Document):
    resource_type = 'token'
    db_name = 'token'
    read_only_fields = ['token_ttl', 'user_id']

    @classmethod
    @coroutine
    def create(cls, user):
        token = cls(user_id=user.id)
        if 'token_ttl' not in token._resource:
            ttl = (datetime.utcnow() + timedelta(seconds=options.token_ttl))

        token.token_ttl = ttl.isoformat()
        yield token._save()

        raise Return(token)

    @property
    def ttl(self):
        return parser.parse(self.token_ttl)

    @classmethod
    @coroutine
    def valid(cls, token, **kwargs):
        """
        Check if a token exists and has not expired

        :param token: the token
        :return: bool
        """
        try:
            token = yield cls.get(token)
        except couch.NotFound:
            raise Return(False)

        raise Return(token.ttl >= datetime.utcnow())


class UserOrganisation(SubResource):
    resource_type = 'user_organisation'
    parent_resource = User
    parent_key = 'organisations'
    view = views.user_organisations_resource
    internal_fields = ['id', 'user_id']

    schema = Schema({
        'id': unicode,
        'user_id': unicode,
        Required('join_state', default=State.default.value): In(VALID_STATES),
        Required('role', default=User.roles.default.value): In([x.value for x in User.roles])
    }, )

    @property
    def organisation_id(self):
        return self.id

    @classmethod
    @coroutine
    def can_create(cls, user, **kwargs):
        if 'join_state' in kwargs:
            if not user.is_admin() and kwargs['join_state'] != State.default.value:
                raise Return(False)

        raise Return(True)

    @coroutine
    def can_update(self, user, **kwargs):
        if not user.is_org_admin(self.organisation_id):
            raise Return((False, []))

        if 'role' in kwargs and self.join_state != State.approved.value:
            raise exceptions.ValidationError(
                'User is not an approved member of {}'
                .format(self.organisation_id))

        raise Return((True, []))

    @coroutine
    def can_delete(self, user, **kwargs):
        if not (user.is_org_admin(self.organisation_id)
                or user.id == self.user_id):
            raise Return(False)

        raise Return(True)