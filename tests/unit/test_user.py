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

import couch
import pytest
from mock import patch
from tornado.testing import AsyncTestCase, gen_test

from perch import exceptions, Organisation, Token, User
from perch.model import State
from .util import make_future, return_fake_future, patch_db

USERS = [
    {
        '_id': 'user0',
        'type': 'user',
        'email': 'user0@mail.test',
        'password': User.hash_password('password0'),
        'verified': True,
        'state': 'approved',
        'has_agreed_to_terms': True,
        'organisations': {}
    }, {
        '_id': 'user1',
        'type': 'user',
        'email': 'user1@mail.test',
        'password': User.hash_password('password1'),
        'verified': False,
        'state': 'approved',
        'has_agreed_to_terms': True,
        'verification_hash': 'this is a hash'
    }
]

UNVERIFIED_USER = USERS[-1]
USERS_VIEW = {k: {'doc': user, 'value': v}
              for user in USERS for k, v in User.view(user)}


@return_fake_future
def fake_users(key=None, **kwargs):
    if key is None:
        return {'rows': USERS_VIEW.values()}
    else:
        try:
            return {'rows': [USERS_VIEW[key]]}
        except KeyError:
            return {'rows': []}

patched_get = patch.object(User.view, 'get', fake_users)


class CreateUser(AsyncTestCase):
    @gen_test
    def test_create_user(self):
        with patch.object(User, '_save', return_value=make_future(None)):
            user = yield User.create(User(),
                                     'password',
                                     first_name='test',
                                     last_name='user')

            assert user.first_name == 'test'
            assert user.last_name == 'user'
            assert user.password != 'password'
            assert user.verify_password('password')
            assert user.state == State.approved
            assert not user.verified
            assert user.verification_hash

            assert user._save.call_count == 1

    @gen_test
    def test_create_user_invalid_password(self):
        # TODO
        pass


class Login(AsyncTestCase):
    def setUp(self):
        patched_get.start()
        super(Login, self).setUp()

    def tearDown(self):
        patched_get.stop()
        super(Login, self).tearDown()

    @patch_db(Token)
    @gen_test
    def test_login(self, db_client):
        user, token = yield User.login(USERS[0]['email'], 'password0')

        assert user.id == USERS[0]['_id']
        assert token

        saved_token = db_client().save_doc.call_args[0][0]

        assert saved_token['_id'] == token
        assert saved_token['user_id'] == user.id

    @patch_db(Token)
    @gen_test
    def test_login_incorrect_password(self, db_client):
        with pytest.raises(exceptions.Unauthorized):
            yield User.login(USERS[0]['email'], 'password1')

    @patch_db(Token)
    @gen_test
    def test_login_incorrect_email(self, db_client):
        with pytest.raises(exceptions.Unauthorized):
            yield User.login('does not exist', 'password')

    @patch_db(Token)
    @gen_test
    def test_login_unverified_user(self, db_client):
        """Check logging in an unverified user doesn't raise an exception"""
        # TODO: should we allow unverified users to login?
        yield User.login(UNVERIFIED_USER['email'], 'password1')


class Verify(AsyncTestCase):
    @patch_db(User)
    @gen_test
    def test_unverified_user(self, db_client):
        db_client().get_doc.return_value = make_future(UNVERIFIED_USER)
        with patch.object(User, 'check_unique', return_value=make_future()):
            user = yield User.verify(UNVERIFIED_USER['_id'],
                                     UNVERIFIED_USER['verification_hash'])

        assert user.id == UNVERIFIED_USER['_id']
        assert user.state == State.approved
        assert user.verified
        assert 'verification_hash' not in user._resource
        db_client().save_doc.assert_called_once_with(user._resource)

    @patch_db(User)
    @gen_test
    def test_verified_user(self, db_client):
        db_client().get_doc.return_value = make_future(USERS[0])
        user = yield User.verify(USERS[0]['_id'], 'something')

        assert user.id == USERS[0]['_id']
        assert not User.db_client().save_doc.called

    @patch_db(User)
    @gen_test
    def test_invalid_hash(self, db_client):
        db_client().get_doc.return_value = make_future(UNVERIFIED_USER)
        with pytest.raises(exceptions.ValidationError):
            yield User.verify(UNVERIFIED_USER['_id'], 'something')

        assert not User.db_client().save_doc.called


class CheckUnique(AsyncTestCase):
    def setUp(self):
        patched_get.start()
        super(CheckUnique, self).setUp()

    def tearDown(self):
        patched_get.stop()
        super(CheckUnique, self).tearDown()

    @gen_test
    def test_unique(self):
        user = User(**USERS[0])
        yield user.check_unique()

    @gen_test
    def test_unique_user_new_email(self):
        user = User(email='test@test')
        yield user.check_unique()

    @gen_test
    def test_unique_user_new(self):
        user = User(email=USERS[0]['email'])
        with pytest.raises(exceptions.ValidationError):
            yield user.check_unique()


class ChangePassword(AsyncTestCase):
    @gen_test
    def test_change_password(self):
        user = User(password=User.hash_password('password1'))
        assert user.verify_password('password1')

        with patch.object(User, '_save', return_value=make_future()):
            yield user.change_password('password1', 'password2')

            assert user.verify_password('password2')
            assert User._save.call_count == 1

    @gen_test
    def test_change_password_incorrect_password(self):
        user = User(password=User.hash_password('password1'))

        with pytest.raises(exceptions.Unauthorized):
            yield user.change_password('password2', 'password3')
