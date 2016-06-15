# -*- coding: utf-8 -*-
# Copyright 2016 Open Permissions Platform Coalition
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy of
# the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import unicode_literals

import pytest
from mock import patch
from tornado.testing import AsyncTestCase, gen_test

from perch import exceptions, Token, User
from perch.model import State
from .util import make_future, patch_db, patch_view

USERS = [
    {
        '_id': 'user0',
        'type': 'user',
        'email': 'user0@mail.test',
        'password': User.hash_password('password0'),
        'state': 'approved',
        'has_agreed_to_terms': True,
        'organisations': {}
    }, {
        '_id': 'user1',
        'type': 'user',
        'email': 'user1@mail.test',
        'password': User.hash_password('password1'),
        'state': 'approved',
        'has_agreed_to_terms': True,
        'verification_hash': 'this is a hash'
    }
]

VERIFIED_USER = USERS[0]
UNVERIFIED_USER = USERS[1]

patched_get = patch_view(User.view, USERS)


class CreateUser(AsyncTestCase):
    @patch_view(User.view, [])
    @patch_db(User)
    @gen_test
    def test_create_user(self, db_client):
        user = yield User.create(User(),
                                 'password',
                                 email='me@mail.test',
                                 first_name='test',
                                 last_name='user',
                                 has_agreed_to_terms=True)

        assert user.first_name == 'test'
        assert user.last_name == 'user'
        assert user.password != 'password'
        assert user.verify_password('password')
        assert user.state == State.approved
        assert user.verification_hash

        assert db_client().save_doc.call_count == 1

    @patch_db(User)
    @gen_test
    def test_create_user_invalid_password(self, db_client):
        with pytest.raises(exceptions.ValidationError):
            yield User.create(User(), 'p')

    @patch_view(User.view, [])
    @patch_db(User)
    @gen_test
    def test_create_admin_user(self, db_client):
        user = yield User.create_admin('me@mail.test',
                                       'password',
                                       first_name='test',
                                       last_name='user')

        assert user.first_name == 'test'
        assert user.last_name == 'user'
        assert user.verify_password('password')
        assert user.state == State.approved
        assert 'verification_hash' not in user._resource
        assert user.is_admin()

        assert db_client().save_doc.call_count == 1
        assert db_client().save_doc.call_args[0][0] == user._resource


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


class CheckUserDefaults(AsyncTestCase):
    @gen_test
    def test_get_user_defaults(self):
        user = User(password='password', id='uid')
        assert user.type == 'user'
        assert user.organisations == {}
        assert user.role == 'user'
        assert user.state.name == 'approved'

    @gen_test
    def test_get_required_fields_with_defaults(self):
        test_user = User(password='password', id='uid')
        expected_org_defaults = {
            'state': 'approved',
            'role': 'user',
            'type': 'user',
            'organisations': {}
        }
        returned_defaults = test_user.get_required_fields_with_defaults()
        assert expected_org_defaults == returned_defaults


class IsAdmin(AsyncTestCase):
    def test_is_admin(self):
        user = User(password='password', role='administrator', id='uid')
        result = user.is_admin()
        assert result is True

    def test_is_not_admin(self):
        user = User(password='password', role='user', id='uid')
        result = user.is_admin()
        assert result is False

    def test_is_deactivated(self):
        user = User(password='password', role='administrator', state='deactivated', id='uid')
        result = user.is_admin()
        assert result is False


class CanUpdate(AsyncTestCase):
    @gen_test
    def test_current_user(self):
        user = User(password='password', id='uid')

        result = yield user.can_update(user, first_name='TestName')
        assert result == (True, set([]))

    @gen_test
    def test_sys_admin(self):
        user_to_update = User(password='password', id='uid2')
        user_doing_update = User(password='password', role='administrator', id='uid')

        result = yield user_to_update.can_update(user_doing_update, first_name='TestName')
        assert result == (True, set([]))

    @gen_test
    def test_other_user(self):
        user_to_update = User(password='password', id='uid2')
        user_doing_update = User(password='password', id='uid')

        result = yield user_to_update.can_update(user_doing_update, first_name='TestName')
        assert result == (False, set([]))

    @gen_test
    def test_current_user_role(self):
        user = User(password='password', id='uid')

        result = yield user.can_update(user, first_name='TestName', role='administrator')
        assert result == (False, {'role'})

    @gen_test
    def test_sys_admin_role(self):
        user_to_update = User(password='password', id='uid2')
        user_doing_update = User(password='password', role='administrator', id='uid')

        result = yield user_to_update.can_update(user_doing_update, first_name='TestName', role='administrator')
        assert result == (True, set([]))

    @gen_test
    def test_other_user_role(self):
        user_to_update = User(password='password', id='uid2')
        user_doing_update = User(password='password', id='uid')

        result = yield user_to_update.can_update(user_doing_update, first_name='TestName')
        assert result == (False, set([]))


@pytest.mark.parametrize("user", USERS)
def test_internal_fields_not_returned(user):
    u = User(**user)
    result = u.clean()

    assert '_id' not in result
    assert 'password' not in result
    assert 'verification_hash' not in result


def test_verified():
    u = User(**VERIFIED_USER)
    result = u.clean()
    assert result['verified'] is True


def test_unverified():
    u = User(**UNVERIFIED_USER)
    result = u.clean()
    assert result['verified'] is False