# -*- coding: utf-8 -*-
# Copyright 2016 Open Permissions Platform Coalition
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import uuid

from mock import Mock, patch
from tornado.concurrent import Future


def make_future(result=None):
    """Create a `tornado.concurrent.Future` that returns `result`

    Useful for adding a return value to a mocked coroutine.

    :param result: the Future's result
    :returns: tornado.concurrent.Future
    """
    future = Future()
    future.set_result(result)
    return future


def return_fake_future(f):
    """will wrap whatever decorated function return in a Future
    """
    def wrap(*args, **kwargs):
        future = Future()
        future.set_result(f(*args, **kwargs))
        return future
    return wrap


@return_fake_future
def fake_save_doc(resource):
    saved = resource.copy()
    saved['id'] = saved.pop('_id', uuid.uuid4().hex)

    return saved

_resource_patches = {}


def patch_db(resource):
    db_client = Mock()
    db_client.save_doc.side_effect = fake_save_doc
    patched = patch.object(resource, 'db_client', return_value=db_client)

    return patched
