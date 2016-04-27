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

from voluptuous import Invalid

from perch import model


def test_format_error_field():
    err = model.format_error(Invalid('error', path=['a', 'b']), 'something')

    assert err == {'message': 'error', 'field': 'a'}


def test_format_error_no_path():
    err = model.format_error(Invalid('error'), 'something')

    assert err == {'message': 'error'}
