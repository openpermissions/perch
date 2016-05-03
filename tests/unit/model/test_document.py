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
from voluptuous import Schema, Required

import perch


def test_getattr():
    doc = perch.Document(x=1, y=2)

    assert doc.x == 1
    assert doc.y == 2


def test_attributeerror():
    with pytest.raises(AttributeError):
        perch.Document().x


def test_default_value():
    class MyDoc(perch.Document):
        schema = Schema({Required('x', default=1): int})

    assert MyDoc().x == 1


def test_falsey_attr():
    doc = perch.Document(x=0, y=[])

    assert doc.x == 0
    assert doc.y == []
