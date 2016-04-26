# -*- coding: utf-8 -*- Copyright 2016 Open Permissions Platform Coalition
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

import pytest
from voluptuous import Invalid

import perch
from perch import validators


@pytest.mark.parametrize('state', perch.State)
def test_validate_state(state):
    assert validators.validate_state(state.name) == state.name


@pytest.mark.parametrize('state', perch.State)
def test_validate_state_object(state):
    assert validators.validate_state(state) == state.name


def test_invalid_state():
    with pytest.raises(Invalid):
        validators.validate_state('blah')
