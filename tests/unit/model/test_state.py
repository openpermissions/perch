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

import pytest
import perch


def test_document_state():
    doc = perch.Document(state=perch.State.approved.name)
    assert doc.state == perch.State.approved


def test_document_default_state():
    doc = perch.Document()
    assert doc.state == perch.Document.default_state


def test_document_with_state_object():
    """Accept a state object in __init__"""
    doc = perch.Document(state=perch.State.approved)
    assert doc.state == perch.State.approved


def test_subresource_state():
    doc = perch.SubResource(
        state=perch.State.approved.name,
        parent=perch.Document(state=perch.State.approved.name))

    assert doc.state == perch.State.approved


def test_subresource_default_state():
    doc = perch.SubResource(parent=perch.Document())
    assert doc.state == perch.SubResource.default_state


def test_subresource_with_state_object():
    """Accept a state object in __init__"""
    doc = perch.SubResource(
        state=perch.State.approved,
        parent=perch.Document(state=perch.State.approved))
    assert doc.state == perch.State.approved


def test_parent_overrides_subresource_state():
    doc = perch.SubResource(
        state=perch.State.approved.name,
        parent=perch.Document(state=perch.State.rejected.name))

    assert doc.state == perch.State.rejected

    doc = perch.SubResource(
        state=perch.State.pending.name,
        parent=perch.Document(state=perch.State.approved.name))

    assert doc.state == perch.State.pending


def test_subresource_state_without_parent():
    doc = perch.SubResource()

    with pytest.raises(Exception):
        doc.state
