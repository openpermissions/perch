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

from functools import partial
import perch
import pytest
from mock import MagicMock
from tornado.ioloop import IOLoop
from ..util import make_future

#start state, end state, valid
transitions = [
    (None, perch.State.pending, True),
    (None, perch.State.approved, False),
    (None, perch.State.rejected, False),
    (None, perch.State.deactivated, False),
    (perch.State.pending, perch.State.pending, True),
    (perch.State.pending, perch.State.approved, False),
    (perch.State.pending, perch.State.rejected, False),
    (perch.State.pending, perch.State.deactivated, True),
    (perch.State.approved, perch.State.pending, True),
    (perch.State.approved, perch.State.approved, True),
    (perch.State.approved, perch.State.rejected, False),
    (perch.State.approved, perch.State.deactivated, True),
    (perch.State.rejected, perch.State.pending, True),
    (perch.State.rejected, perch.State.approved, False),
    (perch.State.rejected, perch.State.rejected, True),
    (perch.State.rejected, perch.State.deactivated, True),
    (perch.State.deactivated, perch.State.pending, True),
    (perch.State.deactivated, perch.State.approved, False),
    (perch.State.deactivated, perch.State.rejected, False),
    (perch.State.deactivated, perch.State.deactivated, True)]

approval_transitions = [
    (None, perch.State.pending, True),
    (None, perch.State.approved, True),
    (None, perch.State.rejected, False),
    (None, perch.State.deactivated, False),
    (perch.State.pending, perch.State.pending, True),
    (perch.State.pending, perch.State.approved, True),
    (perch.State.pending, perch.State.rejected, True),
    (perch.State.pending, perch.State.deactivated, True),
    (perch.State.approved, perch.State.pending, True),
    (perch.State.approved, perch.State.approved, True),
    (perch.State.approved, perch.State.rejected, False),
    (perch.State.approved, perch.State.deactivated, True),
    (perch.State.rejected, perch.State.pending, True),
    (perch.State.rejected, perch.State.approved, False),
    (perch.State.rejected, perch.State.rejected, True),
    (perch.State.rejected, perch.State.deactivated, True),
    (perch.State.deactivated, perch.State.pending, True),
    (perch.State.deactivated, perch.State.approved, True),
    (perch.State.deactivated, perch.State.rejected, False),
    (perch.State.deactivated, perch.State.deactivated, True)]


@pytest.mark.parametrize("start,end,valid", transitions)
def test_state_transition_without_approval(start, end, valid):
    user = perch.User()

    doc = perch.Document(state=start)
    perch.Document.can_approve = MagicMock(return_value=make_future(False))

    func = partial(doc.validate_state_transition, user, start, end)
    result = IOLoop.instance().run_sync(func)
    assert result == valid

@pytest.mark.parametrize("start,end,valid", approval_transitions)
def test_state_transition_with_approval(start, end, valid):
    user = perch.User()

    doc = perch.Document(state=start)
    perch.Document.can_approve = MagicMock(return_value=make_future(True))

    func = partial(doc.validate_state_transition, user, start, end)
    result = IOLoop.instance().run_sync(func)
    assert result == valid
