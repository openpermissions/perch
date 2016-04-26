# -*- coding: utf-8 -*-
# Copyright 2016 Open Permissions Platform Coalition
from __future__ import unicode_literals

import pytest
import perch

from perch.model import State

client = None
service = None

# granted access, requested access, result
examples = [
    ('r', 'r', True),
    ('r', 'w', False),
    ('r', 'rw', False),
    ('r', '-', False),
    ('w', 'r', False),
    ('w', 'w', True),
    ('w', 'rw', False),
    ('w', '-', False),
    ('rw', 'r', True),
    ('rw', 'w', True),
    ('rw', 'rw', True),
    ('rw', '-', False),
    ('-', 'r', False),
    ('-', 'w', False),
    ('-', 'rw', False),
]


def setup():
    global client
    global service

    client_org = perch.Organisation(_id='client_org', state=State.approved)
    client = perch.Service(parent=client_org, **perch.Service.schema({
        'id': 'client1',
        'name': 'cilent',
        'organisation_id': 'client_org',
        'service_type': 'repository',
        'state': State.approved,
        'created_by': 'me',
        'location': 'http://client.test'
    }))
    service_org = perch.Organisation(_id='service_org', state=State.approved)
    service = perch.Service(parent=service_org, **perch.Service.schema({
        'id': 'service1',
        'name': 'service',
        'organisation_id': 'service_org',
        'service_type': 'repository',
        'state': State.approved,
        'created_by': 'me',
        'location': 'http://service.test',
    }))


def test_authorized_default_service_permissions():
    assert client.authorized('rw', service)


@pytest.mark.parametrize('granted,requested,result', examples)
def test_service_organisation_access(granted, requested, result):
    service.permissions = [
        {
            'type': 'organisation_id',
            'permission': granted,
            'value': client.organisation_id
        }
    ]

    assert client.authorized(requested, service) is result


@pytest.mark.parametrize('granted,requested,result', examples)
def test_service_type_access(granted, requested, result):
    service.permissions = [
        {
            'type': 'service_type',
            'permission': granted,
            'value': client.service_type
        }
    ]
    assert client.authorized(requested, service) is result


@pytest.mark.parametrize('granted,requested,result', examples)
def test_service_all_access(granted, requested, result):
    service.permissions = [
        {
            'type': 'all',
            'permission': granted,
            'value': None
        }
    ]

    assert client.authorized(requested, service) is result


@pytest.mark.parametrize('state', [x for x in State if x != State.approved])
def test_client_not_approved(state):
    client._resource['state'] = state
    assert not client.authorized('r', service)


@pytest.mark.parametrize('state', [x for x in State if x != State.approved])
def test_client_parent_not_approved(state):
    client.parent._resource['state'] = state
    assert not client.authorized('r', service)


@pytest.mark.parametrize('state', [x for x in State if x != State.approved])
def test_service_not_approved(state):
    client._resource['state'] = state
    assert not client.authorized('r', service)


@pytest.mark.parametrize('state', [x for x in State if x != State.approved])
def test_service_parent_not_approved(state):
    service.parent._resource['state'] = state
    assert not client.authorized('r', service)


def test_organisation_access_priority():
    service.permissions = [
        {
            'type': 'all',
            'permission': '-',
            'value': None
        },
        {
            'type': 'service_type',
            'permission': '-',
            'value': client.service_type
        },
        {
            'type': 'organisation_id',
            'permission': 'w',
            'value': client.organisation_id
        }
    ]

    assert client.authorized('w', service)


def test_service_type_priority():
    service.permissions = [
        {
            'type': 'all',
            'permission': '-',
            'value': None
        },
        {
            'type': 'service_type',
            'permission': 'w',
            'value': client.service_type
        }
    ]

    assert client.authorized('w', service)


def test_multiple_rules():
    service.permissions = [
        {
            'type': 'organisation_id',
            'permission': 'r',
            'value': client.organisation_id
        },
        {
            'type': 'organisation_id',
            'permission': 'w',
            'value': client.organisation_id
        }
    ]

    assert client.authorized('w', service)
    assert client.authorized('r', service)
    assert client.authorized('rw', service)


def test_multiple_rules_denied():
    service.permissions = [
        {
            'type': 'organisation_id',
            'permission': 'r',
            'value': client.organisation_id
        },
        {
            'type': 'organisation_id',
            'permission': '-',
            'value': client.organisation_id
        },
        {
            'type': 'organisation_id',
            'permission': 'w',
            'value': client.organisation_id
        }
    ]

    assert not client.authorized('w', service)
