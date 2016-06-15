import couch
from mock import patch
from tornado.testing import AsyncTestCase, gen_test
from tornado.httpclient import HTTPError
from perch import Repository, Service, User, Organisation
from ..util import make_future


class WithRelations(AsyncTestCase):
    REPOSITORY = {
        "organisation_id": "org1",
        "name": "repository",
        "created_by": "user1",
        "state": "approved",
        "service_id": "serv1",
        "type": "repository",
        "id": "repo1",
        "permissions": []
    }

    USER = {
        "id": "user1",
        "role": "user",
        "state": "approved",
        "organisations": {}
    }

    @gen_test
    def test_get_repository(self):
        organisation = Organisation(id="org1", type="organisation", name="organisation")
        service = Service(id="serv1", type="service", name="service",
                          organisation_id="org2", location="https://example.com")

        with patch.object(Repository, "get_parent", return_value=make_future(organisation)):
            with patch.object(Service, "get", return_value=make_future(service)) as get_service:
                repo = Repository(**self.REPOSITORY)
                user = User(**self.USER)
                result = yield repo.with_relations(user)

                get_service.assert_called_with('serv1')

                assert result == {
                    "organisation": {
                        "id": "org1",
                        "name": "organisation"
                    },
                    "name": "repository",
                    "created_by": "user1",
                    "state": "approved",
                    "service": {
                        "id": "serv1",
                        "name": "service",
                        "organisation_id": "org2",
                        "location": "https://example.com"
                    },
                    "id": "repo1"
                }

    @gen_test
    def test_get_repository_no_parent(self):
        service = Service(id="serv1", type="service", name="service",
                          organisation_id="org2", location="https://example.com")

        with patch.object(Repository, "get_parent", side_effect=couch.NotFound(HTTPError(404, 'Not Found'))):
            with patch.object(Service, "get", return_value=make_future(service)) as get_service:
                repo = Repository(**self.REPOSITORY)
                user = User(**self.USER)
                result = yield repo.with_relations(user)

                get_service.assert_called_with('serv1')

                assert result == {
                    "organisation": {
                        "id": "org1"
                    },
                    "name": "repository",
                    "created_by": "user1",
                    "state": "approved",
                    "service": {
                        "id": "serv1",
                        "name": "service",
                        "organisation_id": "org2",
                        "location": "https://example.com"
                    },
                    "id": "repo1"
                }

    @gen_test
    def test_get_repository_no_service(self):
        organisation = Organisation(id="org1", type="organisation", name="organisation")

        with patch.object(Repository, "get_parent", return_value=make_future(organisation)):
            with patch.object(Service, "get", side_effect=couch.NotFound(HTTPError(404, 'Not Found'))) as get_service:
                repo = Repository(**self.REPOSITORY)
                user = User(**self.USER)
                result = yield repo.with_relations(user)

                get_service.assert_called_with('serv1')

                assert result == {
                    "organisation": {
                        "id": "org1",
                        "name": "organisation"
                    },
                    "name": "repository",
                    "created_by": "user1",
                    "state": "approved",
                    "service": {
                        "id": "serv1"
                    },
                    "id": "repo1"
                }
