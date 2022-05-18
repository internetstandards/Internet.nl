import json
import uuid


from checks.models import BatchRequestType, BatchUser
from interface.batch.util import register_request


def test_convert_batch_request_type():
    # Validate that we can also instantiate the right batch request type from a string,
    # this saves an if statement when registering requests
    x = BatchRequestType["mail"]
    assert x == BatchRequestType.mail


# todo: freeze time
# @override_settings(CELERY_EAGER_PROPAGATES_EXCEPTIONS=True, CELERY_ALWAYS_EAGER=True, BROKER_BACKEND="memory")
# @pytest.mark.skipif(os.getenv("GITHUB_ACTIONS", "") == "True", reason="Redis hang? at github actions")
# @pytest.mark.skip
def test_register_batch_request(db):
    # todo: should i need a django web client, or can i just run it like this?
    # ah, and now this nonsense where there are two users on the same database at the same time because we have
    # a test-worker.

    test_user = BatchUser.objects.create(name="test_user")

    random_name = str(uuid.uuid4())

    request_data = {"type": "mail", "domains": ["internet.nl", "example.nl"], "name": random_name}

    request_user = {"batch_user": test_user}

    created = register_request(request_data, **request_user)

    response_data = json.loads(created.content)
    assert response_data["request"]["name"] == random_name
    assert response_data["request"]["request_type"] == "mail"
    assert response_data["request"]["status"] == "registering"


#  todo: add testcase where data is available and an API response is created.
#  this requires a scan to be ran etc.
