import json
import uuid
from django.core.cache import cache
from checks.models import BatchRequest, BatchRequestType, BatchUser, BatchRequestStatus
from interface.batch.util import get_request, register_request
from django.test.client import RequestFactory
import pytest
from interface.batch.util import batch_async_generate_results
from interface import redis_id


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

    test_user = BatchUser.objects.create(username="test_user")

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


@pytest.mark.withoutresponses
def test_batch_request_result_generation(db, client, mocker):
    """There can only be one result generate task in the queue per batch request id."""

    request = RequestFactory().get("/")

    # mock putting task on the queue as queue/worker dynamics makes testing unreliable
    mocker.patch("interface.batch.util.batch_async_generate_results.delay")
    batch_async_generate_results.delay.return_value = "123"

    # create dummy batch request for testing
    test_user = BatchUser.objects.create(username="test_user")
    batch_request = BatchRequest.objects.create(user=test_user, name="test_batch_request", type=BatchRequestType.web)

    get_request(request, batch_request, test_user)

    #  batch_async_generate_results task should not be queued if the batch request is not done yet
    assert batch_async_generate_results.delay.call_count == 0

    batch_request.status = BatchRequestStatus.done
    batch_request.save()

    # if batch request is done, a batch_async_generate_results task should be put on the queue to generate the results
    get_request(request, batch_request, test_user)
    assert batch_async_generate_results.delay.call_count == 1

    # there should not be an additional task put on the queue when one is already present
    get_request(request, batch_request, test_user)
    assert batch_async_generate_results.delay.call_count == 1

    # if the cache expires a new batch_async_generate_results task can be added
    lock_id = redis_id.batch_results_request_lock.id.format(batch_request.request_id)
    cache.delete(lock_id)
    get_request(request, batch_request, test_user)
    assert batch_async_generate_results.delay.call_count == 2
