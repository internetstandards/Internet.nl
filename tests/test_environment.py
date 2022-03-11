from django_redis import get_redis_connection


def test_redis_connection():
    # Sends a few trivial queries to redis, to see if the build can talk to it without infinite waits
    red = get_redis_connection("default")
    red.set("testing", 123)
    red.expire("testing", 2)
    assert red.get("testing") == b"123"

    red.expire("testing", 0)
    assert red.scard("testing") == 0


def test_rabbitmq_connection(requests_mock):
    # We want to test the real deal, not this mocked response.
    # How to disable requests_mock completely OR how to do basic authentication
    # requests_mock.get('http://localhost:15672/api/queues/%2F/batch_main', real_http=True)
    # get_rabbit_load()
    ...
