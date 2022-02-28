from django_redis import get_redis_connection


def test_redis_connection():
    # Sends a few trivial queries to redis, to see if the build can talk to it without infinite waits
    red = get_redis_connection("default")
    red.set("testing", 123)
    red.expire("testing", 2)
    assert red.get("testing") == b"123"

    red.expire("testing", 0)
    assert red.scard("testing") == 0


def test_rabbitmq_connection():
