from celery.backends.redis import RedisBackend
from kombu.utils.compat import detect_environment


class RedisResultCleanupRedisBackend(RedisBackend):
    def process_cleanup(self):
        # perform normal cleanup
        super().process_cleanup()
        # skip extra cleanup when not relevant
        if self.thread_safe or detect_environment() != "gevent":
            return

        # kill drainer gevent process if active
        # https://github.com/celery/celery/blob/0626b2ba7ea5cb9457201f9045f54cd4e8a83686/celery/backends/asynchronous.py#L132
        consumer = self.result_consumer
        reader = consumer.drainer._g
        if reader is not None:
            reader.kill(block=True, timeout=1)
        # close redis pubsub object
        # https://github.com/celery/celery/blob/v5.5.3/celery/backends/redis.py#L154
        consumer.stop()
        # prevent closed pubsub object from being used
        consumer._pubsub = None
        # prevent closed pubsub from being reopened
        consumer.subscribed_to.clear()
        # close idle connections that where used by pubsub object
        self.client.connection_pool.disconnect(inuse_connections=False)
        # ensure new result backend calls get new consumer
        if self.app._backend is self:
            self.app._local.backend = None
