"""Redis result backend lifecycle for gevent worker tasks."""

from celery.backends.redis import RedisBackend
from kombu.utils.compat import detect_environment


class TaskLocalRedisBackend(RedisBackend):
    def process_cleanup(self):
        """Release a finished greenlet's result reader, including on task failure.

        Celery calls this hook after publishing continuations and storing results.
        Redis itself coordinates chords; a worker does not need to keep consuming
        the results of the continuations it has just published. Without cleanup,
        the drainer greenlet keeps the task-local backend and its sockets alive.

        Leave prefork workers and application request threads on the ordinary
        backend lifecycle. Only close idle pooled connections: Celery's cached
        task tracers can still use this backend for storing other tasks' results.
        """
        super().process_cleanup()
        if self.thread_safe or detect_environment() != "gevent":
            return

        consumer = self.result_consumer
        reader = consumer.drainer._g
        if reader is not None:
            reader.kill(block=True, timeout=1)
        consumer.stop()
        # AsyncResult finalizers must not reopen the retired Pub/Sub connection.
        consumer._pubsub = None
        consumer.subscribed_to.clear()
        self.client.connection_pool.disconnect(inuse_connections=False)
        # A reused execution context must get a fresh, startable reader.
        if self.app._backend is self:
            self.app._local.backend = None
