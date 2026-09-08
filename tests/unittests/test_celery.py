import os
import subprocess
import sys
import textwrap


def test_gevent_greenlets_use_task_local_result_backends():
    program = textwrap.dedent("""
        from gevent import joinall, monkey, spawn

        monkey.patch_all()

        from internetnl.celery import app

        jobs = [spawn(lambda: app.backend) for _ in range(2)]
        joinall(jobs, raise_error=True)
        backends = [job.value for job in jobs]

        assert backends[0] is not backends[1]

        from internetnl.celery_backend import TaskLocalRedisBackend

        assert all(
            isinstance(backend, TaskLocalRedisBackend)
            for backend in backends
        )
        """)
    environment = {
        **os.environ,
        "SKIP_SECRET_KEY_CHECK": "True",
    }

    result = subprocess.run(
        [sys.executable, "-c", program],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
