import importlib.util
from pathlib import Path
import sys
import types

import pytest

if importlib.util.find_spec("prometheus_client") is None:
    prometheus_client = types.ModuleType("prometheus_client")

    class GaugeValue:
        def __init__(self):
            self.value = 0

        def get(self):
            return self.value

    class GaugeChild:
        def __init__(self, gauge, labels):
            self._value = gauge.values.setdefault(labels, GaugeValue())

        def set(self, value):
            self._value.value = value

    class Gauge:
        def __init__(self, name, _description, labels):
            self.name = name
            self.label_names = labels
            self.values = {}
            REGISTRY.metrics.append(self)

        def labels(self, *labels):
            return GaugeChild(self, labels)

        def clear(self):
            self.values.clear()

    class Registry:
        def __init__(self):
            self.metrics = []

        def unregister(self, _collector):
            pass

    def generate_latest(registry):
        lines = []
        for metric in registry.metrics:
            for labels, value in metric.values.items():
                labels_by_name = dict(zip(metric.label_names, labels, strict=True))
                rendered_labels = ",".join(f'{name}="{labels_by_name[name]}"' for name in sorted(labels_by_name))
                lines.append(f"{metric.name}{{{rendered_labels}}} {float(value.get())}")
        return ("\n".join(lines) + "\n").encode()

    REGISTRY = Registry()
    prometheus_client.REGISTRY = REGISTRY
    prometheus_client.Gauge = Gauge
    prometheus_client.generate_latest = generate_latest
    prometheus_client.GC_COLLECTOR = object()
    prometheus_client.PLATFORM_COLLECTOR = object()
    prometheus_client.PROCESS_COLLECTOR = object()
    sys.modules["prometheus_client"] = prometheus_client


SCRIPT_PATH = Path(__file__).parents[2] / "docker/cron/periodic/15min/tests.py"
SPEC = importlib.util.spec_from_file_location("periodic_tests", SCRIPT_PATH)
periodic_tests = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(periodic_tests)


@pytest.fixture(autouse=True)
def clear_test_metrics():
    for metric in (
        periodic_tests.METRIC_TEST_RUN,
        periodic_tests.METRIC_TEST_CACHE,
        periodic_tests.METRIC_TEST_FAILURE,
        periodic_tests.METRIC_TEST_SUCCESS,
        periodic_tests.METRIC_TEST_TIMEOUT,
        periodic_tests.METRIC_TEST_RUNTIME,
    ):
        metric.clear()


def test_run_timeout_stops_at_active_domain(monkeypatch):
    calls = []

    def time_out(test, domain):
        calls.append((test, domain))
        raise periodic_tests.PeriodicTestTimeout

    monkeypatch.setattr(periodic_tests, "TESTS", ["site"])
    monkeypatch.setattr(periodic_tests, "TEST_DOMAINS", {"site": ["example.nl", "internet.nl"]})
    monkeypatch.setattr(periodic_tests, "run_tests_on_domain", time_out)
    monkeypatch.setattr(periodic_tests.time, "time", iter([100, 114]).__next__)

    with pytest.raises(periodic_tests.PeriodicTestTimeout):
        periodic_tests.run_tests()

    assert calls == [("site", "example.nl")]
    assert periodic_tests.METRIC_TEST_SUCCESS.labels("site", "example.nl")._value.get() == 0
    assert periodic_tests.METRIC_TEST_TIMEOUT.labels("site", "example.nl")._value.get() == 1
    assert periodic_tests.METRIC_TEST_RUNTIME.labels("site", "example.nl")._value.get() == 14


def test_run_tests_with_timeout_cancels_alarm_and_restores_handler(monkeypatch):
    previous_handler = object()
    handlers = []
    alarms = []

    def set_handler(_signal, handler):
        handlers.append(handler)
        return previous_handler

    monkeypatch.setattr(periodic_tests.signal, "signal", set_handler)
    monkeypatch.setattr(periodic_tests.signal, "alarm", alarms.append)
    monkeypatch.setattr(periodic_tests, "run_tests", lambda: None)

    assert periodic_tests.run_tests_with_timeout()
    assert alarms == [periodic_tests.PERIODIC_TEST_TIMEOUT, 0]
    assert handlers == [periodic_tests._periodic_test_timeout, previous_handler]


def test_run_tests_with_timeout_reports_cutoff(monkeypatch):
    monkeypatch.setattr(periodic_tests.signal, "signal", lambda _signal, _handler: None)
    monkeypatch.setattr(periodic_tests.signal, "alarm", lambda _seconds: None)
    monkeypatch.setattr(
        periodic_tests,
        "run_tests",
        lambda: periodic_tests._periodic_test_timeout(None, None),
    )

    assert not periodic_tests.run_tests_with_timeout()


def test_write_metrics_publishes_partial_snapshot(monkeypatch, tmp_path):
    output = tmp_path / "tests.prom"
    periodic_tests.METRIC_TEST_RUN.labels("site", "example.nl").set(1)
    periodic_tests.METRIC_TEST_TIMEOUT.labels("site", "example.nl").set(1)
    monkeypatch.setattr(periodic_tests, "DEBUG", False)
    monkeypatch.setattr(periodic_tests, "OUTPUT_TEXTFILE", output)

    periodic_tests.write_metrics()

    metrics = output.read_text()
    assert 'tests_test_run_total{domain="example.nl",test="site"} 1.0' in metrics
    assert 'tests_test_timeout_total{domain="example.nl",test="site"} 1.0' in metrics


def test_main_exits_unsuccessfully_after_publishing_partial_metrics(monkeypatch):
    published = []
    monkeypatch.setattr(periodic_tests.REGISTRY, "unregister", lambda _collector: None)
    monkeypatch.setattr(periodic_tests, "run_tests_with_timeout", lambda: False)
    monkeypatch.setattr(periodic_tests, "write_metrics", lambda: published.append(True))

    with pytest.raises(SystemExit) as exc_info:
        periodic_tests.main()

    assert exc_info.value.code == 1
    assert published == [True]
