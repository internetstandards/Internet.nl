import os.path

from diagrams import Diagram, Cluster, Edge

from diagrams.oci.compute import Container
from diagrams.onprem.monitoring import Grafana, Prometheus
from diagrams.onprem.queue import RabbitMQ
from diagrams.onprem.database import PostgreSQL
from diagrams.onprem.inmemory import Redis
from diagrams.programming.framework import Django

# diagrams uses the Diagram name as output file name, try to make it match the .py filename as best as possible
NAME = os.path.splitext(os.path.basename(__file__))[0].replace("_", " ").capitalize()

graph_attr = {
    "splines": "true",
    "size": "12",
    "pad": "0.1",
}

with Diagram(NAME, show=False, direction="TB", outformat=["png"], graph_attr=graph_attr):
    with Cluster("Monitoring"):
        grafana = Grafana("Grafana")
        prometheus = Prometheus("Prometheus")

        exporters = {exporter + '-exporter': Container(exporter + '-exporter') for exporter in ['redis', 'postgresql', 'statsd', 'celery']}

    with Cluster("Application"):
        app = Django("app")
        worker = Django("worker")
        beat = Django("beat")

    with Cluster("Services"):
        postgresql = PostgreSQL("postgres")
        redis = Redis("redis")
        rabbitmq = RabbitMQ("rabbitmq")

    app >> Edge(minlen="2", color='transparent') >> postgresql

    grafana << prometheus
    prometheus << list(exporters.values()) + [rabbitmq]
    exporters['statsd-exporter'] << Edge(minlen="2") << [app, worker, beat]
    exporters['postgresql-exporter'] << postgresql
    exporters['redis-exporter'] << redis
    exporters['celery-exporter'] << rabbitmq