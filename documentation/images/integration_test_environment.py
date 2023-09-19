import os.path

from diagrams import Diagram, Cluster, Edge

from diagrams.oci.compute import Container
from diagrams.programming.language import Python
from diagrams.onprem.database import PostgreSQL
from diagrams.onprem.queue import  RabbitMQ
from diagrams.onprem.inmemory import Redis
from diagrams.onprem.network import Apache, Nginx
from diagrams.onprem.client import Users
from diagrams.generic.storage import Storage
from diagrams.oci.compute import Container
from diagrams.programming.framework import Django
from diagrams.onprem.database import PostgreSQL
from diagrams.onprem.queue import  RabbitMQ
from diagrams.onprem.inmemory import Redis
from diagrams.onprem.network import Nginx
from diagrams.onprem.client import Users
from diagrams.generic.storage import Storage
from diagrams.onprem.monitoring import Grafana

# diagrams uses the Diagram name as output file name, try to make it match the .py filename as best as possible
NAME = os.path.splitext(os.path.basename(__file__))[0].replace("_", " ").capitalize()

graph_attr = {
    "splines": "true",
    "size": "20",
    "pad": "0.2",
}

with Diagram(NAME, show=False, direction="TB", outformat=["png"], graph_attr=graph_attr):
    with Cluster("Users"):
        developer = Users("developer")

    port_expose = Container("port-expose")

    with Cluster("Isolated network"):
        with Cluster("Test runner (container)"):
            pytest = Python("Pytest")
            browser = Container("Browser")
            playwright = Python("Playwright")
            requests = Python("Requests")

        with Cluster("resolver"):
            resolver = Container("resolver\n(unbound)")

        with Cluster("mock-resolver"):
            mock_resolver = Container("mock-resolver\n(dnsmasq)")

        with Cluster("Test targets"):
            target_test = Container("https://target.test\nhttps://*.target.test")
            target_test_mail = Container("mx.target.test:25")

        with Cluster("Application Stack"):
            with Cluster("Webserver"):
                nginx = Nginx("nginx/certbot (letsencrypt)")

            with Cluster("Application"):
                app = Django("app")
                worker = Django("worker")
                beat = Django("beat (scheduler)")

            with Cluster("Unbound"):
                unbound = Container("unbound")

            with Cluster("Services"):
                postgresql = PostgreSQL("postgresql")
                redis = Redis("redis")
                rabbitmq = RabbitMQ("rabbitmq")
                routinator = Container("routinator")

            with Cluster("Metrics", graph_attr={"style":"dashed"}):
                monitoring = Container("Metrics system")

    browser  >> mock_resolver
    app  >> resolver
    worker  >> resolver

    resolver >> mock_resolver

    developer >> Edge(label="http://localhost:8081") >> port_expose
    port_expose >> Edge(label="https://webserver:433") >> nginx
    developer >> Edge(label="make integration-tests") >> pytest

    nginx >> Edge(minlen="2", label="http://app:8080") >> app
    nginx >> Edge(minlen="2", label="/grafana,/prometheus", lhead="cluster_Monitoring") >> monitoring

    app >> Edge(minlen="2") >>redis
    app >> Edge(minlen="2") >>rabbitmq
    app >> Edge(minlen="2") >> postgresql

    worker >> Edge(minlen="2") >> redis
    worker >> Edge(minlen="2") >> rabbitmq
    worker >> Edge(minlen="2") >> postgresql
    worker >> Edge(minlen="2") >> routinator

    beat >> Edge(minlen="2") >> rabbitmq

    unbound >> Edge(minlen="2") >> redis

    pytest >> playwright
    pytest >> requests
    playwright >> browser

    browser >> Edge(label="https://internet.test:433") >> nginx
    browser >> Edge(label="connection test NS lookups") >> unbound
    browser >> Edge(label="http://*.conn.test-ns6?-signed.internet.test:80", minlen="2") >> nginx

    requests >> Edge(label="https://internet.test:433/api/batch/") >> nginx

    app >> Edge(minlen="4") >> target_test
    worker >> target_test
    app >> target_test_mail
    worker >> target_test_mail
