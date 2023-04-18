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
    "pad": "0.1",
}

with Diagram(NAME, show=False, direction="TB", outformat=["png"], graph_attr=graph_attr):
    with Cluster("Users"):
        developer = Users("developer")

    with Cluster("Live test runner (container)"):
        pytest = Python("Pytest")
        browser = Container("Browser")
        playwright = Python("Playwright")
        requests = Python("Requests")

    with Cluster("Public internet"):
        instance = Container("Internet.nl instance")

    developer >> Edge(label="make live-tests") >> pytest

    pytest >> playwright
    pytest >> requests
    playwright >> browser

    browser >> Edge(label="https://internet.nl:433") >> instance
    browser >> Edge(label="http://*.conn.test-ns6?-signed.internet.nl:80", minlen="2") >> instance

    requests >> Edge(label="https://internet.nl:433/api/batch/") >> instance
