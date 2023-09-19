import os.path
from diagrams import Diagram, Cluster, Edge

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
    "layout": "dot",
    "splines": "true",
    "compound": "true",
    "size": "12",
    "pad": "0.1",
}

with Diagram(NAME, show=False, direction="TB", outformat=["png"], graph_attr=graph_attr):
    with Cluster("Users"):
        api_user = Users("api_user")
        administrator = Users("administrator")

    with Cluster("Host OS (Linux)"):
        with Cluster("Docker/Docker Compose"):
            port_forwarding = Container("port-forwarding")

            with Cluster("Webserver"):
                nginx = Nginx("nginx/certbot (letsencrypt)")

            with Cluster("Application"):
                app = Django("app")
                worker = Django("worker")
                beat = Django("beat (scheduler)")

            with Cluster("Resolver"):
                resolver = Container("resolver (unbound)")

            with Cluster("Services"):
                postgresql = PostgreSQL("postgresql")
                redis = Redis("redis")
                rabbitmq = RabbitMQ("rabbitmq")
                routinator = Container("routinator")

            with Cluster("Metrics", graph_attr={"style":"dashed"}):
                monitoring = Container("Metrics system")

    with Cluster("Test subjects"):
        target = Container("example.nl")

    api_user >> Edge(minlen="2", label="HTTPS: https://example.com/api/batch/v2\n(password protected)") >> port_forwarding

    administrator >> Edge(minlen="2", label="HTTPS: https://example.com/\n(password protected)") >> port_forwarding
    administrator >> Edge(minlen="2", label="HTTPS: https://example.com/grafana\n(password protected)") >> port_forwarding

    port_forwarding >> Edge(minlen="2", label="HTTPS") >> nginx

    nginx >> Edge(minlen="2", label="/,/api/batch/v2") >> app
    nginx >> Edge(minlen="2", label="/grafana,/prometheus", lhead="cluster_Monitoring") >> monitoring

    app >> Edge(minlen="2") >>redis
    app >> Edge(minlen="2") >>rabbitmq
    app >> Edge(minlen="2") >> postgresql
    app >> Edge(minlen="2") >> resolver

    worker >> Edge(minlen="2") >> redis
    worker >> Edge(minlen="2") >> rabbitmq
    worker >> Edge(minlen="2") >> postgresql
    worker >> Edge(minlen="2") >> routinator
    worker >> Edge(minlen="2") >> resolver

    beat >> Edge(minlen="2") >> rabbitmq

    worker >> target