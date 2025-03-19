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

# diagrams uses the Diagram name as output file name, try to make it match the .py filename as best as possible
NAME = os.path.splitext(os.path.basename(__file__))[0].replace("_", " ").capitalize()

graph_attr = {
    "splines": "true",
    "size": "12",
    "pad": "0.1",
}

with Diagram(NAME, show=False, direction="TB", outformat=["png"], graph_attr=graph_attr):
    webserver = Apache("webserver")

    with Cluster("Application"):
        app = Python("app")
        worker = Python("worker")
        beat = Python("beat")

    with Cluster("Services"):
        postgres = PostgreSQL("postgres")
        redis = Redis("redis")
        rabbitmq = RabbitMQ("rabbitmq")
        routinator = Container("routinator")

    with Cluster("Volumes"):
        volume_postgres = Storage("postgres")
        volume_redis = Storage("redis")
        volume_rabbitmq = Storage("rabbitmq")
        volume_routinator = Storage("routinator")
        volume_batch_results = Storage("batch_results")

    webserver >> app

    app >> Edge(minlen="3") >> postgres
    app >> Edge(minlen="3") >>redis
    app >> Edge(minlen="3") >>rabbitmq
    app >> Edge(minlen="3") >>routinator

    worker >> Edge(minlen="3") >> postgres
    worker >> Edge(minlen="3") >> redis
    worker >> Edge(minlen="3") >> rabbitmq
    worker >> Edge(minlen="3") >> routinator

    beat >> Edge(minlen="3") >> postgres
    beat >> Edge(minlen="3") >> redis
    beat >> Edge(minlen="3") >> rabbitmq
    beat >> Edge(minlen="3") >> routinator

    postgres >> Edge(minlen="3") >> volume_postgres
    redis >> Edge(minlen="3") >> volume_redis
    rabbitmq >> Edge(minlen="3") >> volume_rabbitmq
    routinator >> Edge(minlen="3") >> volume_routinator
    app >> Edge(minlen="3") >> volume_batch_results
    worker >> Edge(minlen="3") >> volume_batch_results



#
# nwdiag {
#   network internal {
#       address = "192.168.42.0/24, fd00:42:1::/48"
#
#       webserver [address = "192.168.42.102, fd00:42:1::100"];
#
#       app [address = "192.168.42.103"];
#       worker [address = "192.168.42.x"];
#       beat [address = "192.168.42.x"];
#
#       redis [address = "192.168.42.x"];
#       rabbitmq [address = "192.168.42.x"];
#       postgres [address = "192.168.42.x"];
#
#       routinator [address = "192.168.42.105"];
#
#       unbound [address = "192.168.42.104, fd00:42:1::101"];
#
#       # monitoring
#       statsd [address = "192.168.42.106"];
#
#       statsd [address = "192.168.42.50"];
#
#   }
#   network public-internet {
#       address = "172.16.42.0/24";
#
#       webserver [address = "172.x.x.1"];
#       web02 [address = "172.x.x.2"];
#       db01;
#       db02;
#   }
# }
