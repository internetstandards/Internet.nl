from diagrams import Diagram, Cluster, Edge

from diagrams.oci.compute import Container
from diagrams.programming.language import Python
from diagrams.onprem.database import PostgreSQL
from diagrams.onprem.queue import  RabbitMQ
from diagrams.onprem.inmemory import Redis
from diagrams.onprem.network import Apache, Nginx
from diagrams.onprem.client import Users
from diagrams.generic.storage import Storage

with Diagram("Development Environment", show=False, direction="TB"):
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

    worker >> postgres
    worker >> redis
    worker >> rabbitmq
    worker >> routinator

    beat >> postgres
    beat >> redis
    beat >> rabbitmq
    beat >> routinator

    postgres >> volume_postgres
    redis >> volume_redis
    rabbitmq >> volume_rabbitmq
    routinator >> volume_routinator
    app >> volume_batch_results
    worker >> volume_batch_results



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
#       address = "172.42.0.0/16";
#
#       webserver [address = "172.x.x.1"];
#       web02 [address = "172.x.x.2"];
#       db01;
#       db02;
#   }
# }