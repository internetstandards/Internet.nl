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

from diagrams.custom import Custom
from functools import partial

File = partial(Custom, icon_path="file.png")

# diagrams uses the Diagram name as output file name, try to make it match the .py filename as best as possible
NAME = os.path.splitext(os.path.basename(__file__))[0].replace("_", " ").capitalize()

graph_attr = {
    "splines": "true",
    "size": "12",
    "pad": "0.1",
}

with Diagram(NAME, show=False, direction="TB", outformat=["png"], graph_attr=graph_attr):
    defaults = File("defaults.env")

    with Cluster("Development"):
        develop = File("develop.env")

    with Cluster("Integration test"):
        test = File("test.env")

    local = File("local.env")

    with Cluster("Deployment"):
        host = File("host.env")

    local >> develop >> defaults
    local >> test >> defaults

    local >> host >> defaults