import os.path

from diagrams import Diagram, Cluster, Edge

from diagrams.oci.compute import Container
from diagrams.onprem.monitoring import Grafana, Prometheus
from diagrams.onprem.database import PostgreSQL
from diagrams.onprem.inmemory import Redis
from diagrams.programming.framework import Django

from diagrams.custom import Custom
from functools import partial

DockerHub = partial(Custom, icon_path="dockerhub.png")
File = partial(Custom, icon_path="file.png")
Image = Container
Settings = Container
Packages = Container
Stage = Container


# diagrams uses the Diagram name as output file name, try to make it match the .py filename as best as possible
NAME = os.path.splitext(os.path.basename(__file__))[0].replace("_", " ").capitalize()

graph_attr = {
    "splines": "true",
}

with Diagram(NAME, show=False, direction="LR", outformat=["png"], graph_attr=graph_attr):
    with Cluster("util.Dockerfile"):
        [
            DockerHub("alpine"),
            File("cron/periodic/*"),
            File("cron-docker/periodic/*"),
            File("deploy.sh"),
            File("compose.yaml,defaults.env,host-dist.env"),
        ] >> Image("ghcr.io/internetstandards/util")

    with Cluster("grafana.Dockerfile"):
        [
            DockerHub("grafana/grafana"),
            File("monitoring/grafana/*"),
        ] >> Image("ghcr.io/internetstandards/grafana")

    with Cluster("test-runner.Dockerfile"):
        [
            DockerHub("mcr.microsoft.com/playwright/python"),
            Packages("pytest/pytest-playwright/debug tools/docker cli"),
            File("intergration_tests/*"),
        ] >> Image("ghcr.io/internetstandards/test-runner")

    with Cluster("webserver.Dockerfile"):
        [
            DockerHub("_/nginx"),
            Packages("htpasswd"),
            Packages("certbot"),
            File("webserver/authentication.sh,webserver/tls_init.sh"),
            File("webserver/nginx_templates"),
            File("robots.txt,.well-known/security.txt,favicon.ico"),
            File("certbot/entrypoint.sh"),
        ] >> Image("ghcr.io/internetstandards/webserver")

with Diagram("Dockerfile", show=False, direction="LR", outformat=["png"], graph_attr=graph_attr):
    with Cluster("Dockerfile"):
        with Cluster("hub.docker.com"):
            source_image = DockerHub("_/debian"),

        vendor_unbound = File("vendor/unbound")
        vendor_openssl = File("vendor/openssl-*")
        requirements = File("requirements.txt")
        requirements_dev = File("requirements-dev.txt")
        unbound_zones = File("unbound/test-ns*.zone")
        unbound_entrypoint = File("unbound/entrypoint.sh")
        unbound_config = File("unbound/unbound.conf.template")
        worker_entrypoint = File("worker/entrypoint.sh")
        application_sources = File("bin\nmanage.py\nchecks\nfrontend\ninterface\ninternetnl\ntranslations\nremote_data\nassets")

        unbound_dependencies = Packages("unbound dependencies")
        python_dependencies = Packages("python\nunbound dependencies\ndebug tools")
        tools_dependencies = Packages("git/make/pip")

        with Cluster("Stages"):
            build_deps = Stage("build-deps")
            build_unbound = Stage("build-unbound")
            build_nassl = Stage("build-nassl")
            build_app_deps = Stage("build-app-deps")
            build_linttest_deps = Stage("build-linttest-deps")
            build_app = Stage("build-app")

        with Cluster("Output images"):
            image_internetnl = Image("ghcr.io/internetstandards/internet.nl")
            image_linttest = Image("ghcr.io/internetstandards/linttest")
            image_unbound = Image("ghcr.io/internetstandards/unbound")

        source_image >> build_deps

        build_deps >> build_unbound
        vendor_unbound >> build_unbound

        build_deps >> build_nassl
        vendor_openssl >> build_nassl

        build_deps >> build_app_deps
        requirements >> build_app_deps

        build_app_deps >> build_linttest_deps
        requirements_dev >> build_linttest_deps

        source_image >> image_unbound
        build_unbound >> Edge(label="/opt/unbound") >>  image_unbound
        unbound_dependencies >>  image_unbound
        unbound_zones >>  image_unbound
        unbound_entrypoint >>  image_unbound
        unbound_config >>  image_unbound

        source_image >> build_app
        python_dependencies >>  build_app
        build_unbound >> Edge(label="/opt/unbound") >>  build_app
        build_unbound >> Edge(label="/usr/lib/python3/dist-packages/*unbound*") >>  build_app
        worker_entrypoint >>  build_app
        application_sources >> build_app

        build_app >> image_internetnl

        build_app >> image_linttest
        build_linttest_deps >> Edge(label="dev dependencies") >>  image_linttest
        tools_dependencies >> image_linttest
