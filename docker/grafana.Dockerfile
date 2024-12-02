FROM grafana/grafana:11.3.1

COPY docker/grafana/dashboards/* /etc/dashboards/
COPY docker/grafana/provisioning/dashboards /etc/grafana/provisioning/dashboards
COPY docker/grafana/provisioning/datasources /etc/grafana/provisioning/datasources

