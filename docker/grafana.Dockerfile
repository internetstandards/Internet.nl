FROM grafana/grafana:9.5.2

COPY docker/grafana/dashboards/* /etc/dashboards/
COPY docker/grafana/provisioning/dashboards /etc/grafana/provisioning/dashboards
COPY docker/grafana/provisioning/datasources /etc/grafana/provisioning/datasources

