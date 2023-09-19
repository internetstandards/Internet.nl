FROM grafana/grafana:9.5.2

COPY docker/monitoring/grafana/dashboards/* /etc/dashboards/
COPY docker/monitoring/grafana/provisioning/dashboards /etc/grafana/provisioning/dashboards
COPY docker/monitoring/grafana/provisioning/datasources /etc/grafana/provisioning/datasources

