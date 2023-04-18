FROM prom/prometheus:v2.44.0

COPY docker/monitoring/prometheus/prometheus.yaml /prometheus.yaml

