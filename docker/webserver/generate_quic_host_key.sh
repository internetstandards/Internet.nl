#!/usr/bin/env sh

# See https://nginx.org/en/docs/http/ngx_http_v3_module.html#quic_host_key
#    Sets a file with the secret key used to encrypt stateless reset and address validation tokens.
#    By default, a random key is generated on each reload. Tokens generated with old keys are not accepted.

# The default NGX_QUIC_DEFAULT_HOST_KEY_LEN is 32 bytes (ngx_event_quic.h)
# This script updates it on restart of the container, which is not too frequent,
# but persists it access reloads, which happen for certbot, user change, and
# possibly other reasons.

openssl rand 32 > /etc/nginx/quic_host.key
