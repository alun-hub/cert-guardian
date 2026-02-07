#!/bin/sh
set -e

CERT_FILE="/etc/nginx/certs/tls.crt"
KEY_FILE="/etc/nginx/certs/tls.key"

if [ -f "$CERT_FILE" ] && [ -f "$KEY_FILE" ]; then
    echo "TLS certificates found, enabling HTTPS configuration."
    cp /etc/nginx/templates/nginx-https.conf /etc/nginx/conf.d/default.conf
else
    echo "No TLS certificates found, using HTTP-only configuration."
    cp /etc/nginx/templates/nginx-http.conf /etc/nginx/conf.d/default.conf
fi

exec "$@"
