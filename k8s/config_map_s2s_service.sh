#!/bin/bash

# Set the namespace and ConfigMap name
NAMESPACE="world"
CONFIG_MAP_NAME="cm-s2s-service"

# get url, port, and client id from 1password
S2S_AUTH_URL=$(op read "op://world_site/ran_service_container_prod/url")
S2S_AUTH_PORT=$(op read "op://world_site/ran_service_container_prod/port")
S2S_AUTH_CLIENT_ID=$(op read "op://world_site/ran_service_container_prod/client_id")

# validate values are not empty
if [[ -z "$S2S_AUTH_URL" || -z "$S2S_AUTH_PORT" || -z "$S2S_AUTH_CLIENT_ID" ]]; then
  echo "Error: failed to get s2s config vars from 1Password."
  exit 1
fi

# generate cm yaml and apply
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: $CONFIG_MAP_NAME
  namespace: $NAMESPACE
data:
  s2s-auth-url: "$S2S_AUTH_URL:$S2S_AUTH_PORT"
  s2s-auth-port: ":$S2S_AUTH_PORT"
  s2s-auth-client-id: "$S2S_AUTH_CLIENT_ID"
EOF

