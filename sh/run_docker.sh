#!/bin/bash

set -euo pipefail

IMAGE_NAME="ran:latest"
CONTAINER_NAME="ran-dev"

docker build --pull --no-cache -t "${IMAGE_NAME}" .

docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true

docker run -d --rm \
    --name "${CONTAINER_NAME}" \
    -p "${RAN_SERVICE_PORT: -4}":"${RAN_SERVICE_PORT: -4}" \
    -e RAN_SERVICE_CLIENT_ID \
    -e RAN_SERVICE_PORT \
    -e RAN_CA_CERT \
    -e RAN_SERVER_CERT \
    -e RAN_SERVER_KEY \
    -e RAN_DB_CA_CERT \
    -e RAN_DB_CLIENT_CERT \
    -e RAN_DB_CLIENT_KEY \
    -e RAN_DATABASE_URL \
    -e RAN_DATABASE_PORT \
    -e RAN_DATABASE_NAME \
    -e RAN_DATABASE_USERNAME \
    -e RAN_DATABASE_PASSWORD \
    -e RAN_DATABASE_HMAC_INDEX_SECRET \
    -e RAN_FIELD_LEVEL_AES_GCM_SECRET \
    -e RAN_PAT_PEPPER \
    -e RAN_S2S_JWT_SIGNING_KEY \
    -e RAN_S2S_JWT_VERIFYING_KEY \
    -e RAN_USER_JWT_VERIFYING_KEY \
    -e RAN_HMAC_S2S_AUTH_SECRET \
    "${IMAGE_NAME}"