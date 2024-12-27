#!/bin/bash

docker build -t ran .

docker run -p $(op read "op://world_site/ran_service_container_dev/port"):$(op read "op://world_site/ran_service_container_dev/port") \
    -e RAN_SERVICE_CLIENT_ID=$(op read "op://world_site/ran_service_container_dev/client_id") \
    -e RAN_SERVICE_PORT=":$(op read "op://world_site/ran_service_container_dev/port")" \
    -e RAN_CA_CERT="$(op document get "service_ca_dev_cert" --vault world_site | base64 -w 0)" \
    -e RAN_SERVER_CERT="$(op document get "ran_service_server_dev_cert" --vault world_site | base64 -w 0)" \
    -e RAN_SERVER_KEY="$(op document get "ran_service_server_dev_key" --vault world_site | base64 -w 0)" \
    -e RAN_DB_CA_CERT="$(op document get "db_ca_dev_cert" --vault world_site | base64 -w 0)" \
    -e RAN_DB_CLIENT_CERT="$(op document get "ran_db_client_dev_cert" --vault world_site | base64 -w 0)" \
    -e RAN_DB_CLIENT_KEY="$(op document get "ran_db_client_dev_key" --vault world_site | base64 -w 0)" \
    -e RAN_DATABASE_URL="$(op read "op://world_site/ran_db_dev/server"):$(op read "op://world_site/ran_db_dev/port")" \
    -e RAN_DATABASE_NAME="$(op read "op://world_site/ran_db_dev/database")" \
    -e RAN_DATABASE_USERNAME="$(op read "op://world_site/ran_db_dev/username")" \
    -e RAN_DATABASE_PASSWORD="$(op read "op://world_site/ran_db_dev/password")" \
    -e RAN_DATABASE_HMAC_INDEX_SECRET="$(op read "op://world_site/ran_hmac_index_secret_dev/secret")" \
    -e RAN_FIELD_LEVEL_AES_GCM_SECRET="$(op read "op://world_site/ran_aes_gcm_secret_dev/secret")" \
    -e RAN_S2S_JWT_SIGNING_KEY="$(op read "op://world_site/ran_jwt_key_pair_dev/signing_key")" \
    -e RAN_S2S_JWT_VERIFYING_KEY="$(op read "op://world_site/ran_jwt_key_pair_dev/verifying_key")" \
    ran:latest

