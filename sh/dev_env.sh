#!/bin/bash

# Service client id and port
export RAN_SERVICE_CLIENT_ID=$(op read "op://world_site/ran_service_container_dev/client_id")
export RAN_SERVICE_PORT=":$(op read "op://world_site/ran_service_container_dev/port")"

# certs
export RAN_CA_CERT=$(op document get "service_ca_dev_cert" --vault world_site | base64 -w 0)

export RAN_SERVER_CERT=$(op document get "ran_service_server_dev_cert" --vault world_site | base64 -w 0)
export RAN_SERVER_KEY=$(op document get "ran_service_server_dev_key" --vault world_site | base64 -w 0)

export RAN_DB_CA_CERT=$(op document get "db_ca_dev_cert" --vault world_site | base64 -w 0)

export RAN_DB_CLIENT_CERT=$(op document get "ran_db_client_dev_cert" --vault world_site | base64 -w 0)
export RAN_DB_CLIENT_KEY=$(op document get "ran_db_client_dev_key" --vault world_site | base64 -w 0)

# Database connection details + creds
export RAN_DATABASE_URL=$(op read "op://world_site/ran_db_dev/server"):$(op read "op://world_site/ran_db_dev/port")
export RAN_DATABASE_NAME=$(op read "op://world_site/ran_db_dev/database")
export RAN_DATABASE_USERNAME=$(op read "op://world_site/ran_db_dev/username")
export RAN_DATABASE_PASSWORD=$(op read "op://world_site/ran_db_dev/password")

# HMAC key for blind index fields in database
export RAN_DATABASE_HMAC_INDEX_SECRET=$(op read "op://world_site/ran_hmac_index_secret_dev/secret")

# Field level encryption key for database fields
export RAN_FIELD_LEVEL_AES_GCM_SECRET=$(op read "op://world_site/ran_aes_gcm_secret_dev/secret")

export RAN_PAT_PEPPER=$(op read "op://world_site/ran_pat_pepper_secret_dev/secret")

# client/s2s JWT signing key --> sign the jwt and provide verifying key to validate the jwt to client services
export RAN_S2S_JWT_SIGNING_KEY=$(op read "op://world_site/ran_jwt_key_pair_dev/signing_key")
export RAN_S2S_JWT_VERIFYING_KEY=$(op read "op://world_site/ran_jwt_key_pair_dev/verifying_key")

# user JWT verifying key -->  validate the the user's jwt
export RAN_USER_JWT_VERIFYING_KEY=$(op read "op://world_site/shaw_jwt_key_pair_dev/verifying_key")

export RAN_HMAC_S2S_AUTH_SECRET=$(op read "op://world_site/ran_hmac_auth_secret_dev/secret")


