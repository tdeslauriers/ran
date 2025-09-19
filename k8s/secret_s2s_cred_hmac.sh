#!/bin/bash

# variables
NAMESPACE="world"
SECRET_NAME="secret-s2s-cred-hmac"

# get db secrets from 1Password
HMAC_SECRET_CREDS_SERVICE=$(op read "op://world_site/ran_hmac_auth_secret_prod/secret")

# check if values are retrieved successfully
if [[ -z "$HMAC_SECRET_CREDS_SERVICE"  ]]; then
  echo "Error: failed to get ran cred service hmac secret from 1Password."
  exit 1
fi

# create the db secret
kubectl create secret generic $SECRET_NAME \
  --namespace $NAMESPACE \
  --from-literal=hmac-auth-pepper="$$HMAC_SECRET_CREDS_SERVICE" \
  --dry-run=client -o yaml | kubectl apply -f -
