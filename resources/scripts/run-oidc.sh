#!/bin/bash

echo "Running OIDC agent"
/scripts/run-agent.sh haproxy-spoe-oidc cmd/haproxy-spoe-oidc/main.go -- \
    -addr :8081 \
    -oidc-provider http://dex.example.com:9080/dex \
    -scopes "email,profile" \
    -client-id haproxy-auth \
    -client-secret haproxy-auth-secret \
    -redirect-url http://auth-oidc.example.com:9080/oauth2/callback \
    -callback-addr :5000 \
    -cookie-name authsession \
    -cookie-domain example.com \
    -cookie-unsecure \
    -signature-secret myunsecuresecret \
    -encryption-secret anotherunsecuresecret