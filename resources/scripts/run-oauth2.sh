#!/bin/bash

echo "Running OAuth2 agent"
/scripts/run-agent.sh haproxy-spoe-oauth2 cmd/haproxy-spoe-oauth2/main.go -- \
    -addr :8081 \
    -authorization-url http://dex.example.com:9080/dex/auth \
    -token-url http://dex.example.com:9080/dex/token \
    -scopes "openid,email,profile" \
    -client-id haproxy-auth \
    -client-secret haproxy-auth-secret \
    -redirect-url http://auth-oauth2.example.com:9080/oauth2/callback \
    -callback-addr :5000 \
    -cookie-name authsession \
    -cookie-domain example.com \
    -cookie-unsecure \
    -signature-secret myunsecuresecret