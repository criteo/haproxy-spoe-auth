#!/bin/bash

echo "Running agent along with dlv debugging server"
/scripts/run-with-debug.sh haproxy-spoe-auth cmd/haproxy-spoe-auth/main.go -- \
    -config /configuration/config.yml \
