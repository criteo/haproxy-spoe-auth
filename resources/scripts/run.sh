#!/bin/bash

if [[ "$DEBUG_ENABLED" -eq "1" ]]
then
    echo "Running agent along with debug server"
    /scripts/run-with-debug.sh haproxy-spoe-auth cmd/haproxy-spoe-auth/main.go -- \
        -config /configuration/config.yml
else
    while true
    do
        echo "Running agent without debug server"
        go run cmd/haproxy-spoe-auth/main.go -config /configuration/config.yml
        sleep 2
    done
fi