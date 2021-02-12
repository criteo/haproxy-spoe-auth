#!/bin/bash

echo "Running LDAP agent"
/scripts/run-agent.sh haproxy-spoe-ldap cmd/haproxy-spoe-ldap/main.go -- \
    -addr :8081 \
    -ldap-url ldap \
    -ldap-userdn cn=admin,dc=example,dc=com \
    -ldap-password password \
    -ldap-base-dn dc=example,dc=com \
    -ldap-user-filter "(cn={login})"