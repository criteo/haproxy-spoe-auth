#!/bin/bash

go build -mod=vendor -o /tmp/haproxy-ldap-auth . && /tmp/haproxy-ldap-auth -userdn ${USERDN} -password ${PASSWORD}