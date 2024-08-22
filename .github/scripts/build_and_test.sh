#!/bin/bash

set -x
set -e

sudo curl -Lo /usr/bin/docker-compose https://github.com/docker/compose/releases/download/v2.23.3/docker-compose-linux-x86_64
sudo chmod 755 /usr/bin/docker-compose
go run .github/scripts/prepare/main.go
sleep 20

go test tests/*.go
result=$?

go run .github/scripts/cleanup/main.go
exit $result