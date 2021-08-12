#!/bin/bash

go run .github/scripts/prepare/main.go
sleep 20

go test tests/*.go
result=$?

go run .github/scripts/cleanup/main.go
exit $result