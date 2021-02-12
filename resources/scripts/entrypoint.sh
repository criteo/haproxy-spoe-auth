#!/bin/bash

set -x

go get github.com/go-delve/delve/cmd/dlv

reflex -r '(\.go$|go\.mod|\.sh)' -s -- $*