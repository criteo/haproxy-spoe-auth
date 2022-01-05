#!/bin/bash

set -x

reflex -r '(\.go$|go\.mod|\.sh|\.yaml|\.yml)' -s -- $*