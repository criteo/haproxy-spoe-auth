#!/bin/bash

set -x

reflex -r '(\.go$|go\.mod)' -s -- $*