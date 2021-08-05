#!/bin/bash

dlv --listen 0.0.0.0:2345 --headless=true --output=/tmp/$1 --continue --api-version 2 --accept-multiclient debug ${@:2}