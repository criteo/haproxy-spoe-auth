#!/bin/bash

dlv --listen 0.0.0.0:2345 --headless=true --output=/tmp/$1 --continue --accept-multiclient debug ${@:2}