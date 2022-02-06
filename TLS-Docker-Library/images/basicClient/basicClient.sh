#!/bin/bash
cd "$(dirname "$0")" || exit 1
source ../helper-functions.sh

_docker build -t basic-client:latest -f Dockerfile .

exit "$EXITCODE"
