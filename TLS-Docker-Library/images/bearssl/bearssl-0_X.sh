#!/bin/bash
cd "$(dirname "$0")" || exit 1
source ../helper-functions.sh

versions=(0.4 0.5 0.6)
for i in "${versions[@]}"; do
    _docker build --build-arg VERSION=${i} -t ${DOCKER_REPOSITORY}bearssl-server:${i} -f Dockerfile-0_x --target bearssl-server .
    _docker build --build-arg VERSION=${i} -t ${DOCKER_REPOSITORY}bearssl-client:${i} -f Dockerfile-0_x --target bearssl-client .
done

exit "$EXITCODE"
