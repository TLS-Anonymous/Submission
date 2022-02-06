#!/bin/bash
cd "$(dirname "$0")" || exit 1
source ../helper-functions.sh
#Builds Container with Compilerenv. !

array=(release-3.1.2)
typeset -i i=0 max=${#array[*]}

while (( i < max ))
do
	echo "Feld $i: python-gnutls-${array[$i]}"
	_docker build --build-arg VERSION=${array[$i]} -t ${DOCKER_REPOSITORY}python_gnutls-server:${array[$i]} -f Dockerfile .
	i=i+1
done

exit "$EXITCODE"
