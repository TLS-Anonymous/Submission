#!/bin/bash

set -eu

cd "$(dirname "$0")"
cd certs

echo "[+] Generate certificates"
./setup.sh
cd ..

echo "[+] Build base image"
./images/baseimage/build-base.sh

echo " "
echo "To build every available docker image, or every docker image of a specific TLS Libraries, use the 'build-everything.py' script (requires python >=3.7)"
echo "To build only specific TLS Libraries, use the 'build.sh' scripts inside the subfolders of 'images/'."