#!/bin/bash

set -e

BUILD_SH="$(readlink -f "${BASH_SOURCE[0]:-$0}")"
BUILD_DIR="$(dirname "$BUILD_SH")/../src"
sudo apt-get -yq update && sudo apt-get -yq install clang-19 g++14
cd $BUILD_DIR
make clean && make
