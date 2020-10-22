#!/bin/bash
set -e

DOCKER_APP=example-jwt-graalvm
./gradlew clean build

docker build . -t $DOCKER_APP

