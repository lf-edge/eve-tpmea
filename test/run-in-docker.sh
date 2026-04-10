#!/bin/bash
#
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Run test/runtests.sh inside a Ubuntu 22.04 Docker container.
#
# Usage:
#   bash test/run-in-docker.sh [--no-cache]

set -e

REPO_ROOT="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
IMAGE="eve-tpmea-test"
NO_CACHE=""

for arg in "$@"; do
    case "$arg" in
        --no-cache) NO_CACHE="--no-cache" ;;
    esac
done

echo "[+] Cleaning up any previous container ..."
docker rm -f eve-tpmea-test 2>/dev/null || true

echo "[+] Building Docker image ($IMAGE) ..."
docker build $NO_CACHE -t "$IMAGE" -f - "$REPO_ROOT" <<'EOF'
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV GOVERSION=1.23.4

# Install Go and sudo (runtests.sh uses sudo for apt-get and build steps).
RUN apt-get update -qq && \
    apt-get install -y -qq curl ca-certificates sudo && \
    curl -sL "https://go.dev/dl/go${GOVERSION}.linux-amd64.tar.gz" | \
        tar -C /usr/local -xz && \
    echo "root ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

ENV PATH="/usr/local/go/bin:${PATH}"

WORKDIR /eve-tpmea
EOF

echo "[+] Running test/runtests.sh inside container ..."
# The repo is mounted read-only and copied to a writable path so build
# artefacts (coverage.txt, temp dirs) don't pollute the source tree.
# swtpm runs in Unix socket mode inside the container, so no --privileged
# or kernel modules are required.
docker run --rm \
    --name eve-tpmea-test \
    -v "$REPO_ROOT:/eve-tpmea:ro" \
    "$IMAGE" \
    bash -c "cp -a /eve-tpmea /eve-tpmea-rw && bash /eve-tpmea-rw/test/runtests.sh"
