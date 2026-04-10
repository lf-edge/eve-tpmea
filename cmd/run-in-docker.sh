#!/usr/bin/env bash
#
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Build the server and client inside a Ubuntu 22.04 container, provision two
# software TPMs, and run the demo. Dependencies (swtpm, libtpms, go) are set
# up inside the container so nothing needs to be installed on the host.
#
# Usage:
#   bash cmd/run-in-docker.sh [--no-cache]

set -e

REPO_ROOT="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
IMAGE="eve-tpmea-demo"
NO_CACHE=""

for arg in "$@"; do
    case "$arg" in
        --no-cache) NO_CACHE="--no-cache" ;;
    esac
done

echo "[+] Cleaning up any previous container ..."
docker rm -f eve-tpmea-demo 2>/dev/null || true

echo "[+] Building Docker image ($IMAGE) ..."
docker build $NO_CACHE -t "$IMAGE" -f - "$REPO_ROOT" <<'EOF'
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV GOVERSION=1.23.4

# Install Go and the tools needed to build swtpm/libtpms.
# tpm2-tools uses the TSS2 stack to talk to swtpm over a socket, so the
# distro package is sufficient - it does not link against libtpms.
RUN apt-get update -qq && \
    apt-get install -y -qq \
        curl ca-certificates git tpm2-tools \
        automake autoconf autoconf-archive libtool build-essential \
        libssl-dev libgnutls28-dev gnutls-bin libtasn1-dev \
        libjson-glib-dev libjson-c-dev libseccomp-dev \
        expect gawk net-tools socat libtirpc-dev && \
    curl -sL "https://go.dev/dl/go${GOVERSION}.linux-amd64.tar.gz" | \
        tar -C /usr/local -xz

ENV PATH="/usr/local/go/bin:${PATH}"

# Purge any distro libtpms so its headers/libraries can't shadow the one we build.
RUN apt-get remove -y --purge 'libtpms*' 2>/dev/null || true

# Build libtpms (same version as pkg/vtpm/Dockerfile in the EVE repo).
RUN git clone --branch v0.10.0 --depth 1 https://github.com/stefanberger/libtpms.git /tmp/libtpms && \
    cd /tmp/libtpms && \
    ./autogen.sh --prefix=/usr --with-tpm2 > /dev/null && \
    make -j"$(nproc)" > /dev/null && \
    make install > /dev/null && \
    ldconfig && \
    rm -rf /tmp/libtpms

# Build swtpm (same pinned commit as pkg/vtpm/Dockerfile in the EVE repo).
RUN git clone https://github.com/stefanberger/swtpm.git /tmp/swtpm && \
    cd /tmp/swtpm && \
    git checkout 732bbd6ad3a52b9552b5a1620e03a9f6449a1aab && \
    ./autogen.sh --prefix=/usr > /dev/null && \
    make -j"$(nproc)" > /dev/null && \
    make install > /dev/null && \
    rm -rf /tmp/swtpm

WORKDIR /eve-tpmea
EOF

echo "[+] Running demo inside container ..."
# Mount the repo read-only and copy it to a writable path so build artifacts
# don't land in the source tree.
docker run --rm \
    --name eve-tpmea-demo \
    -v "$REPO_ROOT:/eve-tpmea:ro" \
    "$IMAGE" \
    bash -c "cp -a /eve-tpmea /eve-tpmea-rw && cd /eve-tpmea-rw/cmd && make build && bash run-demo.sh"
