#!/usr/bin/env bash
#
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Starts two software TPMs (one for the server, one for the client),
# provisions an AIK in the client TPM using tpm2-tools, launches the server,
# then runs the client demo. Everything is cleaned up on exit regardless of
# whether the demo succeeds or fails.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SERVER=${1:-"$SCRIPT_DIR/bin/tpmea-server"}
CLIENT=${2:-"$SCRIPT_DIR/bin/tpmea-client"}

SERVER_STATE=$(mktemp -d)
CLIENT_STATE=$(mktemp -d)
SERVER_SWTPM_PID=""
CLIENT_SWTPM_PID=""
SERVER_PID=""

AIK_HANDLE=0x81000003
# TCP port used only during client AIK provisioning; freed before the demo runs.
CLIENT_PROV_PORT=19721

cleanup() {
    [ -n "$SERVER_SWTPM_PID" ] && kill "$SERVER_SWTPM_PID" 2>/dev/null || true
    [ -n "$CLIENT_SWTPM_PID" ] && kill "$CLIENT_SWTPM_PID" 2>/dev/null || true
    [ -n "$SERVER_PID"        ] && kill "$SERVER_PID"        2>/dev/null || true
    rm -rf "$SERVER_STATE" "$CLIENT_STATE"
}
trap cleanup EXIT


echo "[+] starting server swtpm ..."
swtpm socket --tpm2 --flags startup-clear \
    --server type=unixio,path="$SERVER_STATE/tpm.sock" \
    --ctrl   type=unixio,path="$SERVER_STATE/tpm.ctrl" \
    --tpmstate dir="$SERVER_STATE" \
    --log file="$SERVER_STATE/swtpm.log" &
SERVER_SWTPM_PID=$!

echo "[+] starting client swtpm for AIK provisioning (TCP) ..."
swtpm socket --tpm2 --flags startup-clear \
    --server port="$CLIENT_PROV_PORT" \
    --ctrl   type=tcp,port=$(( CLIENT_PROV_PORT + 1 )) \
    --tpmstate dir="$CLIENT_STATE" \
    --log file="$CLIENT_STATE/swtpm.log" &
CLIENT_PROV_PID=$!

sleep 1

echo "[+] provisioning AIK in client TPM ..."
export TPM2TOOLS_TCTI="swtpm:host=localhost,port=$CLIENT_PROV_PORT"

tpm2 clear

# Create the AIK as a primary RSA restricted-signing key in the owner hierarchy
# and persist it at the well-known handle so the Go library can find it.
tpm2 createprimary -C o \
    -G rsa:rsassa-sha256:null \
    -g sha256 \
    -c "$CLIENT_STATE/aik.ctx" \
    -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|sign|noda'
tpm2 flushcontext -t
tpm2 evictcontrol -C o -c "$CLIENT_STATE/aik.ctx" "$AIK_HANDLE"
tpm2 flushcontext -t

# Export the AIK public key in DER format so the Go client can register it
# with the server without needing TPM access for this step.
tpm2 readpublic -c "$CLIENT_STATE/aik.ctx" -f der -o "$CLIENT_STATE/aik.der"

unset TPM2TOOLS_TCTI

echo "[+] stopping provisioning swtpm ..."
kill "$CLIENT_PROV_PID"
wait "$CLIENT_PROV_PID" 2>/dev/null || true

echo "[+] restarting client swtpm on Unix socket ..."
swtpm socket --tpm2 --flags startup-clear \
    --server type=unixio,path="$CLIENT_STATE/tpm.sock" \
    --ctrl   type=unixio,path="$CLIENT_STATE/tpm.ctrl" \
    --tpmstate dir="$CLIENT_STATE" \
    --log file="$CLIENT_STATE/swtpm.log" &
CLIENT_SWTPM_PID=$!

sleep 1

echo "[+] starting server ..."
SWTPM_PATH="$SERVER_STATE/tpm.sock" "$SERVER" --addr :8765 &
SERVER_PID=$!

sleep 1

echo "[+] running client demo ..."
echo "========================================================"
SWTPM_PATH="$CLIENT_STATE/tpm.sock" "$CLIENT" \
    --server http://localhost:8765 \
    --aik-pub "$CLIENT_STATE/aik.der"
RESULT=$?
echo "========================================================"

if [ "$RESULT" -ne 0 ]; then
    echo "[!] demo FAILED -- swtpm logs:"
    echo "--- server swtpm ---"
    cat "$SERVER_STATE/swtpm.log" 2>/dev/null || true
    echo "--- client swtpm ---"
    cat "$CLIENT_STATE/swtpm.log" 2>/dev/null || true
fi

exit "$RESULT"
