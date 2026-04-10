#!/usr/bin/env bash
#
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#

set -e

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TPM_STATE=$(mktemp -d)
EVE_TPM_SRV="$TPM_STATE/srv.sock"
EVE_TPM_CTRL="$TPM_STATE/ctrl.sock"
SWTPM_PID=""

cleanup() {
    [ -n "$SWTPM_PID" ] && kill "$SWTPM_PID" 2>/dev/null || true
    rm -rf "$TPM_STATE"
}
trap cleanup EXIT

echo "[+] Installing build dependencies and tpm2-tools ..."
export DEBIAN_FRONTEND=noninteractive
sudo -E apt-get -qq update -y > /dev/null
sudo -E apt-get install -y -qq -o Dpkg::Options::="--force-confdef" \
    curl git tpm2-tools automake autoconf autoconf-archive libtool \
    build-essential libssl-dev libgnutls28-dev gnutls-bin libtasn1-dev \
    libjson-glib-dev libjson-c-dev libseccomp-dev expect gawk net-tools \
    socat libtirpc-dev > /dev/null

# Purge any distro libtpms so its libraries can't shadow the one we build.
sudo -E apt-get remove -y -qq --purge 'libtpms*' > /dev/null 2>&1 || true

# Build libtpms, same version as pkg/vtpm/Dockerfile in the EVE repo.
echo "[+] Building libtpms v0.10.0 from source ..."
LIBTPMS_BUILD=$(mktemp -d)
git clone --branch v0.10.0 --depth 1 https://github.com/stefanberger/libtpms.git "$LIBTPMS_BUILD"
cd "$LIBTPMS_BUILD"
./autogen.sh --prefix=/usr --with-tpm2 > /dev/null
make -j "$(getconf _NPROCESSORS_ONLN)" > /dev/null
sudo make install > /dev/null
sudo ldconfig

# Build swtpm, same pinned commit as pkg/vtpm/Dockerfile in the EVE repo.
echo "[+] Building swtpm from source (commit 732bbd6) ..."
SWTPM_BUILD=$(mktemp -d)
git clone https://github.com/stefanberger/swtpm.git "$SWTPM_BUILD"
cd "$SWTPM_BUILD"
git checkout 732bbd6ad3a52b9552b5a1620e03a9f6449a1aab
./autogen.sh --prefix=/usr > /dev/null
make -j "$(getconf _NPROCESSORS_ONLN)" > /dev/null
sudo make install > /dev/null


# swtpm setup via TCP socket (for tpm2-tools during provisioning)
TPM_SRV_PORT=1337
TPM_CTR_PORT=$((TPM_SRV_PORT + 1))
EK_HANDLE=0x81000001
SRK_HANDLE=0x81000002
AIK_HANDLE=0x81000003
ECDH_HANDLE=0x81000005

flushtpm() {
    tpm2 flushcontext -t
    tpm2 flushcontext -l
    tpm2 flushcontext -s
}

echo "[+] swtpm version and capabilities:"
swtpm --version
swtpm socket --tpm2 --print-capabilities
echo "========================================================"

# start swtpm on a TCP port for provisioning with tpm2-tools.
swtpm socket --tpm2 \
    --server port="$TPM_SRV_PORT" \
    --ctrl type=tcp,port="$TPM_CTR_PORT" \
    --tpmstate dir="$TPM_STATE" \
    --flags startup-clear &
PID=$!

# point tpm2-tools at the TCP socket.
export TPM2TOOLS_TCTI="swtpm:host=localhost,port=$TPM_SRV_PORT"

tpm2 clear

# create EK
printf '\x83\x71\x97\x67\x44\x84\xb3\xf8\x1a\x90\xcc\x8d\x46\xa5\xd7\x24\xfd\x52\xd7\x6e\x06\x52\x0b\x64\xf2\xa1\xda\x1b\x33\x14\x69\xaa' > "$TPM_STATE/ek_policy.bin"
tpm2 createprimary -C e -G rsa2048:aes128cfb -g sha256 -c ek.ctx \
    -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|decrypt' \
    -L "$TPM_STATE/ek_policy.bin"
flushtpm

# create a self-signed EK cert and store it in the standard EK cert NV index (0x01C00002)
EK_CERT_HANDLE=0x01C00002
EK_CERT_FILE="$TPM_STATE/ek_test.cert.der"
openssl req -x509 -newkey rsa:2048 -keyout "$TPM_STATE/ek_test.key" \
    -out "$TPM_STATE/ek_test.cert.pem" \
    -days 365 -nodes -subj "/CN=Test EK Cert/" 2>/dev/null
openssl x509 -in "$TPM_STATE/ek_test.cert.pem" -outform DER -out "$EK_CERT_FILE"
EK_CERT_SIZE=$(wc -c < "$EK_CERT_FILE")
tpm2 nvdefine $EK_CERT_HANDLE -C o -s "$EK_CERT_SIZE" -a "authread|ownerwrite"
tpm2 nvwrite $EK_CERT_HANDLE -C o -i "$EK_CERT_FILE"
flushtpm

# create SRK
tpm2 createprimary -C o -G rsa2048:aes128cfb -g sha256 -c srk.ctx \
    -a 'restricted|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth'
flushtpm

# create AIK
tpm2 createprimary -C o -G rsa:rsassa-sha256:null -g sha256 -c aik.ctx \
    -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|sign|noda'
flushtpm

# create ECDH key
tpm2 createprimary -C o -G ecc256:ecdh-sha256 -c ecdh.ctx \
    -a 'noda|decrypt|sensitivedataorigin|userwithauth'
flushtpm

# persist EK, SRK, AIK, ECDH
tpm2 evictcontrol -C o -c ek.ctx   $EK_HANDLE;  flushtpm
tpm2 evictcontrol -C o -c srk.ctx  $SRK_HANDLE; flushtpm
tpm2 evictcontrol -C o -c aik.ctx  $AIK_HANDLE; flushtpm
tpm2 evictcontrol -C o -c ecdh.ctx $ECDH_HANDLE; flushtpm

rm ek.ctx srk.ctx aik.ctx ecdh.ctx

# done with provisioning; stop the TCP swtpm.
kill $PID
unset TPM2TOOLS_TCTI

# restart swtpm on a Unix socket for the Go tests, the Go tests connect 
# via the Unix socket path in SWTPM_SERVER_PATH.
swtpm socket --tpm2 \
    --flags startup-clear \
    --server type=unixio,path="$EVE_TPM_SRV" \
    --ctrl type=unixio,path="$EVE_TPM_CTRL" \
    --tpmstate dir="$TPM_STATE" \
    --log file="$TPM_STATE/swtpm.log" &
SWTPM_PID=$!

# give swtpm a moment to bind the socket.
sleep 1

# run the Go tests
cd "$REPO_ROOT"
echo "[+] Running tests ..."
echo "========================================================"

export SWTPM_SERVER_PATH="$EVE_TPM_SRV"

set +e
go test -v -coverprofile="coverage.txt" -covermode=atomic ./...
RESULT=$?

if [ "$RESULT" -ne 0 ]; then
    echo "[!] Tests FAILED - swtpm log:"
    cat "$TPM_STATE/swtpm.log" 2>/dev/null || true
fi

exit "$RESULT"
