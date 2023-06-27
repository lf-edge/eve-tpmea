#!/usr/bin/env bash
# there is no tpm_vtpm_proxy, so qemu to the rescue...
# this script is hacky but it works.

sudo apt-get -qq update -y > /dev/null && sudo apt-get -qq install cloud-image-utils qemu swtpm wget libguestfs-tools -y > /dev/null

echo "[+] Downloading the ubuntu qemu image..."
img=ubuntu-18.04-server-cloudimg-amd64.img
if [ ! -f "$img" ]; then
  wget -q "https://cloud-images.ubuntu.com/releases/18.04/release/${img}"
  qemu-img resize "$img" +128G > /dev/null
fi

echo "[+] Setting up image credentials..."
ssh-keygen -q -N '' -f id_rsa
sudo virt-customize --ssh-inject "root:file:id_rsa.pub" --root-password password:whocares -a ${img} > /dev/null

# I need this for some reasons
cat >user-data <<EOF
#cloud-config
chpasswd: { expire: False }
ssh_pwauth: True
EOF

cloud-localds user-data.img user-data

echo "[+] Preparing swtpm..."
mkdir /tmp/emulated_tpm
swtpm socket --tpmstate dir=/tmp/emulated_tpm --ctrl type=unixio,path=/tmp/emulated_tpm/swtpm-sock --log level=20 --tpm2 -d

echo "[+] Launching the vm..."
qemu-system-x86_64 \
  -drive "file=${img},format=qcow2" \
  -drive "file=user-data.img,format=raw" \
  -device rtl8139,netdev=net0 \
  -netdev user,id=net0,hostfwd=tcp::2222-:22 \
  -chardev socket,id=chrtpm,path="/tmp/emulated_tpm/swtpm-sock" \
  -tpmdev emulator,id=tpm0,chardev=chrtpm \
  -device tpm-tis,tpmdev=tpm0 \
  -m 2G \
  -smp 4 \
  -display none -daemonize

echo "[+] Waiting for vm to start..."
ssh -q -i id_rsa root@localhost -p 2222 -o "StrictHostKeyChecking no" 'mkdir tpmea'
while test $? -gt 0
do
  sleep 5
  echo "[+] Waiting for vm to start..."
  ssh -q -i id_rsa root@localhost -p 2222 -o "StrictHostKeyChecking no" 'mkdir tpmea'
done

echo "[+] Copying tests to vm ..."
scp -q -i id_rsa -P 2222 -o "StrictHostKeyChecking no" *.{go,mod,sum} root@localhost:/root/tpmea

echo "[+] Preparing go tests ..."
ssh -q -i id_rsa root@localhost -p 2222 -o "StrictHostKeyChecking no"  << EOF
  wget -q https://go.dev/dl/go1.20.5.linux-amd64.tar.gz
  rm -rf /usr/local/go && tar -C /usr/local -xzf go1.20.5.linux-amd64.tar.gz
EOF

echo "[+] Running tests ..."
ssh -i id_rsa root@localhost -p 2222 -o "StrictHostKeyChecking no" 'cd /root/tpmea && /usr/local/go/bin/go test -v'
