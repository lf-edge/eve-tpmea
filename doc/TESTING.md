# Testing and Development
Testing can be done on emulated TPM, on ubuntu you can emulate a TPM by first installing swtpm and (optionally for debugging) tpm2-tools:

```bash
sudo apt-get install swtpm tpm2-tools
```

For the emulation, first load the `tpm_vtpm_proxy`:

```bash
sudo modprobe tpm_vtpm_proxy
```

Next install and compile the linux-vtpm-tests, `vtpmctrl` is required to glue `swtpm` and `tpm_vtpm_proxy` and created TPM char devices:

```bash
git clone https://github.com/stefanberger/linux-vtpm-tests.git
cd linux-vtpm-tests
./bootstrap.sh
./configure
make
```

Finally emulate the TPM:

```bash
vtpmctrl --tpm2 --spawn /bin/swtpm chardev --tpm2 --fd %fd --tpmstate dir=/tmp --flags not-need-init --locality allow-set-locality
```

You should see the TPM device available:

```bash
~$ ls /dev/tpm*
/dev/tpm0  /dev/tpmrm0
```

now you can simply run the `tpmea` tests by invoking `go test -v`.