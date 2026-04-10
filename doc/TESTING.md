# Testing

The simplest way to run the tests is with the provided Docker script, which handles all dependencies (swtpm, libtpms, tpm2-tools) automatically:

```bash
bash test/run-in-docker.sh
```

This builds a Ubuntu 22.04 container, compiles swtpm from source, provisions a software TPM, and runs the full test suite. No kernel modules or host-side TPM tooling are required. Pass `--no-cache` to force a clean image build:

```bash
bash test/run-in-docker.sh --no-cache
```
