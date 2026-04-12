# TPM + Enhanced Authorization

`tpmea` is a small Go package that provides a simple-to-use API to create and use mutable TPM policies. Mutable TPM policies allow you to store a secret in the TPM with dynamic authorization policies instead of a fixed set of policies (for example, static PCR values). The process works by binding policies with an asymmetric key and storing the key name (essentially a hash of the loaded public key object in the TPM) as the Authorization Policy Digest field of a TPM object (e.g. an NV index). Later on it is possible to read back the secret stored in the TPM object using a policy that *first* is signed with the authorization key and *second*, when evaluated in the TPM, matches the current run-time state of the system.

A common way to store secrets in the TPM is to bind a secret with a PCR policy and store it in a TPM object such that the secret is revealed only when the PCR values at run-time match the values of the known-good state stored in the TPM object. This method stores the combined hash of PCR values of the known-good state as the Authorization Policy Digest, and therefore when there is a PCR mismatch at run-time it is not possible to either read the secret or update the Authorization Policy Digest without destroying the object and losing access to its content.

This strict policy comes with a problem: for example, during a system update some PCR values might change and therefore, as expected, the TPM refuses to reveal the secret. In this scenario, using mutable policies, we can simply generate a new policy (for example with predicted PCR values that we know the system will end up with after applying the update) and sign it with the authorization key. After a system update, using the new policy we can still read back the secret as long as the new policy is validly signed by the authorization key and holds true when evaluated at runtime (meaning the predicted post-update PCR values in the policy match the current state of the system).

See the `cmd/` directory for a runnable client/server demo that exercises the full seal, unseal, counter attestation, key rotation, and read-lock lifecycle.

Although this is a standalone and independent library, more usage examples can be found in the EVE PCR Prediction repository: https://github.com/zededa/evepcr/tree/main/cmd

For more information read the documents on [usage](doc/USAGE.md) and [testing](doc/TESTING.md).
