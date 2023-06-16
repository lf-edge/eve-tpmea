# TPM + Enhanced Authorization
The `tmpea` is a  small go package that provides simple to use API to create and use mutable TPM policies. Mutable TPM policies allow you to store a secret in TPM with dynamic authorization policies instead of a fixed set of policies (for example static PCR values). The process work by binding polices with a asymmetric key and storing the key name (basically a hash the loaded public key object in TPM) as the Authorization Policy Digest filed of a TPM object (e.g. NV Index). Later on it is possible to read back the secret stored in the TPM object, using a policy that first) is signed with the authorization key and second) when evaluated in the TPM, it matches the current run-time state of the system.

A common scenario is to bind a secret with a PCR policy and store in TPM object, meaning that secret is revealed only when PCR values at run-time match the value of the good-know-state that is store the TPM object. This method stores the combined hash of PCR values of the good-know-state as the Authorization Policy Digest and therefore when there is PCR mismatch at run-time, it is not possible to neither read the secret nor update Authorization Policy Digest without destroying the object and losing access to its content.

A common use-case for dynamic polices is the when system gets updated, as a result some PCR values might change and therefore as expected TPM refuses to reveal the secret. In this scenario using mutable policies, we can simply generate a new policy (for example with predicted PCR values that we know system will end up with, after applying the update) and sign it with the authorization key. After a system update, using the new policy we can still read back the secret as long as the new policy is validly signed by the authorization key and holds true when evaluated at runtime, meaning predicted update PCR values in the policy match the current state of the system. 

## Usage
The modules relies on APIs from go-tpm2 packages, that are not yet part of any release, so make sure to use the master.

```
go get github.com/canonical/go-tpm2@master
go mod tidy
```

### Generating Mutable Policies
On client side, in the on-boarding process (assumed to be secure) first create a monotonic counter and report back the index and the initial value of the counter to the server (or attester, challenger or whatever you want to call it), it is possible to not define a counter and not use the rollback protection, but is highly discouraged :

```go
counter, err := DefineMonotonicCounter(0x1500017)
```

In the server-side, create a Authorization Digest, when storing the secret in TPM at the client-side this value is used as the Authorization Digest Policy of the TPM object that holds the secret.

```go
key, _ := GenKeyPair()
authorizationDigest, err := GenerateAuthDigest(&key.PublicKey)
```

Then create a policy for the secret, in this example the policy is created using know values of PCRs 0 to 2 (these values can be reported from the client in the on-boarding process or be know before-hand) and the counter value of 1. Every time the policy is updated, the counter value must be increased both in the server side policy and in the client side after applying the new policy:

```go
sealingPcrs := []PCR{{Index: 0, Digest: []byte{0x20, 0x65, ..., 0x65}},
    {Index: 1, Digest: []byte{0x57, 0x40, ..., 0x20}},
    {Index: 2, Digest: []byte{0x75, 0xDE, ..., 0x69,}}}
pcrsList := PCRList{Algo: AlgoSHA256, Pcrs: sealingPcrs}
rbp := RBP{Counter: 0x1500017, Check: 1}

approvedPolicy, approvedPolicySignature, err := GenerateSignedPolicy(key, pcrsList, rbp)
```

Server should send the `authorizationDigest`, `approvedPolicy`, `approvedPolicySignature` and `key.PublicKey` to the client. After receiving these values, the client should seal the secret into TPM:

```go
secret := []byte("THIS_IS_VERY_SECRET")
err = SealSecret(0x1500016, authorizationDigest, secret)
```

For subsequent unsealing the secret, by providing the PCR indexes and expected value of rbp counter, client simply asks for reconstruction of  the policy for evaluation at run-time and uses `key.PublicKey` `approvedPolicy` and `approvedPolicySignature` to read the secret.

```go
rbp := RBP{Counter: 0x1500017, Check: 1}
readSecret, err := UnsealSecret(0x1500016,
    &key.PublicKey,
    approvedPolicy,
    approvedPolicySignature,
    []int{0, 1, 2}, // pcr indexes to be evaluated
    rbp) // rbp counter to be evaluated
```

### Updating a Policy
For updating a policy, similar procedure is used. Server simply creates a new policy and sends it to the client:
```go
sealingPcrs := []PCR{{Index: 0, Digest: []byte{0x67, 0x65, ..., 0x65}},
    {Index: 1, Digest: []byte{0x6f, 0x6c, ..., 0x20}},
    {Index: 2, Digest: []byte{0x52, 0x6f, ..., 0x69,}}}
pcrsList := PCRList{Algo: AlgoSHA256, Pcrs: sealingPcrs}
rbp := RBP{Counter: 0x1500017, Check: 2}

approvedPolicy, approvedPolicySignature, err := GenerateSignedPolicy(key, pcrsList, rbp)
```

Please notice while generating the policy, the `Check` variable for rollback protection is updated to render any old (but still valid) policies useless. It is duty of the client to increase the counter value to match the value in the policy after receiving a new valid policy :

```go
counter, err = IncreaseMonotonicCounter(0x1500017)
```

Client should be able to read back the secret with a new policy that matches the new system state.

### Rotating Signing Key
To rotate the signing key, using the old key, sign the new key and generate a new Authorization Digest based on the new key and send the `newKey.PublicKey`, `newAuthDigest` and `approvedPolicyNewSig` to the client.

```go
newKey, _ := GenKeyPair()
newkeySig, newAuthDigest, approvedPolicyNewSig, err := RotateAuthDigestWithPolicy(oldKey, newKey, pcrs, rbp)
```

 After receiving the new key and signature, by calling `ResealSecretWithNewAuthDigest` client verifiers the new key is signed with the old key and then reseals the secret using the new Authorization Digest which is bound to new key:

```go
rbp := RBP{Counter: 0x1500017, Check: 2}
err = ResealSecretWithNewAuthDigest(0x1500016,
    &oldKey.PublicKey,
    &newKey.PublicKey,
    newkeySig,
    newAuthDigest,
    approvedPolicy,
    approvedPolicySignature,
    []int{0, 1, 2}, // pcr indexes to be evaluated
    rbp)
```

If the operation is successful, the old key can be discarded from both server and client side and for subsequent unseal operations, client simply uses `newAuthDigest` and `approvedPolicyNewSig`:

```go
readSecret, err := UnsealSecret(0x1500016,
    &newKey.PublicKey,
    approvedPolicy,
    approvedPolicyNewSig,
    PCR_INDEXES,
    rbp)
```

# Testing
Testing can be done on emulated TPM, on ubuntu you can emulate a TPM by first installing swtpm and (optionally) tpm2-tools:

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