## Generating Mutable Policies
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

## Updating a Policy
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

Client must validate `approvedPolicySignature` signature using the `key.PublicKey` before replacing any old policy. After update Client should be able to read back the secret with a new policy that matches the new system state.

## Rotating the Signing Key
To rotate the signing key you can either have your own verification logic for the new public key and just use the same logic described in "Generating Mutable Policies" or use the old key to create a signing chain (this might be problematic if devices lost connection with the controller and you retire the old keys). To do this, simply sign the new key and generate a new Authorization Digest based on the new key and send the `newKey.PublicKey`, `newAuthDigest` and `approvedPolicyNewSig` to the client.

```go
newKey, _ := GenKeyPair()
newkeySig, newAuthDigest, approvedPolicyNewSig, err := RotateAuthDigestWithPolicy(oldKey, newKey, pcrs, rbp)
```

 After receiving the new key and signature, by calling `ResealTpmSecretWithVerifiedAuthDigest` client verifiers the new key is signed with the old key and then reseals the secret using the new Authorization Digest which is bound to new key:

```go
rbp := RBP{Counter: 0x1500017, Check: 2}
err = ResealTpmSecretWithVerifiedAuthDigest(0x1500016,
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

## Read Locking
If implemented by the TPM chip, it is possible to block reading data from a NV index at run-time. `ActivateReadLock` activates this restriction and blocks further reading of the data from provided index, this restriction will gets deactivated on next TPM reset or restart.

In a case that operating system is compromised at run-time (after booting up to a known-good-state and successful attestation), an attacker might be able to read the secret from the TPM by repeating the unseal operation form the compromised OS and extract the secret for offline use. Activating read-locking can be beneficial in this scenario, for example we can unseal the secret into a process private memory early at boot and then activate read-locking, preventing a late compromised system getting access to the secret.