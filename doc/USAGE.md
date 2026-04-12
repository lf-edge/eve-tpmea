## Generating Mutable Policies

On the client side, during the on-boarding process (assumed to be secure), first create a monotonic counter and report its index and initial value back to the server (attester, challenger, etc.). Using rollback protection is strongly recommended; it is possible to skip it by passing an empty `RBP{}`, but that allows policy replay attacks.

```go
counter, err := DefineMonotonicCounter(0x1500017)
```

On the server side, create an Authorization Digest. When sealing a secret on the client side, this value is stored as the Authorization Policy of the TPM NV object that holds the secret.

```go
key, _ := rsa.GenerateKey(rand.Reader, 2048) // or ecdsa.GenerateKey(...)
authorizationDigest, err := GenerateAuthDigest(&key.PublicKey)
```

Then create a signed policy. The policy encodes the expected PCR values and the rollback-protection counter bound. PCR values can be reported by the client during on-boarding or known in advance. Every time the policy is updated, the counter `Check` value must be incremented on both the server side (in the new policy) and on the client side (by calling `IncreaseMonotonicCounter`) after the new policy is applied.

```go
sealingPcrs := []PCR{
    {Index: 0, Digest: []byte{0x20, 0x65, ..., 0x65}},
    {Index: 1, Digest: []byte{0x57, 0x40, ..., 0x20}},
    {Index: 2, Digest: []byte{0x75, 0xDE, ..., 0x69}},
}
pcrsList := PCRList{Algo: AlgoSHA256, Pcrs: sealingPcrs}
rbp := RBP{Counter: 0x1500017, Check: 1}

sp, err := GenerateSignedPolicy(key, pcrsList, rbp)
```

The server sends `authorizationDigest`, `sp`, and `key.PublicKey` to the client. After receiving these values, the client seals the secret into the TPM:

```go
secret := []byte("THIS_IS_VERY_SECRET")
err = SealSecret(0x1500016, authorizationDigest, secret)
```

For subsequent unseal operations, the client provides the PCR indices to evaluate at runtime and the signed policy received from the server:

```go
sel := PCRSelection{Algo: AlgoSHA256, Indexes: []int{0, 1, 2}}
readSecret, err := UnsealSecret(0x1500016, &key.PublicKey, sp, sel, rbp)
```

## Updating a Policy

To update a policy, the server creates a new signed policy with updated PCR values and an incremented counter `Check`, then sends it to the client:

```go
sealingPcrs := []PCR{
    {Index: 0, Digest: []byte{0x67, 0x65, ..., 0x65}},
    {Index: 1, Digest: []byte{0x6f, 0x6c, ..., 0x20}},
    {Index: 2, Digest: []byte{0x52, 0x6f, ..., 0x69}},
}
pcrsList := PCRList{Algo: AlgoSHA256, Pcrs: sealingPcrs}
rbp := RBP{Counter: 0x1500017, Check: 2}

sp, err := GenerateSignedPolicy(key, pcrsList, rbp)
```

The incremented `Check` value renders any older (but otherwise still valid) policies unusable. It is the client's responsibility to increment the counter after receiving and validating a new policy:

```go
counter, err = IncreaseMonotonicCounter(0x1500017)
```

The client must validate the signature inside `sp` using `key.PublicKey` before replacing any existing policy. After the update, the client can unseal the secret using the new policy that matches the updated system state.

## Read Locking

If supported by the TPM chip, it is possible to block reading from an NV index at runtime. `ActivateReadLock` activates this restriction and prevents further reads from the given index until the next TPM reset or restart.

Consider a scenario where the OS is compromised after a successful boot and attestation. An attacker with OS-level access could repeat the unseal operation and extract the secret for offline use. Activating read locking mitigates this: unseal the secret into process-private memory early at boot, then immediately lock the index so that any later compromise cannot read it again.

```go
sel := PCRSelection{Algo: AlgoSHA256, Indexes: []int{0, 1, 2}}
err = ActivateReadLock(0x1500016, &key.PublicKey, sp, sel, rbp)
```
