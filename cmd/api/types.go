// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package api

// PCR is a single platform configuration register value.
type PCR struct {
	Index  int    `json:"index"`
	Digest []byte `json:"digest"`
}

// PCRList is a set of PCR values from one hash bank.
type PCRList struct {
	Algo int   `json:"algo"` // tpmea.PCRHashAlgo value
	PCRs []PCR `json:"pcrs"`
}

// RBP carries the rollback protection counter handle and expected value.
type RBP struct {
	Counter uint32 `json:"counter"`
	Check   uint64 `json:"check"`
}

// PolicySig holds the raw signature bytes from GenerateSignedPolicy.
// Exactly one of RSA or ECC fields will be set, the rest are omitted.
type PolicySig struct {
	RSASignature  []byte `json:"rsaSig,omitempty"`
	ECCSignatureR []byte `json:"eccSigR,omitempty"`
	ECCSignatureS []byte `json:"eccSigS,omitempty"`
}

// SignedPolicy bundles a policy digest with the signature over it.
type SignedPolicy struct {
	Digest []byte    `json:"digest"`
	Sig    PolicySig `json:"sig"`
}

// InitResp is returned by GET /api/init. The client uses these values to
// seal a secret into its TPM for the first time.
type InitResp struct {
	AuthDigest   []byte `json:"authDigest"`
	PublicKeyDER []byte `json:"publicKeyDer"` // PKIX DER-encoded public key
}

// RegisterAIKReq is the body sent to POST /api/register-aik. The client sends
// its AIK public key so the server can verify future NV counter certifications.
type RegisterAIKReq struct {
	AIKPublicKeyDER []byte `json:"aikPublicKeyDer"` // PKIX DER-encoded public key
}

// NonceResp is returned by GET /api/nonce. The client uses this freshness token
// when certifying its NV counter; the server checks it against what was issued.
type NonceResp struct {
	Nonce []byte `json:"nonce"`
}

// NVCert is the wire representation of an NVCertification. Exactly one of the
// RSA or ECC signature fields will be set, depending on the AIK key type.
type NVCert struct {
	Nonce      []byte `json:"nonce"`
	AttestBlob []byte `json:"attestBlob"`
	RSASig     []byte `json:"rsaSig,omitempty"`
	ECCSigR    []byte `json:"eccSigR,omitempty"`
	ECCSigS    []byte `json:"eccSigS,omitempty"`
}

// SignPolicyReq is the body sent to POST /api/sign-policy.
// NVCert is optional; if present the server verifies the counter attestation
// before signing the policy. If absent the server trusts the RBP value.
type SignPolicyReq struct {
	PCRList PCRList `json:"pcrList"`
	RBP     RBP     `json:"rbp"`
	NVCert  *NVCert `json:"nvCert,omitempty"`
}

// SignPolicyResp is returned by POST /api/sign-policy.
// NewRBP is the rollback protection binding that was actually signed into the
// policy - the server increments Check by one so the client knows what counter
// value to use on the next unseal.
type SignPolicyResp struct {
	SignedPolicy SignedPolicy `json:"signedPolicy"`
	NewRBP       RBP          `json:"newRbp"`
}

// RotateReq is the body sent to POST /api/rotate.
type RotateReq struct {
	PCRList PCRList `json:"pcrList"`
	RBP     RBP     `json:"rbp"`
}

// RotateResp is returned by POST /api/rotate. The client must verify the
// new key signature before applying it.
type RotateResp struct {
	OldPublicKeyDER []byte       `json:"oldPublicKeyDer"`
	NewPublicKeyDER []byte       `json:"newPublicKeyDer"`
	NewKeySig       []byte       `json:"newKeySig"`
	NewAuthDigest   []byte       `json:"newAuthDigest"`
	SignedPolicy    SignedPolicy `json:"signedPolicy"`
}
