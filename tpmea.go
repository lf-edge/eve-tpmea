package tpmea

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/big"
	"reflect"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/linux"
	"github.com/canonical/go-tpm2/mu"
	"github.com/canonical/go-tpm2/policyutil"
	"github.com/canonical/go-tpm2/util"
)

type PCRHashAlgo int

const (
	AlgoSHA1   = PCRHashAlgo(0)
	AlgoSHA256 = PCRHashAlgo(1)
	AlgoSHA384 = PCRHashAlgo(2)
	AlgoSHA512 = PCRHashAlgo(3)
)

// NVCertification is the output of TPM2_NV_Certify for a monotonic counter.
// It carries the raw attestation blob and signature so a remote verifier can
// authenticate the counter value without direct TPM access.
type NVCertification struct {
	// Nonce is the qualifying data supplied to TPM2_NV_Certify. The TPM
	// embeds it in the signed blob so the verifier can confirm freshness.
	Nonce []byte
	// AttestBlob is the raw marshaled TPMS_ATTEST structure. The signing
	// key's signature covers SHA-256(AttestBlob).
	AttestBlob []byte
	// RSASig is set when the signing key is RSA (PKCS#1v15).
	RSASig []byte
	// ECCSigR and ECCSigS are set when the signing key is ECDSA.
	ECCSigR []byte
	ECCSigS []byte
}

// PolicySignature holds the raw signature bytes produced by GenerateSignedPolicy.
type PolicySignature struct {
	RSASignature  []byte
	ECCSignatureR []byte
	ECCSignatureS []byte
}

// SignedPolicy bundles the policy digest with the signature over it.
type SignedPolicy struct {
	Digest []byte
	Sig    *PolicySignature
}

// PCRSelection identifies which PCR banks and indices to check at unseal
// time. It does not carry expected digest values; those are encoded in the
// policy digest inside SignedPolicy.
type PCRSelection struct {
	Algo    PCRHashAlgo
	Indexes []int
}

// KeyRotation carries everything produced by RotateAuthDigestWithPolicy
// that the device side needs to verify and apply a key transition.
type KeyRotation struct {
	OldPublicKey  crypto.PublicKey
	NewPublicKey  crypto.PublicKey
	NewKeySig     []byte
	NewAuthDigest tpm2.Digest
}

type PCR struct {
	Index  int
	Digest []byte
}

type PCRS []PCR

type PCRList struct {
	Pcrs PCRS
	Algo PCRHashAlgo
}

type RBP struct {
	Counter uint32
	Check   uint64
}

func getPCRAlgo(algo PCRHashAlgo) (tpm2.HashAlgorithmId, error) {
	switch algo {
	case AlgoSHA1:
		return tpm2.HashAlgorithmSHA1, nil
	case AlgoSHA256:
		return tpm2.HashAlgorithmSHA256, nil
	case AlgoSHA384:
		return tpm2.HashAlgorithmSHA384, nil
	case AlgoSHA512:
		return tpm2.HashAlgorithmSHA512, nil
	default:
		return 0, fmt.Errorf("unsupported PCR hash algorithm: %d", algo)
	}
}

var getTpmHandle = func() (*tpm2.TPMContext, error) {
	device, err := linux.DefaultTPM2Device()
	if err != nil {
		return nil, err
	}
	rmDevice, err := device.ResourceManagedDevice()
	if err != nil {
		return nil, err
	}
	return tpm2.OpenTPMDevice(rmDevice)
}

// SetTPMHandleFunc replaces the function used to open a TPM connection.
func SetTPMHandleFunc(f func() (*tpm2.TPMContext, error)) {
	getTpmHandle = f
}

func zeroExtendBytes(x *big.Int, l int) (out []byte) {
	out = make([]byte, l)
	tmp := x.Bytes()
	copy(out[len(out)-len(tmp):], tmp)
	return
}

func eccCurveID(curve elliptic.Curve) (tpm2.ECCCurve, error) {
	switch curve {
	case elliptic.P256():
		return tpm2.ECCCurveNIST_P256, nil
	case elliptic.P384():
		return tpm2.ECCCurveNIST_P384, nil
	case elliptic.P521():
		return tpm2.ECCCurveNIST_P521, nil
	default:
		return 0, fmt.Errorf("unsupported ECC curve: %s", curve.Params().Name)
	}
}

func newExternalECCPub(key *ecdsa.PublicKey) (tpm2.Public, error) {
	curveID, err := eccCurveID(key.Curve)
	if err != nil {
		return tpm2.Public{}, err
	}
	coordSize := (key.Params().BitSize + 7) / 8
	return tpm2.Public{
		Type:    tpm2.ObjectTypeECC,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.AttrDecrypt | tpm2.AttrSign | tpm2.AttrUserWithAuth,
		Params: &tpm2.PublicParamsU{
			ECCDetail: &tpm2.ECCParams{
				Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
				Scheme:    tpm2.ECCScheme{Scheme: tpm2.ECCSchemeNull},
				CurveID:   curveID,
				KDF:       tpm2.KDFScheme{Scheme: tpm2.KDFAlgorithmNull}}},
		Unique: &tpm2.PublicIDU{
			ECC: &tpm2.ECCPoint{
				X: zeroExtendBytes(key.X, coordSize),
				Y: zeroExtendBytes(key.Y, coordSize)}}}, nil
}

func newExternalRSAPub(key *rsa.PublicKey) tpm2.Public {
	return tpm2.Public{
		Type:    tpm2.ObjectTypeRSA,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.AttrDecrypt | tpm2.AttrSign | tpm2.AttrUserWithAuth,
		Params: &tpm2.PublicParamsU{
			RSADetail: &tpm2.RSAParams{
				Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
				Scheme:    tpm2.RSAScheme{Scheme: tpm2.RSASchemeNull},
				KeyBits:   uint16(key.N.BitLen()),
				Exponent:  uint32(key.E)}},
		Unique: &tpm2.PublicIDU{RSA: key.N.Bytes()}}
}

// extractPublicKey returns the public half of a private key.
func extractPublicKey(priv crypto.PrivateKey) (crypto.PublicKey, error) {
	switch p := priv.(type) {
	case *rsa.PrivateKey:
		return &p.PublicKey, nil
	case *ecdsa.PrivateKey:
		return &p.PublicKey, nil
	default:
		return nil, fmt.Errorf("invalid private key (neither RSA nor ECC)")
	}
}

func verifyPolicySignature(tpm *tpm2.TPMContext, publicKey crypto.PublicKey, sp SignedPolicy) (*tpm2.TkVerified, tpm2.ResourceContext, error) {
	if sp.Sig == nil {
		return nil, nil, fmt.Errorf("invalid parameter(s)")
	}

	var (
		public    tpm2.Public
		signature *tpm2.Signature
		err       error
	)
	switch p := publicKey.(type) {
	case *rsa.PublicKey:
		public = newExternalRSAPub(p)
		signature = &tpm2.Signature{
			SigAlg: tpm2.SigSchemeAlgRSASSA,
			Signature: &tpm2.SignatureU{
				RSASSA: &tpm2.SignatureRSASSA{
					Hash: tpm2.HashAlgorithmSHA256,
					Sig:  sp.Sig.RSASignature}}}
	case *ecdsa.PublicKey:
		public, err = newExternalECCPub(p)
		if err != nil {
			return nil, nil, err
		}
		signature = &tpm2.Signature{
			SigAlg: tpm2.SigSchemeAlgECDSA,
			Signature: &tpm2.SignatureU{
				ECDSA: &tpm2.SignatureECDSA{
					Hash:       tpm2.HashAlgorithmSHA256,
					SignatureR: sp.Sig.ECCSignatureR,
					SignatureS: sp.Sig.ECCSignatureS}}}
	default:
		return nil, nil, fmt.Errorf("invalid public key (neither RSA nor ECC)")
	}

	// null-hierarchy won't produce a valid ticket, go with owner
	keyCtx, err := tpm.LoadExternal(nil, &public, tpm2.HandleOwner)
	if err != nil {
		return nil, nil, err
	}

	// flush keyCtx on any error; on success the caller takes ownership and flushes it.
	success := false
	defer func() {
		if !success {
			tpm.FlushContext(keyCtx)
		}
	}()

	// approvedPolicy by itself is a digest, but approvedPolicySignature is a
	// signature over digest of approvedPolicy (signature over digest of digest),
	// so compute it first.
	approvedPolicyDigest, err := util.ComputePolicyAuthorizeDigest(tpm2.HashAlgorithmSHA256, sp.Digest, nil)
	if err != nil {
		return nil, nil, err
	}

	// check the signature and produce a ticket if it's valid
	ticket, err := tpm.VerifySignature(keyCtx, approvedPolicyDigest, signature)
	if err != nil {
		return nil, nil, err
	}

	success = true
	return ticket, keyCtx, nil
}

func authorizeObject(tpm *tpm2.TPMContext, publicKey crypto.PublicKey, sp SignedPolicy, sel PCRSelection, rbp RBP) (tpm2.SessionContext, error) {
	ticket, keyCtx, err := verifyPolicySignature(tpm, publicKey, sp)
	if err != nil {
		return nil, err
	}
	defer tpm.FlushContext(keyCtx)

	// start a policy session, a policy session will actually evaluate commands
	// in comparison to trial policy that only computes the final digest whether
	// run-time state match the provided state or not.
	polss, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)
	if err != nil {
		return nil, err
	}

	// flush polss on any error; on success the caller takes ownership and flushes it.
	success := false
	defer func() {
		if !success {
			tpm.FlushContext(polss)
		}
	}()

	if rbp != (RBP{}) {
		index, err := tpm.NewResourceContext(tpm2.Handle(rbp.Counter))
		if err != nil {
			return nil, err
		}

		// if rbp is provided, first check the PolicyNV then PolicyPCR, in this
		// case the two policies form a logical AND (PolicyNV AND PolicyPCR).
		operandB := make([]byte, 8)
		binary.BigEndian.PutUint64(operandB, rbp.Check)
		err = tpm.PolicyNV(tpm.OwnerHandleContext(), index, polss, operandB, 0, tpm2.OpUnsignedLE, nil)
		if err != nil {
			return nil, err
		}
	}

	pcrHashAlgo, err := getPCRAlgo(sel.Algo)
	if err != nil {
		return nil, err
	}
	pcrSelections := tpm2.PCRSelectionList{{Hash: pcrHashAlgo, Select: sel.Indexes}}
	err = tpm.PolicyPCR(polss, nil, pcrSelections)
	if err != nil {
		return nil, err
	}

	// authorize policy will check if policies hold at runtime (i.e PCR values
	// match the expected value and counter holds true on the arithmetic op)
	err = tpm.PolicyAuthorize(polss, sp.Digest, nil, keyCtx.Name(), ticket)
	if err != nil {
		return nil, err
	}

	success = true
	return polss, nil
}

// defineMonotonicCounterOn ensures the NV counter at handle exists and is
// initialized on the given tpm connection, returning its current value.
func defineMonotonicCounterOn(tpm *tpm2.TPMContext, handle uint32) (uint64, error) {
	index, err := tpm.NewResourceContext(tpm2.Handle(handle))
	if err == nil {
		// handle already exists, read its attributes.
		nvpub, _, err := tpm.NVReadPublic(index)
		if err != nil {
			return 0, err
		}

		// check if the type and attributes match what we need, if so, just use the handle.
		attr := tpm2.AttrNVOwnerRead | tpm2.AttrNVOwnerWrite
		if nvpub.Attrs.Type() != tpm2.NVTypeCounter || (nvpub.Attrs&attr) != attr {
			return 0, errors.New("a counter at provide handle already exists with mismatched attributes")
		}

		// if it's not initialized, initialize it by increasing it.
		if (nvpub.Attrs & tpm2.AttrNVWritten) != tpm2.AttrNVWritten {
			err = tpm.NVIncrement(tpm.OwnerHandleContext(), index, nil)
			if err != nil {
				return 0, err
			}
		}

		counter, err := tpm.NVReadCounter(tpm.OwnerHandleContext(), index, nil)
		if err != nil {
			return 0, err
		}

		return counter, nil
	}

	// handle doesn't exist, create it with desired attributes.
	nvpub := tpm2.NVPublic{
		Index:   tpm2.Handle(handle),
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeCounter.WithAttrs(tpm2.AttrNVOwnerRead | tpm2.AttrNVOwnerWrite),
		Size:    8}
	index, err = tpm.NVDefineSpace(tpm.OwnerHandleContext(), nil, &nvpub, nil)
	if err != nil {
		return 0, err
	}

	// increasing the counter is necessary to initialize it.
	err = tpm.NVIncrement(tpm.OwnerHandleContext(), index, nil)
	if err != nil {
		return 0, err
	}

	return tpm.NVReadCounter(tpm.OwnerHandleContext(), index, nil)
}

// DefineMonotonicCounter will define a monotonic NV counter at the given index,
// function will initialize the counter and returns its current value.
//
// monotonic counters will retain their value and won't go away even if undefined,
// because of this if the handle already exist and it's attributes matches what
// we need, it will get initialized first if it is uninitialized, and then
// its current value is returned.
func DefineMonotonicCounter(handle uint32) (uint64, error) {
	tpm, err := getTpmHandle()
	if err != nil {
		return 0, err
	}
	defer tpm.Close()

	return defineMonotonicCounterOn(tpm, handle)
}

// IncreaseMonotonicCounter will increase the value of the monotonic counter at
// provided index, by one and returns the new value.
func IncreaseMonotonicCounter(handle uint32) (uint64, error) {
	tpm, err := getTpmHandle()
	if err != nil {
		return 0, err
	}
	defer tpm.Close()

	index, err := tpm.NewResourceContext(tpm2.Handle(handle))
	if err != nil {
		return 0, err
	}

	nvpub, _, err := tpm.NVReadPublic(index)
	if err != nil {
		return 0, err
	}
	if nvpub.Attrs.Type() != tpm2.NVTypeCounter {
		return 0, fmt.Errorf("NV index 0x%x is not a monotonic counter", handle)
	}

	err = tpm.NVIncrement(tpm.OwnerHandleContext(), index, nil)
	if err != nil {
		return 0, err
	}

	counter, err := tpm.NVReadCounter(tpm.OwnerHandleContext(), index, nil)
	if err != nil {
		return 0, err
	}

	return counter, nil
}

// SealSecret will write the provide secret to the TPM. The authDigest parameter
// binds the unseal operation with a signed policy that must hold true at run-time.
func SealSecret(handle uint32, authDigest []byte, secret []byte) error {
	if authDigest == nil || secret == nil {
		return fmt.Errorf("invalid parameter(s)")
	}

	if len(authDigest) == 0 {
		return fmt.Errorf("authDigest must not be empty: an empty policy allows unauthorized access")
	}

	if len(secret) == 0 {
		return fmt.Errorf("secret must not be empty")
	}

	if len(secret) > math.MaxUint16 {
		return fmt.Errorf("secret too large: %d bytes exceeds TPM NV max of %d", len(secret), math.MaxUint16)
	}

	tpm, err := getTpmHandle()
	if err != nil {
		return err
	}
	defer tpm.Close()

	// if the handle already exists, verify it is an ordinary NV index before
	// overwriting it.
	index, err := tpm.NewResourceContext(tpm2.Handle(handle))
	if err == nil {
		nvpub, _, err := tpm.NVReadPublic(index)
		if err != nil {
			return err
		}
		if nvpub.Attrs.Type() != tpm2.NVTypeOrdinary {
			return fmt.Errorf("NV index 0x%x exists but is not an ordinary NV index (type: %v)", handle, nvpub.Attrs.Type())
		}
		err = tpm.NVUndefineSpace(tpm.OwnerHandleContext(), index, nil)
		if err != nil {
			return err
		}
	}

	nvpub := tpm2.NVPublic{
		Index:      tpm2.Handle(handle),
		NameAlg:    tpm2.HashAlgorithmSHA256,
		Attrs:      tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVPolicyRead | tpm2.AttrNVOwnerWrite | tpm2.AttrNVReadStClear),
		AuthPolicy: authDigest,
		Size:       uint16(len(secret))}
	index, err = tpm.NVDefineSpace(tpm.OwnerHandleContext(), nil, &nvpub, nil)
	if err != nil {
		return err
	}

	return tpm.NVWrite(tpm.OwnerHandleContext(), index, secret, 0, nil)
}

// UnsealSecret reads the secret from the TPM. The signed policy must have been
// produced by GenerateSignedPolicy with a key whose public half matches publicKey.
// Unsealing succeeds only if the signature is valid and the TPM's runtime state
// (PCR values and, optionally, the rollback-protection counter) matches what was
// encoded in the policy at signing time.
func UnsealSecret(handle uint32, publicKey crypto.PublicKey, sp SignedPolicy, sel PCRSelection, rbp RBP) ([]byte, error) {
	if publicKey == nil || sp.Sig == nil || sp.Digest == nil {
		return nil, fmt.Errorf("invalid parameter(s)")
	}

	tpm, err := getTpmHandle()
	if err != nil {
		return nil, err
	}
	defer tpm.Close()

	// if the handle is not valid don't bother authorizing.
	index, err := tpm.NewResourceContext(tpm2.Handle(handle))
	if err != nil {
		return nil, err
	}

	// perform the TPM commands in order, this will work only if policy signature
	// is valid and session digest matches the auth (saved) digest of the object.
	polss, err := authorizeObject(tpm, publicKey, sp, sel, rbp)
	if err != nil {
		return nil, err
	}
	defer tpm.FlushContext(polss)

	// read the public area of NV to find out its size.
	pub, _, err := tpm.NVReadPublic(index)
	if err != nil {
		return nil, err
	}

	return tpm.NVRead(index, index, pub.Size, 0, polss)
}

// ActivateReadLock prevents further reading of the data from provided index,
// this restriction will gets deactivated on next tpm reset or restart.
func ActivateReadLock(handle uint32, publicKey crypto.PublicKey, sp SignedPolicy, sel PCRSelection, rbp RBP) error {
	if publicKey == nil || sp.Sig == nil || sp.Digest == nil {
		return fmt.Errorf("invalid parameter(s)")
	}

	tpm, err := getTpmHandle()
	if err != nil {
		return err
	}
	defer tpm.Close()

	// don't bother authorizing, if the handle is not valid
	index, err := tpm.NewResourceContext(tpm2.Handle(handle))
	if err != nil {
		return err
	}

	// perform the TPM commands in order, this will work only if policy signature
	// is valid and session digest matches the auth (saved) digest of the object.
	polss, err := authorizeObject(tpm, publicKey, sp, sel, rbp)
	if err != nil {
		return err
	}
	defer tpm.FlushContext(polss)

	return tpm.NVReadLock(index, index, polss)
}

// GenerateAuthDigest will generate a authorization digest based on the provided
// public key. The returned authorizationDigest is the basis for creating mutable
// TPM policies.
//
// It is not necessary to run this function on a real TPM, running it on a
// true-to-spec emulator like swtpm will work.
//
// This function should be called in the server side (attester, Challenger, etc).
func GenerateAuthDigest(publicKey crypto.PublicKey) (authDigest tpm2.Digest, err error) {
	if publicKey == nil {
		return nil, fmt.Errorf("invalid parameter(s)")
	}

	tpm, err := getTpmHandle()
	if err != nil {
		return nil, err
	}
	defer tpm.Close()

	// we generate the auth digest in a trial session, trial session won't
	// evaluate the states of TPM and we can get the final session digest
	// regardless of TPM state.
	triss, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypeTrial, nil, tpm2.HashAlgorithmSHA256)
	if err != nil {
		return nil, err
	}
	defer tpm.FlushContext(triss)

	var public tpm2.Public
	switch p := publicKey.(type) {
	case *rsa.PublicKey:
		public = newExternalRSAPub(p)
	case *ecdsa.PublicKey:
		public, err = newExternalECCPub(p)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("invalid public key (neither RSA nor ECC)")
	}

	// load the public key into TPM
	keyCtx, err := tpm.LoadExternal(nil, &public, tpm2.HandleNull)
	if err != nil {
		return nil, err
	}
	defer tpm.FlushContext(keyCtx)

	// ask TPM to compute the session digest.
	err = tpm.PolicyAuthorize(triss, nil, nil, keyCtx.Name(), nil)
	if err != nil {
		return nil, err
	}

	// retrieve the session digest.
	return tpm.PolicyGetDigest(triss)
}

// GenerateSignedPolicy computes a policy digest that encodes the expected
// runtime state (PCR values and, optionally, a rollback-protection counter
// bound) and signs it with the provided private key. The returned SignedPolicy
// must be passed verbatim to UnsealSecret or ActivateReadLock.
//
// The private key must belong to the pair used with GenerateAuthDigest.
//
// It is not necessary to run this function on a real TPM, running it on a
// true-to-spec emulator like swtpm will work.
//
// This function should be called in the server side (attester, Challenger, etc).
func GenerateSignedPolicy(privateKey crypto.PrivateKey, pcrList PCRList, rbp RBP) (SignedPolicy, error) {
	if privateKey == nil {
		return SignedPolicy{}, fmt.Errorf("invalid parameter(s)")
	}

	tpm, err := getTpmHandle()
	if err != nil {
		return SignedPolicy{}, err
	}
	defer tpm.Close()

	// we generate the policy digest in a trial session, because we don't want to
	// evaluate the provided state, we are only interested in the final session
	// digest that is computed as result of executing TPM commands, here the
	// commands are PolicyNV and PolicyPCR.
	triss, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypeTrial, nil, tpm2.HashAlgorithmSHA256)
	if err != nil {
		return SignedPolicy{}, err
	}
	defer tpm.FlushContext(triss)

	if rbp != (RBP{}) {
		// The trial session needs the NV index to exist on this TPM so it can
		// compute the correct policy name. Create it on the same connection if
		// it is not already present; value does not matter for name derivation.
		if _, err := defineMonotonicCounterOn(tpm, rbp.Counter); err != nil {
			return SignedPolicy{}, err
		}

		index, err := tpm.NewResourceContext(tpm2.Handle(rbp.Counter))
		if err != nil {
			return SignedPolicy{}, err
		}

		// PolicyNV : index value <= operandB
		operandB := make([]byte, 8)
		binary.BigEndian.PutUint64(operandB, rbp.Check)
		err = tpm.PolicyNV(tpm.OwnerHandleContext(), index, triss, operandB, 0, tpm2.OpUnsignedLE, nil)
		if err != nil {
			return SignedPolicy{}, err
		}
	}

	sel := make([]int, 0)
	digests := make(map[int]tpm2.Digest)
	for _, pcr := range pcrList.Pcrs {
		sel = append(sel, pcr.Index)
		digests[pcr.Index] = pcr.Digest
	}

	pcrHashAlgo, err := getPCRAlgo(pcrList.Algo)
	if err != nil {
		return SignedPolicy{}, err
	}
	pcrSelections := tpm2.PCRSelectionList{{Hash: pcrHashAlgo, Select: sel}}
	pcrValues := tpm2.PCRValues{pcrHashAlgo: digests}
	pcrDigests, err := policyutil.ComputePCRDigest(pcrHashAlgo, pcrSelections, pcrValues)
	if err != nil {
		return SignedPolicy{}, err
	}

	// PolicyPCR: runtime PCRs == pcrList
	err = tpm.PolicyPCR(triss, pcrDigests, pcrSelections)
	if err != nil {
		return SignedPolicy{}, err
	}

	// get the final session digest from TPM.
	policyDigest, err := tpm.PolicyGetDigest(triss)
	if err != nil {
		return SignedPolicy{}, err
	}

	switch p := privateKey.(type) {
	case *rsa.PrivateKey:
		scheme := tpm2.SigScheme{
			Scheme: tpm2.SigSchemeAlgRSASSA,
			Details: &tpm2.SigSchemeU{
				RSASSA: &tpm2.SigSchemeRSASSA{
					HashAlg: tpm2.HashAlgorithmSHA256}}}
		// util.PolicyAuthorize is not executing PolicyAuthorize TPM commands, it
		// just computes digest of policyDigest and signs it with provided key, bad
		// naming on the go-tpm2.
		_, s, err := util.PolicyAuthorize(p, &scheme, policyDigest, nil)
		if err != nil {
			return SignedPolicy{}, err
		}
		return SignedPolicy{Digest: policyDigest, Sig: &PolicySignature{RSASignature: s.Signature.RSASSA.Sig}}, nil
	case *ecdsa.PrivateKey:
		scheme := tpm2.SigScheme{
			Scheme: tpm2.SigSchemeAlgECDSA,
			Details: &tpm2.SigSchemeU{
				ECDSA: &tpm2.SigSchemeECDSA{
					HashAlg: tpm2.HashAlgorithmSHA256}}}
		// util.PolicyAuthorize is not executing PolicyAuthorize TPM commands, it
		// just computes digest of policyDigest and signs it with provided key, bad
		// naming on the go-tpm2.
		_, s, err := util.PolicyAuthorize(p, &scheme, policyDigest, nil)
		if err != nil {
			return SignedPolicy{}, err
		}
		return SignedPolicy{Digest: policyDigest, Sig: &PolicySignature{ECCSignatureR: s.Signature.ECDSA.SignatureR, ECCSignatureS: s.Signature.ECDSA.SignatureS}}, nil
	default:
		return SignedPolicy{}, fmt.Errorf("invalid private key (neither RSA nor ECC)")
	}
}

func hashPublicKey(publicKey crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	sh := crypto.SHA256.New()
	sh.Write(der)
	return sh.Sum(nil), nil
}

// rotateAuthDigestKeyWithKeySigning signs the new auth public key using the old one,
// and generates a new Authorization Digest using the new auth key.
//
// It is not necessary to run this function on a real TPM, running it on a
// true-to-spec emulator like swtpm will work.
//
// This function should be called in the server side  (attester, Challenger, etc).
func rotateAuthDigestKeyWithKeySigning(oldPrivateKey crypto.PrivateKey, newPrivateKey crypto.PrivateKey) (newSignature []byte, newAuthDigest tpm2.Digest, err error) {
	var public tpm2.Public
	var signature []byte
	switch p := oldPrivateKey.(type) {
	case *rsa.PrivateKey:
		newRSAPrivateKey, ok := newPrivateKey.(*rsa.PrivateKey)
		if !ok {
			return nil, nil, fmt.Errorf("new key must be *rsa.PrivateKey")
		}
		newRSAPublicKeyHash, err := hashPublicKey(&newRSAPrivateKey.PublicKey)
		if err != nil {
			return nil, nil, err
		}
		public = newExternalRSAPub(&newRSAPrivateKey.PublicKey)
		signature, err = rsa.SignPKCS1v15(nil, p, crypto.SHA256, newRSAPublicKeyHash)
		if err != nil {
			return nil, nil, err
		}
	case *ecdsa.PrivateKey:
		newECCPrivateKey, ok := newPrivateKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, nil, fmt.Errorf("new key must be *ecdsa.PrivateKey")
		}
		newECCPublicKeyHash, err := hashPublicKey(&newECCPrivateKey.PublicKey)
		if err != nil {
			return nil, nil, err
		}
		public, err = newExternalECCPub(&newECCPrivateKey.PublicKey)
		if err != nil {
			return nil, nil, err
		}
		signature, err = ecdsa.SignASN1(rand.Reader, p, newECCPublicKeyHash)
		if err != nil {
			return nil, nil, err
		}
	default:
		return nil, nil, fmt.Errorf("invalid private key (neither RSA nor ECC)")
	}

	tpm, err := getTpmHandle()
	if err != nil {
		return nil, nil, err
	}
	defer tpm.Close()

	keyCtx, err := tpm.LoadExternal(nil, &public, tpm2.HandleNull)
	if err != nil {
		return nil, nil, err
	}
	defer tpm.FlushContext(keyCtx)

	// we generate the auth digest in a trial session, no evaluation in TPM is
	// required, we are only interested in the final session digest
	triss, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypeTrial, nil, tpm2.HashAlgorithmSHA256)
	if err != nil {
		return nil, nil, err
	}
	defer tpm.FlushContext(triss)

	// ask TPM to compute the session digest.
	err = tpm.PolicyAuthorize(triss, nil, nil, keyCtx.Name(), nil)
	if err != nil {
		return nil, nil, err
	}

	// retrieve the session digest.
	digest, err := tpm.PolicyGetDigest(triss)
	if err != nil {
		return nil, nil, err
	}

	return signature, digest, nil
}

// RotateAuthDigestWithPolicy signs the new auth public key with the old private
// key, derives a new Authorization Digest bound to the new key, and signs a
// fresh policy with the new key. The returned KeyRotation carries everything
// the device needs to apply the transition; the returned SignedPolicy is the
// first policy valid under the new key.
//
// It is not necessary to run this function on a real TPM, running it on a
// true-to-spec emulator like swtpm will work.
//
// This function should be called in the server side  (attester, Challenger, etc).
func RotateAuthDigestWithPolicy(oldPrivateKey crypto.PrivateKey, newPrivateKey crypto.PrivateKey, pcrList PCRList, rbp RBP) (KeyRotation, SignedPolicy, error) {
	if oldPrivateKey == nil || newPrivateKey == nil {
		return KeyRotation{}, SignedPolicy{}, fmt.Errorf("invalid parameter(s)")
	}

	if reflect.TypeOf(oldPrivateKey) != reflect.TypeOf(newPrivateKey) {
		return KeyRotation{}, SignedPolicy{}, fmt.Errorf("both old and new private keys have to be of same type")
	}

	oldPub, err := extractPublicKey(oldPrivateKey)
	if err != nil {
		return KeyRotation{}, SignedPolicy{}, err
	}

	newPub, err := extractPublicKey(newPrivateKey)
	if err != nil {
		return KeyRotation{}, SignedPolicy{}, err
	}

	newKeySig, newAuthDigest, err := rotateAuthDigestKeyWithKeySigning(oldPrivateKey, newPrivateKey)
	if err != nil {
		return KeyRotation{}, SignedPolicy{}, err
	}

	sp, err := GenerateSignedPolicy(newPrivateKey, pcrList, rbp)
	if err != nil {
		return KeyRotation{}, SignedPolicy{}, err
	}

	rotation := KeyRotation{
		OldPublicKey:  oldPub,
		NewPublicKey:  newPub,
		NewKeySig:     newKeySig,
		NewAuthDigest: newAuthDigest,
	}
	return rotation, sp, nil
}

// VerifyNewAuthDigest verifies that the new public key was signed by the old
// key. Call this on the device before applying a key rotation.
func VerifyNewAuthDigest(rotation KeyRotation) error {
	if rotation.OldPublicKey == nil || rotation.NewPublicKey == nil || rotation.NewKeySig == nil {
		return fmt.Errorf("invalid parameter(s)")
	}

	if reflect.TypeOf(rotation.OldPublicKey) != reflect.TypeOf(rotation.NewPublicKey) {
		return fmt.Errorf("both old and new public keys have to be of same type")
	}

	newPublicKeyHash, err := hashPublicKey(rotation.NewPublicKey)
	if err != nil {
		return err
	}

	switch p := rotation.OldPublicKey.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(p, crypto.SHA256, newPublicKeyHash, rotation.NewKeySig)
	case *ecdsa.PublicKey:
		ok := ecdsa.VerifyASN1(p, newPublicKeyHash, rotation.NewKeySig)
		if !ok {
			return fmt.Errorf("invalid new key signature")
		}
		return nil
	default:
		return fmt.Errorf("invalid public key (neither RSA nor ECC)")
	}
}

// SealSecretWithVerifiedAuthDigest verifies the key rotation then reseals the
// secret under the new Authorization Digest. Subsequent unseal operations will
// require policies signed with the new key.
func SealSecretWithVerifiedAuthDigest(handle uint32, rotation KeyRotation, secret []byte) error {
	if rotation.OldPublicKey == nil || rotation.NewPublicKey == nil || rotation.NewKeySig == nil || rotation.NewAuthDigest == nil || secret == nil {
		return fmt.Errorf("invalid parameter(s)")
	}

	err := VerifyNewAuthDigest(rotation)
	if err != nil {
		return err
	}

	return SealSecret(handle, rotation.NewAuthDigest, secret)
}

// ResealTpmSecretWithVerifiedAuthDigest unseals the secret with the old key,
// verifies the key rotation, then reseals the secret under the new
// Authorization Digest.
func ResealTpmSecretWithVerifiedAuthDigest(handle uint32, rotation KeyRotation, sp SignedPolicy, sel PCRSelection, rbp RBP) error {
	if rotation.OldPublicKey == nil || rotation.NewPublicKey == nil || rotation.NewKeySig == nil || rotation.NewAuthDigest == nil || sp.Sig == nil || sp.Digest == nil {
		return fmt.Errorf("invalid parameter(s)")
	}

	secret, err := UnsealSecret(handle, rotation.OldPublicKey, sp, sel, rbp)
	if err != nil {
		return err
	}

	return SealSecretWithVerifiedAuthDigest(handle, rotation, secret)
}

// ReadPCRs reads the current values of the given PCR indexes from the
// specified hash bank. The returned list preserves the original PCR indexes
// so it can be passed directly to GenerateSignedPolicy.
func ReadPCRs(indexes []int, algo PCRHashAlgo) (PCRList, error) {
	tpm, err := getTpmHandle()
	if err != nil {
		return PCRList{}, err
	}
	defer tpm.Close()

	pcrHashAlgo, err := getPCRAlgo(algo)
	if err != nil {
		return PCRList{}, err
	}

	pcrSelections := tpm2.PCRSelectionList{{Hash: pcrHashAlgo, Select: indexes}}
	_, pcrsValue, err := tpm.PCRRead(pcrSelections)
	if err != nil {
		return PCRList{}, err
	}

	pcrList := PCRList{Algo: algo, Pcrs: make(PCRS, 0, len(indexes))}
	for i, val := range pcrsValue[pcrHashAlgo] {
		pcrList.Pcrs = append(pcrList.Pcrs, PCR{Index: i, Digest: val})
	}
	return pcrList, nil
}

func ReadNVAuthDigest(handle uint32) ([]byte, error) {
	tpm, err := getTpmHandle()
	if err != nil {
		return nil, err
	}
	defer tpm.Close()

	index, err := tpm.NewResourceContext(tpm2.Handle(handle))
	if err != nil {
		return nil, err
	}

	info, _, err := tpm.NVReadPublic(index)
	if err != nil {
		return nil, err
	}

	return info.AuthPolicy, nil
}

// CertifyNVCounter runs TPM2_NV_Certify on the NV counter at nvHandle, signed
// by the key at akHandle. nonce is a freshness token from the verifier; the
// TPM embeds it in the attestation so replays can be detected.
func CertifyNVCounter(akHandle, nvHandle uint32, nonce []byte) (NVCertification, error) {
	tpm, err := getTpmHandle()
	if err != nil {
		return NVCertification{}, err
	}
	defer tpm.Close()

	akCtx, err := tpm.NewResourceContext(tpm2.Handle(akHandle))
	if err != nil {
		return NVCertification{}, fmt.Errorf("cannot load signing key at 0x%08x: %w", akHandle, err)
	}
	nvCtx, err := tpm.NewResourceContext(tpm2.Handle(nvHandle))
	if err != nil {
		return NVCertification{}, fmt.Errorf("cannot load NV index 0x%08x: %w", nvHandle, err)
	}
	attest, sig, err := nvCertify(tpm, akCtx, tpm.OwnerHandleContext(), nvCtx, nonce)
	if err != nil {
		return NVCertification{}, err
	}
	attestBytes, err := mu.MarshalToBytes(attest)
	if err != nil {
		return NVCertification{}, fmt.Errorf("marshal attest: %w", err)
	}

	cert := NVCertification{Nonce: nonce, AttestBlob: attestBytes}
	switch sig.SigAlg {
	case tpm2.SigSchemeAlgRSASSA, tpm2.SigSchemeAlgRSAPSS:
		cert.RSASig = []byte(sig.Signature.RSASSA.Sig)
	case tpm2.SigSchemeAlgECDSA:
		cert.ECCSigR = []byte(sig.Signature.ECDSA.SignatureR)
		cert.ECCSigS = []byte(sig.Signature.ECDSA.SignatureS)
	default:
		return NVCertification{}, fmt.Errorf("unsupported signature algorithm 0x%04x", sig.SigAlg)
	}
	return cert, nil
}

// VerifyNVCounter verifies that cert was produced by the TPM holding the key
// whose public component is akPub and that the attestation is bound to nonce
// (replay protection). It returns the certified counter value on success.
func VerifyNVCounter(cert *NVCertification, akPub crypto.PublicKey, nonce []byte) (uint64, error) {
	if cert == nil {
		return 0, nil
	}

	digest := sha256.Sum256(cert.AttestBlob)

	switch pub := akPub.(type) {
	case *rsa.PublicKey:
		if len(cert.RSASig) == 0 {
			return 0, errors.New("RSA key but no RSA signature in certification")
		}
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], cert.RSASig); err != nil {
			return 0, fmt.Errorf("signature verification failed: %w", err)
		}
	case *ecdsa.PublicKey:
		if len(cert.ECCSigR) == 0 || len(cert.ECCSigS) == 0 {
			return 0, errors.New("ECDSA key but missing signature components in certification")
		}
		r := new(big.Int).SetBytes(cert.ECCSigR)
		s := new(big.Int).SetBytes(cert.ECCSigS)
		if !ecdsa.Verify(pub, digest[:], r, s) {
			return 0, errors.New("ECDSA signature verification failed")
		}
	default:
		return 0, fmt.Errorf("unsupported key type: %T", akPub)
	}

	var attest tpm2.Attest
	if _, err := mu.UnmarshalFromBytes(cert.AttestBlob, &attest); err != nil {
		return 0, fmt.Errorf("unmarshal attestation: %w", err)
	}
	if attest.Magic != tpm2.TPMGeneratedValue {
		return 0, fmt.Errorf("bad TPM_GENERATED magic: 0x%x", attest.Magic)
	}
	if attest.Type != tpm2.TagAttestNV {
		return 0, fmt.Errorf("unexpected attestation type 0x%04x, want 0x%04x (NV)", attest.Type, tpm2.TagAttestNV)
	}
	if !bytes.Equal([]byte(attest.ExtraData), nonce) {
		return 0, errors.New("nonce mismatch: possible replay attack")
	}

	nvInfo := attest.Attested.NV
	if nvInfo == nil {
		return 0, errors.New("attestation missing NV certify info")
	}
	if len(nvInfo.NVContents) != 8 {
		return 0, fmt.Errorf("unexpected NV contents length %d, want 8", len(nvInfo.NVContents))
	}

	return binary.BigEndian.Uint64(nvInfo.NVContents), nil
}

// nvCertify executes TPM2_NV_Certify.
func nvCertify(
	tpm *tpm2.TPMContext,
	signCtx, authCtx, nvCtx tpm2.ResourceContext,
	nonce []byte,
) (*tpm2.Attest, *tpm2.Signature, error) {
	inScheme := &tpm2.SigScheme{Scheme: tpm2.SigSchemeAlgNull}
	var attest *tpm2.Attest
	var sig *tpm2.Signature
	err := tpm.StartCommand(tpm2.CommandNVCertify).
		AddHandles(
			tpm2.UseResourceContextWithAuth(signCtx, nil),
			tpm2.UseResourceContextWithAuth(authCtx, nil),
			tpm2.UseHandleContext(nvCtx),
		).
		AddParams(tpm2.Data(nonce), inScheme, uint16(8), uint16(0)).
		Run(nil, mu.Sized(&attest), &sig)
	if err != nil {
		return nil, nil, fmt.Errorf("TPM2_NV_Certify: %w", err)
	}
	return attest, sig, nil
}
