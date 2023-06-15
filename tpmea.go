package tpmea

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/linux"
	"github.com/canonical/go-tpm2/policyutil"
	"github.com/canonical/go-tpm2/util"
)

const (
	TpmDevicePath = "/dev/tpmrm0"
)

type PCRHashAlgo int

const (
	AlgoSHA1   = PCRHashAlgo(0)
	AlgoSHA256 = PCRHashAlgo(1)
	AlgoSHA384 = PCRHashAlgo(2)
	AlgoSHA512 = PCRHashAlgo(3)
)

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

func getPCRAlgo(algo PCRHashAlgo) tpm2.HashAlgorithmId {
	switch algo {
	case AlgoSHA1:
		return tpm2.HashAlgorithmSHA1
	case AlgoSHA256:
		return tpm2.HashAlgorithmSHA256
	case AlgoSHA384:
		return tpm2.HashAlgorithmSHA384
	case AlgoSHA512:
		return tpm2.HashAlgorithmSHA512
	default:
		return tpm2.HashAlgorithmSHA256
	}
}

func getTpmHandle() (*tpm2.TPMContext, error) {
	tcti, err := linux.OpenDevice(TpmDevicePath)
	if err != nil {
		return nil, err
	}
	return tpm2.NewTPMContext(tcti), nil
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
				KeyBits:   2048,
				Exponent:  uint32(key.E)}},
		Unique: &tpm2.PublicIDU{RSA: key.N.Bytes()}}
}

func authorizeObject(tpm *tpm2.TPMContext, key *rsa.PublicKey, approvedPol []byte, approvedPolSig []byte, pcrs []int, rbp RBP) (tpm2.SessionContext, error) {
	public := newExternalRSAPub(key)

	// null-hierarchy won't produce a valid ticket, go with owner
	keyCtx, err := tpm.LoadExternal(nil, &public, tpm2.HandleOwner)
	if err != nil {
		return nil, err
	}
	defer tpm.FlushContext(keyCtx)

	// approvedPolicy by itself is a digest, but approvedPolicySignature is a
	// signature over digest of approvedPolicy, so compute it first.
	approvedPolicyDigest, err := util.ComputePolicyAuthorizeDigest(tpm2.HashAlgorithmSHA256, approvedPol, nil)
	if err != nil {
		return nil, err
	}

	// check the signature and produce a ticket if it's valid
	signature := tpm2.Signature{
		SigAlg: tpm2.SigSchemeAlgRSASSA,
		Signature: &tpm2.SignatureU{
			RSASSA: &tpm2.SignatureRSASSA{
				Hash: tpm2.HashAlgorithmSHA256,
				Sig:  approvedPolSig}}}
	ticket, err := tpm.VerifySignature(keyCtx, approvedPolicyDigest, &signature)
	if err != nil {
		return nil, err
	}

	// start a policy session, a policy session will actually evaluate commands
	// in comparison to trial policy that only computes the final digest no matter
	// if run-time state doesn't match the provided state or not.
	polss, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)
	if err != nil {
		return nil, err
	}

	if rbp != (RBP{}) {
		index, err := tpm.NewResourceContext(tpm2.Handle(rbp.Counter))
		if err != nil {
			return nil, err
		}

		// if rbp is provide, first check the PolicyNV then PolicyPCR, in this
		// case the two policy will from a logical AND (PolicyPCR AND PolicyPCR).
		operandB := make([]byte, 8)
		binary.BigEndian.PutUint64(operandB, rbp.Check)
		err = tpm.PolicyNV(tpm.OwnerHandleContext(), index, polss, operandB, 0, tpm2.OpUnsignedLE, nil)
		if err != nil {
			return nil, err
		}
	}

	pcrSelections := tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: pcrs}}
	err = tpm.PolicyPCR(polss, nil, pcrSelections)
	if err != nil {
		return nil, err
	}

	// authorize policy will check if policies hold at runtime (i.e PCR values
	// match the expected value and counter holds true on the arithmetic op)
	err = tpm.PolicyAuthorize(polss, approvedPol, nil, keyCtx.Name(), ticket)
	if err != nil {
		return nil, err
	}

	return polss, nil
}

func GenKeyPair() (*rsa.PrivateKey, error) {
	// 2048 is the limit for TPM
	return rsa.GenerateKey(rand.Reader, 2048)
}

func GetKeyPemEncoding(key *rsa.PrivateKey) (private []byte, public []byte, err error) {
	privPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		},
	)

	if privPem == nil {
		return nil, nil, errors.New("failed to convert private key to PEM format")
	}

	pub := key.Public()
	pubPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(pub.(*rsa.PublicKey)),
		},
	)

	if pubPem == nil {
		return nil, nil, errors.New("failed to convert public key to PEM format")
	}

	return privPem, pubPem, nil
}

// ExtendPCR extends the provided PCR index with hash of the data,
// hash algorithm to use is determined by algo parameter.
func ExtendPCR(index int, algo PCRHashAlgo, data []byte) error {
	tpm, err := getTpmHandle()
	if err != nil {
		return err
	}
	defer tpm.Close()

	pcrHashAlgo := getPCRAlgo(algo)
	h := getPCRAlgo(algo).NewHash()
	h.Write(data)

	digest := tpm2.TaggedHashList{tpm2.MakeTaggedHash(pcrHashAlgo, h.Sum(nil))}
	return tpm.PCRExtend(tpm.PCRHandleContext(index), digest, nil)
}

// ResetPCR resets PCR value at the provide index, this only works on indexes
// 16 and 23, as per spec, other indexes are not resettable.
func ResetPCR(index int) error {
	if index == 16 || index == 23 {
		tpm, err := getTpmHandle()
		if err != nil {
			return err
		}
		defer tpm.Close()

		return tpm.PCRReset(tpm.PCRHandleContext(index), nil)
	}

	return errors.New("only PCR indexes 16 and 23 are resettable")
}

// ReadPCRs will read the value of PCR indexes provided by pcrs argument,
// the algo defines which banks should be read (e.g SHA1 or SHA256).
func ReadPCRs(pcrs []int, algo PCRHashAlgo) (PCRList, error) {
	tpm, err := getTpmHandle()
	if err != nil {
		return PCRList{}, err
	}
	defer tpm.Close()

	pcrHashAlgo := getPCRAlgo(algo)
	pcrSelections := tpm2.PCRSelectionList{{Hash: pcrHashAlgo, Select: pcrs}}
	_, pcrsValue, err := tpm.PCRRead(pcrSelections)
	if err != nil {
		return PCRList{}, err
	}

	pcrList := PCRList{Algo: algo, Pcrs: make(PCRS, 0)}
	for i, val := range pcrsValue[pcrHashAlgo] {
		pcrList.Pcrs = append(pcrList.Pcrs, PCR{i, val})
	}

	return pcrList, nil
}

// DefineMonotonicCounter will define a monotonic NV counter at the given index,
// function will initialize the counter and returns the its current value.
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

	index, err := tpm.NewResourceContext(tpm2.Handle(handle))
	if err == nil {
		// handle already exists, check if the attributes match what we need,
		// is so, we just use it.
		nvpub, _, err := tpm.NVReadPublic(index)
		if err != nil {
			return 0, err
		}

		attr := tpm2.AttrNVOwnerRead | tpm2.AttrNVOwnerWrite
		if (nvpub.Attrs & attr) != attr {
			return 0, errors.New("a counter at provide handle already exists with mismatched attributes")
		}

		// if it is not initialized, initialize it.
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

	nvpub := tpm2.NVPublic{
		Index:   tpm2.Handle(handle),
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeCounter.WithAttrs(tpm2.AttrNVOwnerRead | tpm2.AttrNVOwnerWrite),
		Size:    8}
	index, err = tpm.NVDefineSpace(tpm.OwnerHandleContext(), nil, &nvpub, nil)
	if err != nil {
		return 0, err
	}

	// this is necessary to initialize the counter.
	err = tpm.NVIncrement(tpm.OwnerHandleContext(), index, nil)
	if err != nil {
		return 0, err
	}

	return 1, nil
}

// IncreaseMonotonicCounter will increase the value of the monotonic counter at
// provided index, by one.
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

// GenerateAuthDigest will generate a authorization digest based on the provided
// public key. The returned authorizationDigest is the basis for creating mutable
// TPM policies.
//
// It is not necessary to run this function on a real TPM, running it on a
// true-to-spec emulator like swtpm will work.
func GenerateAuthDigest(key *rsa.PublicKey) (authDigest tpm2.Digest, err error) {
	tpm, err := getTpmHandle()
	if err != nil {
		return nil, err
	}
	defer tpm.Close()

	public := newExternalRSAPub(key)
	keyCtx, err := tpm.LoadExternal(nil, &public, tpm2.HandleNull)
	if err != nil {
		return nil, err
	}
	defer tpm.FlushContext(keyCtx)

	// we generate the auth digest in a trial session, no evaluation in TPM is
	// required, we are only interested in the final session digest
	triss, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypeTrial, nil, tpm2.HashAlgorithmSHA256)
	if err != nil {
		return nil, err
	}
	defer tpm.FlushContext(triss)

	// ask TPM to compute the session digest and retrieve it
	err = tpm.PolicyAuthorize(triss, nil, nil, keyCtx.Name(), nil)
	if err != nil {
		return nil, err
	}

	return tpm.PolicyGetDigest(triss)
}

// GenerateSignedPolicy will compute the digest of PolicyNV and PolicyPCR and
// signs it using the provided key. It will return the approvedPolicy which
// represent the run-time state that the target TPM should match (i.e PCR values),
// and approvedPolicySignature which is the signature of the approvedPolicy that gets
// validated on the target TPM to match the key which is used to generate
// authorizationDigest from GenerateAuthDigest().
//
// The private key must be belong to the pair that is used with GenerateAuthDigest.
func GenerateSignedPolicy(key *rsa.PrivateKey, pcrList PCRList, rbp RBP) (approvedPol []byte, approvedPolSig []byte, err error) {
	tpm, err := getTpmHandle()
	if err != nil {
		return nil, nil, err
	}
	defer tpm.Close()

	public := newExternalRSAPub(&key.PublicKey)
	keyCtx, err := tpm.LoadExternal(nil, &public, tpm2.HandleNull)
	if err != nil {
		return nil, nil, err
	}
	defer tpm.FlushContext(keyCtx)

	// we generate the policy digest in a trial session, because we don't want to
	// evaluate the provided state, we are only interested in the final session
	// digest that is computed as result of executing TPM commands, here PolicyNV and PolicyPCR.
	triss, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypeTrial, nil, tpm2.HashAlgorithmSHA256)
	if err != nil {
		return nil, nil, err
	}
	defer tpm.FlushContext(triss)

	if rbp != (RBP{}) {
		index, err := tpm.NewResourceContext(tpm2.Handle(rbp.Counter))
		if err != nil {
			return nil, nil, err
		}

		operandB := make([]byte, 8)
		binary.BigEndian.PutUint64(operandB, rbp.Check)
		err = tpm.PolicyNV(tpm.OwnerHandleContext(), index, triss, operandB, 0, tpm2.OpUnsignedLE, nil)
		if err != nil {
			return nil, nil, err
		}
	}

	sel := make([]int, 0)
	digests := make(map[int]tpm2.Digest)
	for _, pcr := range pcrList.Pcrs {
		sel = append(sel, pcr.Index)
		digests[pcr.Index] = pcr.Digest
	}

	pcrHashAlgo := getPCRAlgo(pcrList.Algo)
	pcrSelections := tpm2.PCRSelectionList{{Hash: pcrHashAlgo, Select: sel}}
	pcrValues := tpm2.PCRValues{pcrHashAlgo: digests}
	pcrDigests, err := policyutil.ComputePCRDigest(pcrHashAlgo, pcrSelections, pcrValues)
	if err != nil {
		return nil, nil, err
	}

	err = tpm.PolicyPCR(triss, pcrDigests, pcrSelections)
	if err != nil {
		return nil, nil, err
	}

	// get the final session digest from TPM
	policyDigest, err := tpm.PolicyGetDigest(triss)
	if err != nil {
		return nil, nil, err
	}

	// PolicyAuthorize from util is not executing any TPM commands, it just
	// computes digest of policyDigest and signs it with provided key, bad
	// naming on the go-tpm2.
	scheme := tpm2.SigScheme{
		Scheme: tpm2.SigSchemeAlgRSASSA,
		Details: &tpm2.SigSchemeU{
			RSASSA: &tpm2.SigSchemeRSASSA{
				HashAlg: tpm2.HashAlgorithmSHA256}}}
	_, s, err := util.PolicyAuthorize(key, &scheme, policyDigest, nil)
	return policyDigest, s.Signature.RSASSA.Sig, err
}

// SealSecret will write the provide secret to the TPM. The authDigest parameter
// binds the unseal operation with valid and singed policy.
func SealSecret(handle uint32, authDigest []byte, secret []byte) error {
	tpm, err := getTpmHandle()
	if err != nil {
		return err
	}
	defer tpm.Close()

	// ignore error from NewResourceContext, maybe handle doesn't exist,
	// we catch other errors at NVDefineSpace anyways.
	index, err := tpm.NewResourceContext(tpm2.Handle(handle))
	if err == nil {
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

// UnsealSecret will read the secret from the TPM. To read the secret the
// approvedPolicy and approvedPolicySignature (result of GenerateSignedPolicy)
// most be provided, plus the actual PolicyPCR and PolicyNV that will get evaluated
// at run time in TPM. If approvedPolicy is signed with the valid key and provided
// TPM states matches the run-time state of the TPM, the secret is returned.
func UnsealSecret(handle uint32, key *rsa.PublicKey, approvedPol []byte, approvedPolSig []byte, pcrs []int, rbp RBP) ([]byte, error) {
	tpm, err := getTpmHandle()
	if err != nil {
		return nil, err
	}
	defer tpm.Close()

	// don't bother authorizing, if the handle is not valid
	index, err := tpm.NewResourceContext(tpm2.Handle(handle))
	if err != nil {
		return nil, err
	}

	// perform the TPM commands in order, this will work only if policy signature
	// is valid and session digest matches the auth (saved) digest of the object.
	polss, err := authorizeObject(tpm, key, approvedPol, approvedPolSig, pcrs, rbp)
	if err != nil {
		return nil, err
	}
	defer tpm.FlushContext(polss)

	pub, _, err := tpm.NVReadPublic(index)
	if err != nil {
		return nil, err
	}

	return tpm.NVRead(index, index, pub.Size, 0, polss)
}

// RotateAuthDigestKey generates signs the new auth public key using the old one,
// and generates a new Authorization Digest using new key.
//
// It is not necessary to run this function on a real TPM, running it on a
// true-to-spec emulator like swtpm will work.
func RotateAuthDigestKey(oldKey *rsa.PrivateKey, newKey *rsa.PublicKey) (newkeySig []byte, newAuthDigest tpm2.Digest, err error) {
	message, err := json.Marshal(newKey)
	if err != nil {
		return nil, nil, err
	}

	sh := crypto.SHA256.New()
	sh.Write(message)
	hash := sh.Sum(nil)
	signature, err := rsa.SignPKCS1v15(nil, oldKey, crypto.SHA256, hash)
	if err != nil {
		return nil, nil, err
	}

	tpm, err := getTpmHandle()
	if err != nil {
		return nil, nil, err
	}
	defer tpm.Close()

	public := newExternalRSAPub(newKey)
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

	// ask TPM to compute the session digest and retrieve it
	err = tpm.PolicyAuthorize(triss, nil, nil, keyCtx.Name(), nil)
	if err != nil {
		return nil, nil, err
	}

	digest, err := tpm.PolicyGetDigest(triss)
	if err != nil {
		return nil, nil, err
	}

	return signature, digest, nil
}

// RotateAuthDigestWithPolicy will first do a RotateAuthDigestKey and then
// signs the policy using new key
//
// It is not necessary to run this function on a real TPM, running it on a
// true-to-spec emulator like swtpm will work.
func RotateAuthDigestWithPolicy(oldKey *rsa.PrivateKey, newKey *rsa.PrivateKey, pcrList PCRList, rbp RBP) (newkeySig []byte, newAuthDigest tpm2.Digest, approvedPolNewSig []byte, err error) {
	newkeySig, newAuthDigest, err = RotateAuthDigestKey(oldKey, &newKey.PublicKey)
	if err != nil {
		return nil, nil, nil, err
	}

	_, approvedPolNewSig, err = GenerateSignedPolicy(newKey, pcrList, rbp)
	if err != nil {
		return nil, nil, nil, err
	}

	return newkeySig, newAuthDigest, approvedPolNewSig, nil
}

// VerifyAuthDigestRotation verifies that the new key signed by the old key,
// this is needed when the target TPM is doing a Authorization Digest rotation
// using a new key.
func VerifyAuthDigestRotation(oldKey *rsa.PublicKey, newKey *rsa.PublicKey, newkeySig []byte) error {
	message, err := json.Marshal(newKey)
	if err != nil {
		return err
	}

	sh := crypto.SHA256.New()
	sh.Write(message)
	hash := sh.Sum(nil)
	return rsa.VerifyPKCS1v15(oldKey, crypto.SHA256, hash, newkeySig)
}

// ResealSecretWithNewAuthDigest will first validates the new key by calling
// VerifyAuthDigestRotation, then unseals the secret using old key and policies,
// then reseals it again using the new Authorization Digest that is bind to the
// new key, meaning subsequent unseal operations require policies that are signed
// with the new key.
func ResealSecretWithNewAuthDigest(handle uint32, oldKey *rsa.PublicKey, newKey *rsa.PublicKey, newkeySig []byte, newAuthDigest tpm2.Digest, approvedPol []byte, approvedPolSig []byte, pcrs []int, rbp RBP) error {
	err := VerifyAuthDigestRotation(oldKey, newKey, newkeySig)
	if err != nil {
		return err
	}

	secret, err := UnsealSecret(handle, oldKey, approvedPol, approvedPolSig, pcrs, rbp)
	if err != nil {
		return err
	}

	return SealSecret(handle, newAuthDigest, secret)
}
