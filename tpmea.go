package tpmea

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/linux"
	"github.com/canonical/go-tpm2/policyutil"
	"github.com/canonical/go-tpm2/util"
)

const (
	//TpmDevicePath is the TPM device file path
	TpmDevicePath = "/dev/tpmrm0"
	PolicyRef     = "eveos_policy.ref"
)

type SHA256PCR struct {
	Index  int
	Digest []byte
}

type SHA256PCRList []SHA256PCR

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

func GetKeyPemEncoding(key *rsa.PrivateKey) (private []byte, public []byte, err error) {
	privPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		},
	)

	if privPem == nil {
		return nil, nil, errors.New("failed to convert private key to pem format")
	}

	pub := key.Public()
	pubPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(pub.(*rsa.PublicKey)),
		},
	)

	if pubPem == nil {
		return nil, nil, errors.New("failed to convert public key to pem format")
	}

	return privPem, pubPem, nil
}

func GenKeyPair() (*rsa.PrivateKey, error) {
	// 2048 is the limit for TPM
	return rsa.GenerateKey(rand.Reader, 2048)
}

func ReadPCRs(pcrs []int) (SHA256PCRList, error) {
	tpm, err := getTpmHandle()
	if err != nil {
		return nil, err
	}
	defer tpm.Close()

	pcrSelections := tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: pcrs}}
	_, pcrsValue, err := tpm.PCRRead(pcrSelections)
	if err != nil {
		return nil, err
	}

	pcrList := make(SHA256PCRList, 0)
	for i, val := range pcrsValue[tpm2.HashAlgorithmSHA256] {
		pcrList = append(pcrList, SHA256PCR{i, val})
	}

	return pcrList, nil
}

func GenerateAuthDigest(key *rsa.PublicKey) (authorizationDigest tpm2.Digest, err error) {
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

	triss, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypeTrial, nil, tpm2.HashAlgorithmSHA256)
	if err != nil {
		return nil, err
	}
	defer tpm.FlushContext(triss)

	err = tpm.PolicyAuthorize(triss, nil, nil, keyCtx.Name(), nil)
	if err != nil {
		return nil, err
	}

	return tpm.PolicyGetDigest(triss)
}

func GenerateSignedPolicy(key *rsa.PrivateKey, pcrs SHA256PCRList, withRBP bool) (desiredPolicy []byte, desiredPolicySignature []byte, err error) {
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

	triss, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypeTrial, nil, tpm2.HashAlgorithmSHA256)
	if err != nil {
		return nil, nil, err
	}
	defer tpm.FlushContext(triss)

	if withRBP {
		return nil, nil, errors.New("RBP not implemented")
	}

	sel := make([]int, 0)
	digests := make(map[int]tpm2.Digest)
	for _, pcr := range pcrs {
		sel = append(sel, pcr.Index)
		digests[pcr.Index] = pcr.Digest
	}

	pcrSelections := tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: sel}}
	pcrValues := tpm2.PCRValues{tpm2.HashAlgorithmSHA256: digests}
	pcrDigests, err := policyutil.ComputePCRDigest(tpm2.HashAlgorithmSHA256, pcrSelections, pcrValues)
	if err != nil {
		return nil, nil, err
	}

	err = tpm.PolicyPCR(triss, pcrDigests, pcrSelections)
	if err != nil {
		return nil, nil, err
	}

	policyDigest, err := tpm.PolicyGetDigest(triss)
	if err != nil {
		return nil, nil, err
	}

	scheme := tpm2.SigScheme{
		Scheme: tpm2.SigSchemeAlgRSASSA,
		Details: &tpm2.SigSchemeU{
			RSASSA: &tpm2.SigSchemeRSASSA{
				HashAlg: tpm2.HashAlgorithmSHA256}}}

	_, s, err := util.PolicyAuthorize(key, &scheme, policyDigest, nil)
	return policyDigest, s.Signature.RSASSA.Sig, err
}

func SealSecret(handle uint32, key rsa.PublicKey, authDigest []byte, approvedPolicy []byte, approvedPolicySignature []byte, pcrs []int, secret []byte) error {
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
		Attrs:      tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVPolicyRead | tpm2.AttrNVPolicyWrite | tpm2.AttrNVReadStClear),
		AuthPolicy: authDigest,
		Size:       uint16(len(secret))}
	index, err = tpm.NVDefineSpace(tpm.OwnerHandleContext(), nil, &nvpub, nil)
	if err != nil {
		return err
	}

	// null-hierarchy won't produce a valid ticket, go with owner.
	public := newExternalRSAPub(&key)
	keyCtx, err := tpm.LoadExternal(nil, &public, tpm2.HandleOwner)
	if err != nil {
		return err
	}
	defer tpm.FlushContext(keyCtx)

	approvedPolicyAuthDigest, err := util.ComputePolicyAuthorizeDigest(tpm2.HashAlgorithmSHA256, approvedPolicy, nil)
	if err != nil {
		return err
	}

	signature := tpm2.Signature{
		SigAlg: tpm2.SigSchemeAlgRSASSA,
		Signature: &tpm2.SignatureU{
			RSASSA: &tpm2.SignatureRSASSA{
				Hash: tpm2.HashAlgorithmSHA256,
				Sig:  approvedPolicySignature}}}

	ticket, err := tpm.VerifySignature(keyCtx, approvedPolicyAuthDigest, &signature)
	if err != nil {
		return err
	}

	polss, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)
	if err != nil {
		return err
	}
	defer tpm.FlushContext(polss)

	pcrSelections := tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: pcrs}}
	err = tpm.PolicyPCR(polss, nil, pcrSelections)
	if err != nil {
		return err
	}

	err = tpm.PolicyAuthorize(polss, approvedPolicy, nil, keyCtx.Name(), ticket)
	if err != nil {
		return err
	}

	return tpm.NVWrite(index, index, secret, 0, polss)
}

func UnsealSecret(handle uint32, key rsa.PublicKey, approvedPolicy []byte, approvedPolicySignature []byte, pcrs []int) ([]byte, error) {
	tpm, err := getTpmHandle()
	if err != nil {
		return nil, err
	}
	defer tpm.Close()

	// don't bother with auth, if the handle is not valid
	index, err := tpm.NewResourceContext(tpm2.Handle(handle))
	if err != nil {
		return nil, err
	}

	// null-hierarchy won't produce a valid ticket, go with owner
	public := newExternalRSAPub(&key)
	keyCtx, err := tpm.LoadExternal(nil, &public, tpm2.HandleOwner)
	if err != nil {
		return nil, err
	}
	defer tpm.FlushContext(keyCtx)

	approvedPolicyAuthDigest, err := util.ComputePolicyAuthorizeDigest(tpm2.HashAlgorithmSHA256, approvedPolicy, nil)
	if err != nil {
		return nil, err
	}

	signature := tpm2.Signature{
		SigAlg: tpm2.SigSchemeAlgRSASSA,
		Signature: &tpm2.SignatureU{
			RSASSA: &tpm2.SignatureRSASSA{
				Hash: tpm2.HashAlgorithmSHA256,
				Sig:  approvedPolicySignature}}}

	ticket, err := tpm.VerifySignature(keyCtx, approvedPolicyAuthDigest, &signature)
	if err != nil {
		return nil, err
	}

	polss, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)
	if err != nil {
		return nil, err
	}
	defer tpm.FlushContext(polss)

	pcrSelections := tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: pcrs}}
	err = tpm.PolicyPCR(polss, nil, pcrSelections)
	if err != nil {
		return nil, err
	}

	err = tpm.PolicyAuthorize(polss, approvedPolicy, nil, keyCtx.Name(), ticket)
	if err != nil {
		return nil, err
	}

	pub, _, err := tpm.NVReadPublic(index)
	if err != nil {
		return nil, err
	}
	return tpm.NVRead(index, index, pub.Size, 0, polss)
}
