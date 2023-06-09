package tpmea

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/linux"
	tmpl "github.com/canonical/go-tpm2/templates"
	"github.com/canonical/go-tpm2/util"
)

const (
	//TpmDevicePath is the TPM device file path
	TpmDevicePath = "/dev/tpmrm0"
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

func GenAuthDigest(key *rsa.PrivateKey) (tpm2.Digest, error) {
	tpm, err := getTpmHandle()
	if err != nil {
		return nil, err
	}
	defer tpm.Close()

	public := util.NewExternalRSAPublicKeyWithDefaults(tmpl.KeyUsageSign|tmpl.KeyUsageDecrypt, &key.PublicKey)
	private := &tpm2.Sensitive{
		Type:      tpm2.ObjectTypeRSA,
		Sensitive: &tpm2.SensitiveCompositeU{RSA: key.Primes[0].Bytes()},
	}

	// should we use HandleOwner?
	keyCtx, err := tpm.LoadExternal(private, public, tpm2.HandleNull)
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

func GenSignedPolicy(key *rsa.PrivateKey, pcrs SHA256PCRList) ([]byte, error) {
	tpm, err := getTpmHandle()
	if err != nil {
		return nil, err
	}
	defer tpm.Close()

	triss, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypeTrial, nil, tpm2.HashAlgorithmSHA256)
	if err != nil {
		return nil, err
	}
	defer tpm.FlushContext(triss)

	sel := make([]int, 0)
	digests := make(map[int]tpm2.Digest)
	for _, pcr := range pcrs {
		sel = append(sel, pcr.Index)
		digests[pcr.Index] = pcr.Digest
	}

	pcrSelections := tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: sel}}
	pcrValues := tpm2.PCRValues{tpm2.HashAlgorithmSHA256: digests}
	pcrDigests, err := util.ComputePCRDigest(tpm2.HashAlgorithmSHA256, pcrSelections, pcrValues)
	if err != nil {
		return nil, err
	}

	err = tpm.PolicyPCR(triss, pcrDigests, pcrSelections)
	if err != nil {
		return nil, err
	}

	digest, err := tpm.PolicyGetDigest(triss)
	if err != nil {
		return nil, err
	}

	sumOfDigest := sha256.Sum256(digest)
	return rsa.SignPKCS1v15(nil, key, crypto.SHA256, sumOfDigest[:])
}
