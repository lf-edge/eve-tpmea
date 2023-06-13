package tpmea

import (
	"bytes"
	"testing"
)

func TestGenerateAuthDigest(t *testing.T) {
	key, _ := GenKeyPair()
	authorizationDigest, err := GenerateAuthDigest(&key.PublicKey)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	t.Logf("Authorization Digest : %x", authorizationDigest)
}

func TestReadPCRs(t *testing.T) {
	_, err := ReadPCRs([]int{0}, AlgoSHA256)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

//func TestPCRReset(t *testing.T) {
//	err := ResetPCR(16)
//	if err != nil {
//		t.Errorf("Expected no error, got %v", err)
//	}

//	pcrs, err := ReadPCRs([]int{0}, AlgoSHA256)
//	byes

//func TestPCRExtend(t *testing.T) {
//	pcrs, err := ReadPCRs([]int{0}, AlgoSHA256)
//	if err != nil {
//		t.Errorf("Expected no error, got %v", err)
//	}

//}

func TestSimpleSealUnseal(t *testing.T) {
	key, _ := GenKeyPair()
	authorizationDigest, err := GenerateAuthDigest(&key.PublicKey)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	pcrs, err := ReadPCRs([]int{0}, AlgoSHA256)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	pcrsList := PCRList{
		Algo: AlgoSHA256,
		Pcrs: []PCR{{
			Index:  0,
			Digest: pcrs.Pcrs[0].Digest}}}

	desiredPolicy, desiredPolicySignature, err := GenerateSignedPolicy(key, pcrsList, false)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	writtenSecret := []byte("THIS_IS_VERY_SECRET")
	err = SealSecret(0x1500016, key.PublicKey,
		authorizationDigest,
		desiredPolicy,
		desiredPolicySignature,
		[]int{0},
		writtenSecret)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	readSecret, err := UnsealSecret(0x1500016,
		key.PublicKey,
		desiredPolicy,
		desiredPolicySignature,
		[]int{0})

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if bytes.Equal(writtenSecret, readSecret) != true {
		t.Errorf("Expected %s, got %s", writtenSecret, readSecret)
	}
}
