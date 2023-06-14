package tpmea

import (
	"bytes"
	"math/rand"
	"testing"
)

const (
	RESETABLE_PCR_INDEX = 16
	NV_INDEX            = 0x1500016
)

var PCR_INDEX = []int{0, 1, 2, 3, 4, 5}

func TestGenerateAuthDigest(t *testing.T) {
	key, _ := GenKeyPair()
	_, err := GenerateAuthDigest(&key.PublicKey)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestReadPCRs(t *testing.T) {
	_, err := ReadPCRs(PCR_INDEX, AlgoSHA256)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestPCRReset(t *testing.T) {
	err := ExtendPCR(RESETABLE_PCR_INDEX, AlgoSHA256, []byte("DATA_TO_EXTEND"))
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	err = ResetPCR(RESETABLE_PCR_INDEX)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	afterResetPcrs, err := ReadPCRs([]int{RESETABLE_PCR_INDEX}, AlgoSHA256)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	after := afterResetPcrs.Pcrs[0].Digest
	reset := make([]byte, 32)
	if bytes.Equal(after, reset) != true {
		t.Errorf("Expected equal PCR values, got %x != %x", after, reset)
	}
}

func TestPCRExtend(t *testing.T) {
	beforeExtendPcrs, err := ReadPCRs([]int{RESETABLE_PCR_INDEX}, AlgoSHA256)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	err = ExtendPCR(RESETABLE_PCR_INDEX, AlgoSHA256, []byte("DATA_TO_EXTEND"))
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	afterExtendPcrs, err := ReadPCRs([]int{RESETABLE_PCR_INDEX}, AlgoSHA256)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	before := beforeExtendPcrs.Pcrs[0].Digest
	after := afterExtendPcrs.Pcrs[0].Digest
	if bytes.Equal(before, after) {
		t.Errorf("Expected different PCR values, got %x = %x", before, after)
	}
}

func TestSimpleSealUnseal(t *testing.T) {
	key, _ := GenKeyPair()
	authorizationDigest, err := GenerateAuthDigest(&key.PublicKey)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// since this should run on a emulated TPM, we might start will PCR values
	// being zero, so extend them to non-zero first.
	for _, index := range PCR_INDEX {
		err = ExtendPCR(index, AlgoSHA256, []byte("DATA_TO_EXTEND"))
		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}
	}

	pcrs, err := ReadPCRs(PCR_INDEX, AlgoSHA256)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	sealingPcrs := make(PCRS, 0)
	for _, index := range PCR_INDEX {
		sealingPcrs = append(sealingPcrs, PCR{Index: pcrs.Pcrs[index].Index, Digest: pcrs.Pcrs[index].Digest})
	}
	pcrsList := PCRList{Algo: AlgoSHA256, Pcrs: sealingPcrs}

	desiredPolicy, desiredPolicySignature, err := GenerateSignedPolicy(key, pcrsList, false)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	writtenSecret := []byte("THIS_IS_VERY_SECRET")
	err = SealSecret(NV_INDEX, key.PublicKey,
		authorizationDigest,
		desiredPolicy,
		desiredPolicySignature,
		PCR_INDEX,
		writtenSecret)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	readSecret, err := UnsealSecret(NV_INDEX,
		key.PublicKey,
		desiredPolicy,
		desiredPolicySignature,
		PCR_INDEX)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if bytes.Equal(writtenSecret, readSecret) != true {
		t.Errorf("Expected %s, got %s", writtenSecret, readSecret)
	}
}

func TestMutablePolicySealUnseal(t *testing.T) {
	key, _ := GenKeyPair()
	authorizationDigest, err := GenerateAuthDigest(&key.PublicKey)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// since this should run on a emulated TPM, we might start will PCR values
	// being zero, so extend them to non-zero first.
	for _, index := range PCR_INDEX {
		err = ExtendPCR(index, AlgoSHA256, []byte("DATA_TO_EXTEND"))
		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}
	}

	pcrs, err := ReadPCRs(PCR_INDEX, AlgoSHA256)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	sealingPcrs := make(PCRS, 0)
	for _, index := range PCR_INDEX {
		sealingPcrs = append(sealingPcrs, PCR{Index: pcrs.Pcrs[index].Index, Digest: pcrs.Pcrs[index].Digest})
	}
	pcrsList := PCRList{Algo: AlgoSHA256, Pcrs: sealingPcrs}

	desiredPolicy, desiredPolicySignature, err := GenerateSignedPolicy(key, pcrsList, false)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	writtenSecret := []byte("THIS_IS_VERY_SECRET")
	err = SealSecret(NV_INDEX, key.PublicKey,
		authorizationDigest,
		desiredPolicy,
		desiredPolicySignature,
		PCR_INDEX,
		writtenSecret)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	readSecret, err := UnsealSecret(NV_INDEX,
		key.PublicKey,
		desiredPolicy,
		desiredPolicySignature,
		PCR_INDEX)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if bytes.Equal(writtenSecret, readSecret) != true {
		t.Errorf("Expected %s, got %s", writtenSecret, readSecret)
	}

	// randomly select and extend a PCR index
	pick := PCR_INDEX[rand.Intn(len(PCR_INDEX))]
	err = ExtendPCR(pick, AlgoSHA256, []byte("EXTEND_DATA_TWO"))
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	pcrs, err = ReadPCRs(PCR_INDEX, AlgoSHA256)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// this must fail due to PCR mismatch
	_, err = UnsealSecret(NV_INDEX,
		key.PublicKey,
		desiredPolicy,
		desiredPolicySignature,
		PCR_INDEX)
	if err == nil {
		t.Errorf("Expected error, got nothing!")
	}

	sealingPcrs = make(PCRS, 0)
	for _, index := range PCR_INDEX {
		sealingPcrs = append(sealingPcrs, PCR{Index: pcrs.Pcrs[index].Index, Digest: pcrs.Pcrs[index].Digest})
	}
	pcrsList = PCRList{Algo: AlgoSHA256, Pcrs: sealingPcrs}

	desiredPolicy, desiredPolicySignature, err = GenerateSignedPolicy(key, pcrsList, false)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	readSecret, err = UnsealSecret(NV_INDEX,
		key.PublicKey,
		desiredPolicy,
		desiredPolicySignature,
		PCR_INDEX)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if bytes.Equal(writtenSecret, readSecret) != true {
		t.Errorf("Expected %s, got %s", writtenSecret, readSecret)
	}
}
