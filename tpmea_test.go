package tpmea

import (
	"bytes"
	"math/rand"
	"testing"
)

const (
	RESETABLE_PCR_INDEX = 16
	NV_INDEX            = 0x1500016
	NV_COUNTER_INDEX    = 0x1500017
)

var PCR_INDEXES = []int{0, 1, 2, 3, 4, 5}

func TestGenerateAuthDigest(t *testing.T) {
	key, _ := GenKeyPair()
	_, err := GenerateAuthDigest(&key.PublicKey)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
}

func TestReadPCRs(t *testing.T) {
	_, err := ReadPCRs(PCR_INDEXES, AlgoSHA256)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
}

func TestPCRReset(t *testing.T) {
	err := ExtendPCR(RESETABLE_PCR_INDEX, AlgoSHA256, []byte("DATA_TO_EXTEND"))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	err = ResetPCR(RESETABLE_PCR_INDEX)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	afterResetPcrs, err := ReadPCRs([]int{RESETABLE_PCR_INDEX}, AlgoSHA256)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	after := afterResetPcrs.Pcrs[0].Digest
	reset := make([]byte, 32)
	if bytes.Equal(after, reset) != true {
		t.Fatalf("Expected equal PCR values, got %x != %x", after, reset)
	}
}

func TestPCRExtend(t *testing.T) {
	beforeExtendPcrs, err := ReadPCRs([]int{RESETABLE_PCR_INDEX}, AlgoSHA256)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	err = ExtendPCR(RESETABLE_PCR_INDEX, AlgoSHA256, []byte("DATA_TO_EXTEND"))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	afterExtendPcrs, err := ReadPCRs([]int{RESETABLE_PCR_INDEX}, AlgoSHA256)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	before := beforeExtendPcrs.Pcrs[0].Digest
	after := afterExtendPcrs.Pcrs[0].Digest
	if bytes.Equal(before, after) {
		t.Fatalf("Expected different PCR values, got %x = %x", before, after)
	}
}

func TestMonotonicCounter(t *testing.T) {
	initCounter, err := DefineMonotonicCounter(NV_COUNTER_INDEX)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	incCounter, err := IncreaseMonotonicCounter(NV_COUNTER_INDEX)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if incCounter != (initCounter + 1) {
		t.Fatalf("Expected counter value of %d, got %d", (initCounter + 1), incCounter)
	}
}

func TestSimpleSealUnseal(t *testing.T) {
	key, _ := GenKeyPair()
	authorizationDigest, err := GenerateAuthDigest(&key.PublicKey)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// since this should run on a emulated TPM, we might start will PCR values
	// being zero, so extend them to non-zero first.
	for _, index := range PCR_INDEXES {
		err = ExtendPCR(index, AlgoSHA256, []byte("DATA_TO_EXTEND"))
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
	}

	pcrs, err := ReadPCRs(PCR_INDEXES, AlgoSHA256)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	sealingPcrs := make(PCRS, 0)
	for _, index := range PCR_INDEXES {
		sealingPcrs = append(sealingPcrs, PCR{Index: pcrs.Pcrs[index].Index, Digest: pcrs.Pcrs[index].Digest})
	}
	pcrsList := PCRList{Algo: AlgoSHA256, Pcrs: sealingPcrs}

	desiredPolicy, desiredPolicySignature, err := GenerateSignedPolicy(key, pcrsList, RBP{})
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	writtenSecret := []byte("THIS_IS_VERY_SECRET")
	err = SealSecret(NV_INDEX, key.PublicKey,
		authorizationDigest,
		desiredPolicy,
		desiredPolicySignature,
		PCR_INDEXES,
		RBP{},
		writtenSecret)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	readSecret, err := UnsealSecret(NV_INDEX,
		key.PublicKey,
		desiredPolicy,
		desiredPolicySignature,
		PCR_INDEXES,
		RBP{})
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if bytes.Equal(writtenSecret, readSecret) != true {
		t.Fatalf("Expected %s, got %s", writtenSecret, readSecret)
	}
}

func TestMutablePolicySealUnseal(t *testing.T) {
	key, _ := GenKeyPair()
	authorizationDigest, err := GenerateAuthDigest(&key.PublicKey)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// since this should run on a emulated TPM, we might start will PCR values
	// being zero, so extend them to non-zero first.
	for _, index := range PCR_INDEXES {
		err = ExtendPCR(index, AlgoSHA256, []byte("DATA_TO_EXTEND"))
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
	}

	pcrs, err := ReadPCRs(PCR_INDEXES, AlgoSHA256)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	sealingPcrs := make(PCRS, 0)
	for _, index := range PCR_INDEXES {
		sealingPcrs = append(sealingPcrs, PCR{Index: pcrs.Pcrs[index].Index, Digest: pcrs.Pcrs[index].Digest})
	}
	pcrsList := PCRList{Algo: AlgoSHA256, Pcrs: sealingPcrs}

	desiredPolicy, desiredPolicySignature, err := GenerateSignedPolicy(key, pcrsList, RBP{})
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	writtenSecret := []byte("THIS_IS_VERY_SECRET")
	err = SealSecret(NV_INDEX, key.PublicKey,
		authorizationDigest,
		desiredPolicy,
		desiredPolicySignature,
		PCR_INDEXES,
		RBP{},
		writtenSecret)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	readSecret, err := UnsealSecret(NV_INDEX,
		key.PublicKey,
		desiredPolicy,
		desiredPolicySignature,
		PCR_INDEXES,
		RBP{})
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if bytes.Equal(writtenSecret, readSecret) != true {
		t.Fatalf("Expected %s, got %s", writtenSecret, readSecret)
	}

	// randomly select and extend a PCR index
	pick := PCR_INDEXES[rand.Intn(len(PCR_INDEXES))]
	err = ExtendPCR(pick, AlgoSHA256, []byte("EXTEND_DATA_TWO"))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	pcrs, err = ReadPCRs(PCR_INDEXES, AlgoSHA256)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// this must fail due to PCR mismatch
	_, err = UnsealSecret(NV_INDEX,
		key.PublicKey,
		desiredPolicy,
		desiredPolicySignature,
		PCR_INDEXES,
		RBP{})
	if err == nil {
		t.Fatalf("Expected error, got nothing!")
	}

	sealingPcrs = make(PCRS, 0)
	for _, index := range PCR_INDEXES {
		sealingPcrs = append(sealingPcrs, PCR{Index: pcrs.Pcrs[index].Index, Digest: pcrs.Pcrs[index].Digest})
	}
	pcrsList = PCRList{Algo: AlgoSHA256, Pcrs: sealingPcrs}

	desiredPolicy, desiredPolicySignature, err = GenerateSignedPolicy(key, pcrsList, RBP{})
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	readSecret, err = UnsealSecret(NV_INDEX,
		key.PublicKey,
		desiredPolicy,
		desiredPolicySignature,
		PCR_INDEXES,
		RBP{})
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if bytes.Equal(writtenSecret, readSecret) != true {
		t.Fatalf("Expected %s, got %s", writtenSecret, readSecret)
	}
}

func TestMutablePolicySealUnsealWithRollbackProtection(t *testing.T) {
	key, _ := GenKeyPair()
	authorizationDigest, err := GenerateAuthDigest(&key.PublicKey)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// since this should run on a emulated TPM, we might start will PCR values
	// being zero, so extend them to non-zero first.
	for _, index := range PCR_INDEXES {
		err = ExtendPCR(index, AlgoSHA256, []byte("DATA_TO_EXTEND"))
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
	}

	initCounter, err := DefineMonotonicCounter(NV_COUNTER_INDEX)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	rbp := RBP{Counter: NV_COUNTER_INDEX, Check: initCounter}

	pcrs, err := ReadPCRs(PCR_INDEXES, AlgoSHA256)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	sealingPcrs := make(PCRS, 0)
	for _, index := range PCR_INDEXES {
		sealingPcrs = append(sealingPcrs, PCR{Index: pcrs.Pcrs[index].Index, Digest: pcrs.Pcrs[index].Digest})
	}
	pcrsList := PCRList{Algo: AlgoSHA256, Pcrs: sealingPcrs}

	desiredPolicy, desiredPolicySignature, err := GenerateSignedPolicy(key, pcrsList, rbp)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	writtenSecret := []byte("THIS_IS_VERY_SECRET")
	err = SealSecret(NV_INDEX, key.PublicKey,
		authorizationDigest,
		desiredPolicy,
		desiredPolicySignature,
		PCR_INDEXES,
		rbp,
		writtenSecret)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	readSecret, err := UnsealSecret(NV_INDEX,
		key.PublicKey,
		desiredPolicy,
		desiredPolicySignature,
		PCR_INDEXES,
		rbp)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if bytes.Equal(writtenSecret, readSecret) != true {
		t.Fatalf("Expected %s, got %s", writtenSecret, readSecret)
	}

	// randomly select and extend a PCR index
	pick := PCR_INDEXES[rand.Intn(len(PCR_INDEXES))]
	err = ExtendPCR(pick, AlgoSHA256, []byte("EXTEND_DATA_TWO"))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	pcrs, err = ReadPCRs(PCR_INDEXES, AlgoSHA256)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// this must fail due to PCR mismatch
	_, err = UnsealSecret(NV_INDEX,
		key.PublicKey,
		desiredPolicy,
		desiredPolicySignature,
		PCR_INDEXES,
		rbp)
	if err == nil {
		t.Fatalf("Expected error, got nothing!")
	}

	sealingPcrs = make(PCRS, 0)
	for _, index := range PCR_INDEXES {
		sealingPcrs = append(sealingPcrs, PCR{Index: pcrs.Pcrs[index].Index, Digest: pcrs.Pcrs[index].Digest})
	}
	pcrsList = PCRList{Algo: AlgoSHA256, Pcrs: sealingPcrs}

	desiredPolicy, desiredPolicySignature, err = GenerateSignedPolicy(key, pcrsList, rbp)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	readSecret, err = UnsealSecret(NV_INDEX,
		key.PublicKey,
		desiredPolicy,
		desiredPolicySignature,
		PCR_INDEXES,
		rbp)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if bytes.Equal(writtenSecret, readSecret) != true {
		t.Fatalf("Expected %s, got %s", writtenSecret, readSecret)
	}

	// not lets increase the counter
	incCounter, err := IncreaseMonotonicCounter(NV_COUNTER_INDEX)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// this should fail because the counter arithmetic op (ULE) don't hold anymore
	_, err = UnsealSecret(NV_INDEX,
		key.PublicKey,
		desiredPolicy,
		desiredPolicySignature,
		PCR_INDEXES,
		rbp)
	if err == nil {
		t.Fatalf("Expected error, got nothing!")
	}

	// update the policy and try again
	rbp.Check = incCounter
	desiredPolicy, desiredPolicySignature, err = GenerateSignedPolicy(key, pcrsList, rbp)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	readSecret, err = UnsealSecret(NV_INDEX,
		key.PublicKey,
		desiredPolicy,
		desiredPolicySignature,
		PCR_INDEXES,
		rbp)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if bytes.Equal(writtenSecret, readSecret) != true {
		t.Fatalf("Expected %s, got %s", writtenSecret, readSecret)
	}
}
