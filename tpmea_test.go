package tpmea

import (
	"bytes"
	crand "crypto/rand"
	"crypto/rsa"
	"errors"
	"math/rand"
	"strings"
	"testing"

	"github.com/canonical/go-tpm2"
)

const (
	RESETABLE_PCR_INDEX = 16
	NV_INDEX            = 0x1500016
	NV_COUNTER_INDEX    = 0x1500017
)

var PCR_INDEXES = []int{0, 1, 2, 3, 4, 5}

// genTpmKeyPair generates a 2048 bit RSA key,
// 2048 bits is the limit for TPM.
func genTpmKeyPair() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(crand.Reader, 2048)
}

// extendPCR extends the provided PCR index with hash of the data,
// hash algorithm to use is determined by algo parameter.
func extendPCR(index int, algo PCRHashAlgo, data []byte) error {
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

// resetPCR resets PCR value at the provide index, this only works on indexes
// 16 and 23, as per spec, other indexes are not resettable.
func resetPCR(index int) error {
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

// readPCRs will read the value of PCR indexes provided by pcrs argument,
// the algo defines which banks should be read (e.g SHA1 or SHA256).
func readPCRs(pcrs []int, algo PCRHashAlgo) (PCRList, error) {
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

func TestGenerateAuthDigest(t *testing.T) {
	key, _ := genTpmKeyPair()
	_, err := GenerateAuthDigest(&key.PublicKey)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}
}

func TestReadPCRs(t *testing.T) {
	_, err := readPCRs(PCR_INDEXES, AlgoSHA256)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}
}

func TestPCRReset(t *testing.T) {
	err := extendPCR(RESETABLE_PCR_INDEX, AlgoSHA256, []byte("DATA_TO_EXTEND"))
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	err = resetPCR(RESETABLE_PCR_INDEX)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	afterResetPcrs, err := readPCRs([]int{RESETABLE_PCR_INDEX}, AlgoSHA256)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	after := afterResetPcrs.Pcrs[0].Digest
	reset := make([]byte, 32)
	if bytes.Equal(after, reset) != true {
		t.Fatalf("Expected equal PCR values, got %x != %x", after, reset)
	}
}

func TestPCRExtend(t *testing.T) {
	beforeExtendPcrs, err := readPCRs([]int{RESETABLE_PCR_INDEX}, AlgoSHA256)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	err = extendPCR(RESETABLE_PCR_INDEX, AlgoSHA256, []byte("DATA_TO_EXTEND"))
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	afterExtendPcrs, err := readPCRs([]int{RESETABLE_PCR_INDEX}, AlgoSHA256)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
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
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	updatedCounter, err := IncreaseMonotonicCounter(NV_COUNTER_INDEX)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	if updatedCounter != (initCounter + 1) {
		t.Fatalf("Expected counter value of %d, got %d", (initCounter + 1), updatedCounter)
	}
}

func TestSimpleSealUnseal(t *testing.T) {
	key, _ := genTpmKeyPair()
	authorizationDigest, err := GenerateAuthDigest(&key.PublicKey)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	// since this should run on a emulated TPM, we might start with PCR values
	// being zero, so extend them to a non-zero value first.
	for _, index := range PCR_INDEXES {
		err = extendPCR(index, AlgoSHA256, []byte("DATA_TO_EXTEND"))
		if err != nil {
			t.Fatalf("Expected no error, got  \"%v\"", err)
		}
	}

	pcrs, err := readPCRs(PCR_INDEXES, AlgoSHA256)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	sealingPcrs := make(PCRS, 0)
	for _, index := range PCR_INDEXES {
		sealingPcrs = append(sealingPcrs, PCR{Index: pcrs.Pcrs[index].Index, Digest: pcrs.Pcrs[index].Digest})
	}
	pcrsList := PCRList{Algo: AlgoSHA256, Pcrs: sealingPcrs}

	approvedPolicy, approvedPolicySignature, err := GenerateSignedPolicy(key, pcrsList, RBP{})
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	writtenSecret := []byte("THIS_IS_VERY_SECRET")
	err = SealSecret(NV_INDEX, authorizationDigest, writtenSecret)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	readSecret, err := UnsealSecret(NV_INDEX,
		&key.PublicKey,
		approvedPolicy,
		approvedPolicySignature,
		PCR_INDEXES,
		RBP{})
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	if bytes.Equal(writtenSecret, readSecret) != true {
		t.Fatalf("Expected %s, got %s", writtenSecret, readSecret)
	}
}

func TestMutablePolicySealUnseal(t *testing.T) {
	key, _ := genTpmKeyPair()
	authorizationDigest, err := GenerateAuthDigest(&key.PublicKey)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	// since this should run on a emulated TPM, we might start with PCR values
	// being zero, so extend them to a non-zero value first.
	for _, index := range PCR_INDEXES {
		err = extendPCR(index, AlgoSHA256, []byte("DATA_TO_EXTEND"))
		if err != nil {
			t.Fatalf("Expected no error, got  \"%v\"", err)
		}
	}

	pcrs, err := readPCRs(PCR_INDEXES, AlgoSHA256)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	sealingPcrs := make(PCRS, 0)
	for _, index := range PCR_INDEXES {
		sealingPcrs = append(sealingPcrs, PCR{Index: pcrs.Pcrs[index].Index, Digest: pcrs.Pcrs[index].Digest})
	}
	pcrsList := PCRList{Algo: AlgoSHA256, Pcrs: sealingPcrs}

	approvedPolicy, approvedPolicySignature, err := GenerateSignedPolicy(key, pcrsList, RBP{})
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	writtenSecret := []byte("THIS_IS_VERY_SECRET")
	err = SealSecret(NV_INDEX, authorizationDigest, writtenSecret)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	readSecret, err := UnsealSecret(NV_INDEX,
		&key.PublicKey,
		approvedPolicy,
		approvedPolicySignature,
		PCR_INDEXES,
		RBP{})
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	if bytes.Equal(writtenSecret, readSecret) != true {
		t.Fatalf("Expected %s, got %s", writtenSecret, readSecret)
	}

	// randomly select and extend a PCR index
	pick := PCR_INDEXES[rand.Intn(len(PCR_INDEXES))]
	err = extendPCR(pick, AlgoSHA256, []byte("EXTEND_DATA_TWO"))
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	pcrs, err = readPCRs(PCR_INDEXES, AlgoSHA256)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	// this must fail due to PCR mismatch
	_, err = UnsealSecret(NV_INDEX,
		&key.PublicKey,
		approvedPolicy,
		approvedPolicySignature,
		PCR_INDEXES,
		RBP{})
	if err != nil {
		if strings.Contains(err.Error(), "TPM_RC_VALUE") != true {
			t.Fatalf("Expected TPM_RC_VALUE error, got  \"%v\"", err)
		}
	} else {
		t.Fatalf("Expected TPM_RC_VALUE error, got nil")
	}

	sealingPcrs = make(PCRS, 0)
	for _, index := range PCR_INDEXES {
		sealingPcrs = append(sealingPcrs, PCR{Index: pcrs.Pcrs[index].Index, Digest: pcrs.Pcrs[index].Digest})
	}
	pcrsList = PCRList{Algo: AlgoSHA256, Pcrs: sealingPcrs}

	approvedPolicy, approvedPolicySignature, err = GenerateSignedPolicy(key, pcrsList, RBP{})
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	readSecret, err = UnsealSecret(NV_INDEX,
		&key.PublicKey,
		approvedPolicy,
		approvedPolicySignature,
		PCR_INDEXES,
		RBP{})
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	if bytes.Equal(writtenSecret, readSecret) != true {
		t.Fatalf("Expected %s, got %s", writtenSecret, readSecret)
	}
}

func TestMutablePolicySealUnsealWithRollbackProtection(t *testing.T) {
	key, _ := genTpmKeyPair()
	authorizationDigest, err := GenerateAuthDigest(&key.PublicKey)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	// since this should run on a emulated TPM, we might start with PCR values
	// being zero, so extend them to a non-zero value first.
	for _, index := range PCR_INDEXES {
		err = extendPCR(index, AlgoSHA256, []byte("DATA_TO_EXTEND"))
		if err != nil {
			t.Fatalf("Expected no error, got  \"%v\"", err)
		}
	}

	rbpCounter, err := DefineMonotonicCounter(NV_COUNTER_INDEX)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}
	rbp := RBP{Counter: NV_COUNTER_INDEX, Check: rbpCounter}

	pcrs, err := readPCRs(PCR_INDEXES, AlgoSHA256)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	sealingPcrs := make(PCRS, 0)
	for _, index := range PCR_INDEXES {
		sealingPcrs = append(sealingPcrs, PCR{Index: pcrs.Pcrs[index].Index, Digest: pcrs.Pcrs[index].Digest})
	}
	pcrsList := PCRList{Algo: AlgoSHA256, Pcrs: sealingPcrs}

	approvedPolicy, approvedPolicySignature, err := GenerateSignedPolicy(key, pcrsList, rbp)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	writtenSecret := []byte("THIS_IS_VERY_SECRET")
	err = SealSecret(NV_INDEX, authorizationDigest, writtenSecret)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	readSecret, err := UnsealSecret(NV_INDEX,
		&key.PublicKey,
		approvedPolicy,
		approvedPolicySignature,
		PCR_INDEXES,
		rbp)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	if bytes.Equal(writtenSecret, readSecret) != true {
		t.Fatalf("Expected %s, got %s", writtenSecret, readSecret)
	}

	// randomly select and extend a PCR index
	pick := PCR_INDEXES[rand.Intn(len(PCR_INDEXES))]
	err = extendPCR(pick, AlgoSHA256, []byte("EXTEND_DATA_TWO"))
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	pcrs, err = readPCRs(PCR_INDEXES, AlgoSHA256)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	// this must fail due to PCR mismatch
	_, err = UnsealSecret(NV_INDEX,
		&key.PublicKey,
		approvedPolicy,
		approvedPolicySignature,
		PCR_INDEXES,
		rbp)
	if err != nil {
		if strings.Contains(err.Error(), "TPM_RC_VALUE") != true {
			t.Fatalf("Expected TPM_RC_VALUE error, got  \"%v\"", err)
		}
	} else {
		t.Fatalf("Expected TPM_RC_VALUE error, got nil")
	}

	sealingPcrs = make(PCRS, 0)
	for _, index := range PCR_INDEXES {
		sealingPcrs = append(sealingPcrs, PCR{Index: pcrs.Pcrs[index].Index, Digest: pcrs.Pcrs[index].Digest})
	}
	pcrsList = PCRList{Algo: AlgoSHA256, Pcrs: sealingPcrs}

	approvedPolicy, approvedPolicySignature, err = GenerateSignedPolicy(key, pcrsList, rbp)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	readSecret, err = UnsealSecret(NV_INDEX,
		&key.PublicKey,
		approvedPolicy,
		approvedPolicySignature,
		PCR_INDEXES,
		rbp)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	if bytes.Equal(writtenSecret, readSecret) != true {
		t.Fatalf("Expected %s, got %s", writtenSecret, readSecret)
	}

	// now lets increase the counter
	rbpCounter, err = IncreaseMonotonicCounter(NV_COUNTER_INDEX)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	// this should fail because the counter arithmetic op (ULE) don't hold anymore
	_, err = UnsealSecret(NV_INDEX,
		&key.PublicKey,
		approvedPolicy,
		approvedPolicySignature,
		PCR_INDEXES,
		rbp)
	if err != nil {
		if strings.Contains(err.Error(), "TPM_RC_POLICY") != true {
			t.Fatalf("Expected TPM_RC_POLICY error, got  \"%v\"", err)
		}
	} else {
		t.Fatalf("Expected TPM_RC_POLICY error, got nil")
	}

	// update the policy and try again
	rbp.Check = rbpCounter
	approvedPolicy, approvedPolicySignature, err = GenerateSignedPolicy(key, pcrsList, rbp)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	readSecret, err = UnsealSecret(NV_INDEX,
		&key.PublicKey,
		approvedPolicy,
		approvedPolicySignature,
		PCR_INDEXES,
		rbp)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	if bytes.Equal(writtenSecret, readSecret) != true {
		t.Fatalf("Expected %s, got %s", writtenSecret, readSecret)
	}
}

func TestMutablePolicySealUnsealWithKeyRotation(t *testing.T) {
	oldKey, _ := genTpmKeyPair()
	authorizationDigest, err := GenerateAuthDigest(&oldKey.PublicKey)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	// since this should run on a emulated TPM, we might start with PCR values
	// being zero, so extend them to a non-zero value first.
	for _, index := range PCR_INDEXES {
		err = extendPCR(index, AlgoSHA256, []byte("DATA_TO_EXTEND"))
		if err != nil {
			t.Fatalf("Expected no error, got  \"%v\"", err)
		}
	}

	rbpCounter, err := DefineMonotonicCounter(NV_COUNTER_INDEX)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	pcrs, err := readPCRs(PCR_INDEXES, AlgoSHA256)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	sealingPcrs := make(PCRS, 0)
	for _, index := range PCR_INDEXES {
		sealingPcrs = append(sealingPcrs, PCR{Index: pcrs.Pcrs[index].Index, Digest: pcrs.Pcrs[index].Digest})
	}

	pcrsList := PCRList{Algo: AlgoSHA256, Pcrs: sealingPcrs}
	rbp := RBP{Counter: NV_COUNTER_INDEX, Check: rbpCounter}
	approvedPolicy, approvedPolicySignature, err := GenerateSignedPolicy(oldKey, pcrsList, rbp)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	writtenSecret := []byte("THIS_IS_VERY_SECRET")
	err = SealSecret(NV_INDEX, authorizationDigest, writtenSecret)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	newKey, _ := genTpmKeyPair()
	newkeySig, newAuthDigest, approvedPolicyNewSig, err := RotateAuthDigestWithPolicy(oldKey, newKey, pcrs, rbp)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	err = ResealTpmSecretWithNewAuthDigest(NV_INDEX,
		&oldKey.PublicKey,
		&newKey.PublicKey,
		newkeySig,
		newAuthDigest,
		approvedPolicy,
		approvedPolicySignature,
		PCR_INDEXES,
		rbp)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	readSecret, err := UnsealSecret(NV_INDEX,
		&newKey.PublicKey,
		approvedPolicy,
		approvedPolicyNewSig,
		PCR_INDEXES,
		rbp)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	if bytes.Equal(writtenSecret, readSecret) != true {
		t.Fatalf("Expected %s, got %s", writtenSecret, readSecret)
	}

	// update the signature variable for subsequent uses
	approvedPolicySignature = approvedPolicyNewSig

	// randomly select and extend a PCR index
	pick := PCR_INDEXES[rand.Intn(len(PCR_INDEXES))]
	err = extendPCR(pick, AlgoSHA256, []byte("EXTEND_DATA_TWO"))
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	pcrs, err = readPCRs(PCR_INDEXES, AlgoSHA256)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	// this must fail due to PCR mismatch
	_, err = UnsealSecret(NV_INDEX,
		&newKey.PublicKey,
		approvedPolicy,
		approvedPolicySignature,
		PCR_INDEXES,
		rbp)
	if err != nil {
		if strings.Contains(err.Error(), "TPM_RC_VALUE") != true {
			t.Fatalf("Expected TPM_RC_VALUE error, got  \"%v\"", err)
		}
	} else {
		t.Fatalf("Expected TPM_RC_VALUE error, got nil")
	}

	sealingPcrs = make(PCRS, 0)
	for _, index := range PCR_INDEXES {
		sealingPcrs = append(sealingPcrs, PCR{Index: pcrs.Pcrs[index].Index, Digest: pcrs.Pcrs[index].Digest})
	}
	pcrsList = PCRList{Algo: AlgoSHA256, Pcrs: sealingPcrs}

	approvedPolicy, approvedPolicySignature, err = GenerateSignedPolicy(newKey, pcrsList, rbp)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	readSecret, err = UnsealSecret(NV_INDEX,
		&newKey.PublicKey,
		approvedPolicy,
		approvedPolicySignature,
		PCR_INDEXES,
		rbp)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	if bytes.Equal(writtenSecret, readSecret) != true {
		t.Fatalf("Expected %s, got %s", writtenSecret, readSecret)
	}

	// not lets increase the counter
	rbpCounter, err = IncreaseMonotonicCounter(NV_COUNTER_INDEX)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	// this should fail because the counter arithmetic op (ULE) don't hold anymore
	_, err = UnsealSecret(NV_INDEX,
		&newKey.PublicKey,
		approvedPolicy,
		approvedPolicySignature,
		PCR_INDEXES,
		rbp)
	if err != nil {
		if strings.Contains(err.Error(), "TPM_RC_POLICY") != true {
			t.Fatalf("Expected TPM_RC_POLICY error, got  \"%v\"", err)
		}
	} else {
		t.Fatalf("Expected TPM_RC_POLICY error, got nil")
	}

	// update the policy and try again
	rbp.Check = rbpCounter
	approvedPolicy, approvedPolicySignature, err = GenerateSignedPolicy(newKey, pcrsList, rbp)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	readSecret, err = UnsealSecret(NV_INDEX,
		&newKey.PublicKey,
		approvedPolicy,
		approvedPolicySignature,
		PCR_INDEXES,
		rbp)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	if bytes.Equal(writtenSecret, readSecret) != true {
		t.Fatalf("Expected %s, got %s", writtenSecret, readSecret)
	}
}

func TestReadLocking(t *testing.T) {
	key, _ := genTpmKeyPair()
	authorizationDigest, err := GenerateAuthDigest(&key.PublicKey)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	// since this should run on a emulated TPM, we might start with PCR values
	// being zero, so extend them to a non-zero value first.
	for _, index := range PCR_INDEXES {
		err = extendPCR(index, AlgoSHA256, []byte("DATA_TO_EXTEND"))
		if err != nil {
			t.Fatalf("Expected no error, got  \"%v\"", err)
		}
	}

	pcrs, err := readPCRs(PCR_INDEXES, AlgoSHA256)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	sealingPcrs := make(PCRS, 0)
	for _, index := range PCR_INDEXES {
		sealingPcrs = append(sealingPcrs, PCR{Index: pcrs.Pcrs[index].Index, Digest: pcrs.Pcrs[index].Digest})
	}
	pcrsList := PCRList{Algo: AlgoSHA256, Pcrs: sealingPcrs}

	approvedPolicy, approvedPolicySignature, err := GenerateSignedPolicy(key, pcrsList, RBP{})
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	writtenSecret := []byte("THIS_IS_VERY_SECRET")
	err = SealSecret(NV_INDEX, authorizationDigest, writtenSecret)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	readSecret, err := UnsealSecret(NV_INDEX,
		&key.PublicKey,
		approvedPolicy,
		approvedPolicySignature,
		PCR_INDEXES,
		RBP{})
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	if bytes.Equal(writtenSecret, readSecret) != true {
		t.Fatalf("Expected %s, got %s", writtenSecret, readSecret)
	}

	err = ActivateReadLock(NV_INDEX,
		&key.PublicKey,
		approvedPolicy,
		approvedPolicySignature,
		PCR_INDEXES,
		RBP{})

	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	_, err = UnsealSecret(NV_INDEX,
		&key.PublicKey,
		approvedPolicy,
		approvedPolicySignature,
		PCR_INDEXES,
		RBP{})
	if err != nil {
		if strings.Contains(err.Error(), "TPM_RC_NV_LOCKED") != true {
			t.Fatalf("Expected TPM_RC_NV_LOCKED error, got  \"%v\"", err)
		}
	} else {
		t.Fatalf("Expected TPM_RC_NV_LOCKED error, got  nil")
	}
}
