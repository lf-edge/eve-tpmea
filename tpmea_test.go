// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package tpmea

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/rsa"
	"errors"
	"math/rand"
	"os"
	"strings"
	"testing"

	"github.com/canonical/go-tpm2"
)

const (
	RESETABLE_PCR_INDEX = 16
	NV_INDEX            = 0x1500016
	NV_COUNTER_INDEX    = 0x1500017
	// AIK_HANDLE is the RSA restricted signing key provisioned by runtests.sh
	AIK_HANDLE = uint32(0x81000003)
)

var PCR_INDEXES = []int{0, 1, 2, 3, 4, 5}

func TestMain(m *testing.M) {
	if socketPath := os.Getenv("SWTPM_SERVER_PATH"); socketPath != "" {
		ConnectToSwtpm(socketPath)
	}
	os.Exit(m.Run())
}

// genTpmKeyPairRSA generates a 2048 bit RSA key,
// 2048 bits is the limit for TPM.
func genTpmKeyPairRSA() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(crand.Reader, 2048)
}

func genTpmKeyPairECC() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
}

// extendPCR extends the provided PCR index with hash of the data,
// hash algorithm to use is determined by algo parameter.
func extendPCR(index int, algo PCRHashAlgo, data []byte) error {
	tpm, err := getTpmHandle()
	if err != nil {
		return err
	}
	defer tpm.Close()

	pcrHashAlgo, err := getPCRAlgo(algo)
	if err != nil {
		return err
	}
	h := pcrHashAlgo.NewHash()
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

	pcrHashAlgo, err := getPCRAlgo(algo)
	if err != nil {
		return PCRList{}, err
	}
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

// TestGenerateAuthDigest* verify that GenerateAuthDigest produces a digest for
// both RSA and ECC public keys, and returns an error when given a nil key.
func TestGenerateAuthDigestRSA(t *testing.T) {
	key, _ := genTpmKeyPairRSA()
	_, err := GenerateAuthDigest(&key.PublicKey)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}
}

func TestGenerateAuthDigestECC(t *testing.T) {
	key, _ := genTpmKeyPairECC()
	_, err := GenerateAuthDigest(&key.PublicKey)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}
}

func TestGenerateAuthDigestError(t *testing.T) {
	_, err := GenerateAuthDigest(nil)
	if err == nil {
		t.Fatalf("Expected error, got nothing")
	}
}

// TestReadPCRs verifies that PCR values can be read from the TPM.
func TestReadPCRs(t *testing.T) {
	_, err := readPCRs(PCR_INDEXES, AlgoSHA256)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}
}

// TestPCRReset verifies that a resettable PCR (index 16) goes back to all-zeros
// after a reset, even when it had previously been extended.
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

// TestPCRExtend verifies that extending a PCR changes its value.
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

// TestMonotonicCounter verifies that a monotonic counter can be defined and
// incremented, and that its value goes up by exactly one on each increment.
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

// TestSimpleSealUnseal* verify the basic seal and unseal flow for both RSA and
// ECC keys. A secret is sealed against the current PCR state and must be
// recoverable using a matching signed policy.
func TestSimpleSealUnsealRSA(t *testing.T) {
	key, _ := genTpmKeyPairRSA()
	testMutablePolicySealUnseal(t, key, &key.PublicKey)
}

func TestSimpleSealUnsealECC(t *testing.T) {
	key, _ := genTpmKeyPairECC()
	testSimpleSealUnseal(t, key, &key.PublicKey)
}

func testSimpleSealUnseal(t *testing.T, privateKey crypto.PrivateKey, publicKey crypto.PublicKey) {
	authorizationDigest, err := GenerateAuthDigest(publicKey)
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

	sp, err := GenerateSignedPolicy(privateKey, pcrsList, RBP{})
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	writtenSecret := []byte("THIS_IS_VERY_SECRET")
	err = SealSecret(NV_INDEX, authorizationDigest, writtenSecret)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	sel := PCRSelection{Algo: AlgoSHA256, Indexes: PCR_INDEXES}
	readSecret, err := UnsealSecret(NV_INDEX, publicKey, sp, sel, RBP{})
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	if bytes.Equal(writtenSecret, readSecret) != true {
		t.Fatalf("Expected %s, got %s", writtenSecret, readSecret)
	}
}

// TestMutablePolicySealUnseal* verify that a sealed secret is recoverable with
// a valid policy, that unseal fails after a PCR changes, and that a freshly
// signed policy covering the new PCR values restores access.
func TestMutablePolicySealUnsealRSA(t *testing.T) {
	key, _ := genTpmKeyPairRSA()
	testMutablePolicySealUnseal(t, key, &key.PublicKey)
}

func TestMutablePolicySealUnsealECC(t *testing.T) {
	key, _ := genTpmKeyPairECC()
	testMutablePolicySealUnseal(t, key, &key.PublicKey)
}

func testMutablePolicySealUnseal(t *testing.T, privateKey crypto.PrivateKey, publicKey crypto.PublicKey) {

	authorizationDigest, err := GenerateAuthDigest(publicKey)
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

	sp, err := GenerateSignedPolicy(privateKey, pcrsList, RBP{})
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	writtenSecret := []byte("THIS_IS_VERY_SECRET")
	err = SealSecret(NV_INDEX, authorizationDigest, writtenSecret)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	sel := PCRSelection{Algo: AlgoSHA256, Indexes: PCR_INDEXES}
	readSecret, err := UnsealSecret(NV_INDEX, publicKey, sp, sel, RBP{})
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
	_, err = UnsealSecret(NV_INDEX, publicKey, sp, sel, RBP{})
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

	sp, err = GenerateSignedPolicy(privateKey, pcrsList, RBP{})
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	readSecret, err = UnsealSecret(NV_INDEX, publicKey, sp, sel, RBP{})
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	if bytes.Equal(writtenSecret, readSecret) != true {
		t.Fatalf("Expected %s, got %s", writtenSecret, readSecret)
	}
}

// TestMutablePolicySealUnsealWithRollbackProtection* verify that rollback
// protection works: an old policy is rejected once the counter is incremented,
// and a new policy bound to the updated counter value restores access.
func TestMutablePolicySealUnsealWithRollbackProtectionRSA(t *testing.T) {
	key, _ := genTpmKeyPairRSA()
	testMutablePolicySealUnsealWithRollbackProtection(t, key, &key.PublicKey)
}

func TestMutablePolicySealUnsealWithRollbackProtectionECC(t *testing.T) {
	key, _ := genTpmKeyPairECC()
	testMutablePolicySealUnsealWithRollbackProtection(t, key, &key.PublicKey)
}

func testMutablePolicySealUnsealWithRollbackProtection(t *testing.T, privateKey crypto.PrivateKey, publicKey crypto.PublicKey) {
	authorizationDigest, err := GenerateAuthDigest(publicKey)
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

	sp, err := GenerateSignedPolicy(privateKey, pcrsList, rbp)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	writtenSecret := []byte("THIS_IS_VERY_SECRET")
	err = SealSecret(NV_INDEX, authorizationDigest, writtenSecret)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	sel := PCRSelection{Algo: AlgoSHA256, Indexes: PCR_INDEXES}
	readSecret, err := UnsealSecret(NV_INDEX, publicKey, sp, sel, rbp)
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
	_, err = UnsealSecret(NV_INDEX, publicKey, sp, sel, rbp)
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

	sp, err = GenerateSignedPolicy(privateKey, pcrsList, rbp)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	readSecret, err = UnsealSecret(NV_INDEX, publicKey, sp, sel, rbp)
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
	_, err = UnsealSecret(NV_INDEX, publicKey, sp, sel, rbp)
	if err != nil {
		if strings.Contains(err.Error(), "TPM_RC_POLICY") != true {
			t.Fatalf("Expected TPM_RC_POLICY error, got  \"%v\"", err)
		}
	} else {
		t.Fatalf("Expected TPM_RC_POLICY error, got nil")
	}

	// update the policy and try again
	rbp.Check = rbpCounter
	sp, err = GenerateSignedPolicy(privateKey, pcrsList, rbp)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	readSecret, err = UnsealSecret(NV_INDEX, publicKey, sp, sel, rbp)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	if bytes.Equal(writtenSecret, readSecret) != true {
		t.Fatalf("Expected %s, got %s", writtenSecret, readSecret)
	}
}

// TestReadLocking* verify that ActivateReadLock blocks further reads from the
// NV index until the next TPM reset, even when a valid policy is presented.
func TestReadLockingRSA(t *testing.T) {
	key, _ := genTpmKeyPairRSA()
	testReadLocking(t, key, &key.PublicKey)
}

func TestReadLockingECC(t *testing.T) {
	key, _ := genTpmKeyPairECC()
	testReadLocking(t, key, &key.PublicKey)
}

func testReadLocking(t *testing.T, privateKey crypto.PrivateKey, publicKey crypto.PublicKey) {
	authorizationDigest, err := GenerateAuthDigest(publicKey)
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

	sp, err := GenerateSignedPolicy(privateKey, pcrsList, RBP{})
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	writtenSecret := []byte("THIS_IS_VERY_SECRET")
	err = SealSecret(NV_INDEX, authorizationDigest, writtenSecret)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	sel := PCRSelection{Algo: AlgoSHA256, Indexes: PCR_INDEXES}
	readSecret, err := UnsealSecret(NV_INDEX, publicKey, sp, sel, RBP{})
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	if bytes.Equal(writtenSecret, readSecret) != true {
		t.Fatalf("Expected %s, got %s", writtenSecret, readSecret)
	}

	err = ActivateReadLock(NV_INDEX, publicKey, sp, sel, RBP{})
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	_, err = UnsealSecret(NV_INDEX, publicKey, sp, sel, RBP{})
	if err != nil {
		if strings.Contains(err.Error(), "TPM_RC_NV_LOCKED") != true {
			t.Fatalf("Expected TPM_RC_NV_LOCKED error, got  \"%v\"", err)
		}
	} else {
		t.Fatalf("Expected TPM_RC_NV_LOCKED error, got  nil")
	}
}

// TestReadNVAuthDigest verifies that ReadNVAuthDigest returns the same
// Authorization Digest that was stored when the NV index was defined.
func TestReadNVAuthDigest(t *testing.T) {
	key, _ := genTpmKeyPairECC()
	authorizationDigest, err := GenerateAuthDigest(&key.PublicKey)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	writtenSecret := []byte("THIS_IS_VERY_SECRET")
	err = SealSecret(NV_INDEX, authorizationDigest, writtenSecret)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	authPolicy, err := ReadNVAuthDigest(NV_INDEX)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	if bytes.Equal(authPolicy, authorizationDigest) != true {
		t.Fatalf("Expected equal authPolicy and authorizationDigest, got %x != %x", authPolicy, authorizationDigest)
	}
}

// TestUnsealSecretWrongKey* verify that unsealing with a key that does not
// match the Authorization Digest bound to the NV index is rejected.
func TestUnsealSecretWrongKeyRSA(t *testing.T) {
	correctKey, _ := genTpmKeyPairRSA()
	wrongKey, _ := genTpmKeyPairRSA()
	testUnsealSecretWrongKey(t, correctKey, &correctKey.PublicKey, &wrongKey.PublicKey)
}

func TestUnsealSecretWrongKeyECC(t *testing.T) {
	correctKey, _ := genTpmKeyPairECC()
	wrongKey, _ := genTpmKeyPairECC()
	testUnsealSecretWrongKey(t, correctKey, &correctKey.PublicKey, &wrongKey.PublicKey)
}

func testUnsealSecretWrongKey(t *testing.T, privateKey crypto.PrivateKey, correctPublicKey crypto.PublicKey, wrongPublicKey crypto.PublicKey) {
	authorizationDigest, err := GenerateAuthDigest(correctPublicKey)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

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

	sp, err := GenerateSignedPolicy(privateKey, pcrsList, RBP{})
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	err = SealSecret(NV_INDEX, authorizationDigest, []byte("THIS_IS_VERY_SECRET"))
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	sel := PCRSelection{Algo: AlgoSHA256, Indexes: PCR_INDEXES}
	_, err = UnsealSecret(NV_INDEX, wrongPublicKey, sp, sel, RBP{})
	if err == nil {
		t.Fatalf("Expected error when unsealing with wrong key, got nil")
	}
}

// TestUnsealSecretTamperedSignature* verify that a corrupted policy digest
// is rejected before the TPM evaluates any policy commands.
func TestUnsealSecretTamperedSignatureRSA(t *testing.T) {
	key, _ := genTpmKeyPairRSA()
	testUnsealSecretTamperedSignature(t, key, &key.PublicKey)
}

func TestUnsealSecretTamperedSignatureECC(t *testing.T) {
	key, _ := genTpmKeyPairECC()
	testUnsealSecretTamperedSignature(t, key, &key.PublicKey)
}

func testUnsealSecretTamperedSignature(t *testing.T, privateKey crypto.PrivateKey, publicKey crypto.PublicKey) {
	authorizationDigest, err := GenerateAuthDigest(publicKey)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

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

	sp, err := GenerateSignedPolicy(privateKey, pcrsList, RBP{})
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	err = SealSecret(NV_INDEX, authorizationDigest, []byte("THIS_IS_VERY_SECRET"))
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	// corrupt the policy digest: the existing signature won't verify against it.
	tamperedSP := SignedPolicy{
		Sig:    sp.Sig,
		Digest: make([]byte, len(sp.Digest)),
	}
	copy(tamperedSP.Digest, sp.Digest)
	tamperedSP.Digest[0] ^= 0xff

	sel := PCRSelection{Algo: AlgoSHA256, Indexes: PCR_INDEXES}
	_, err = UnsealSecret(NV_INDEX, publicKey, tamperedSP, sel, RBP{})
	if err == nil {
		t.Fatalf("Expected error when unsealing with tampered policy digest, got nil")
	}
}

// TestSealSecretRejectsCounterHandle verifies that SealSecret refuses to
// overwrite a monotonic counter NV index.
func TestSealSecretRejectsCounterHandle(t *testing.T) {
	_, err := DefineMonotonicCounter(NV_COUNTER_INDEX)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	err = SealSecret(NV_COUNTER_INDEX, bytes.Repeat([]byte{0x01}, 32), []byte("secret"))
	if err == nil {
		t.Fatalf("Expected error when sealing to counter handle, got nil")
	}
}

// TestDefineMonotonicCounterIdempotent verifies that calling
// DefineMonotonicCounter twice on the same handle succeeds and returns the
// same value both times (no spurious increment on the second call).
func TestDefineMonotonicCounterIdempotent(t *testing.T) {
	counter1, err := DefineMonotonicCounter(NV_COUNTER_INDEX)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	counter2, err := DefineMonotonicCounter(NV_COUNTER_INDEX)
	if err != nil {
		t.Fatalf("Expected no error on second call, got  \"%v\"", err)
	}

	if counter1 != counter2 {
		t.Fatalf("Expected same counter value on second call, got %d != %d", counter1, counter2)
	}
}

// TestDefineMonotonicCounterWrongNVType verifies that DefineMonotonicCounter
// refuses to use an existing NV index whose type is not a counter.
func TestDefineMonotonicCounterWrongNVType(t *testing.T) {
	const wrongTypeHandle = uint32(0x1500018)

	key, _ := genTpmKeyPairECC()
	authorizationDigest, err := GenerateAuthDigest(&key.PublicKey)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	// plant an ordinary NV index at the handle.
	err = SealSecret(wrongTypeHandle, authorizationDigest, []byte("dummy"))
	if err != nil {
		t.Fatalf("Expected no error from SealSecret, got  \"%v\"", err)
	}

	_, err = DefineMonotonicCounter(wrongTypeHandle)
	if err == nil {
		t.Fatalf("Expected error when defining counter on ordinary NV handle, got nil")
	}
}

// TestUnsealSecretNonExistentHandle verifies that unsealing a handle that was
// never defined returns an error rather than panicking or producing a
// misleading result.
func TestUnsealSecretNonExistentHandle(t *testing.T) {
	key, _ := genTpmKeyPairRSA()

	const nonExistentHandle = uint32(0x1500099)
	sp := SignedPolicy{
		Digest: bytes.Repeat([]byte{0x01}, 32),
		Sig:    &PolicySignature{RSASignature: bytes.Repeat([]byte{0x01}, 32)},
	}
	sel := PCRSelection{Algo: AlgoSHA256, Indexes: PCR_INDEXES}

	_, err := UnsealSecret(nonExistentHandle, &key.PublicKey, sp, sel, RBP{})
	if err == nil {
		t.Fatalf("Expected error for non-existent handle, got nil")
	}
}

// readAIKPublicKey reads the public component of the AIK
func readAIKPublicKey(t *testing.T) crypto.PublicKey {
	t.Helper()
	tpm, err := getTpmHandle()
	if err != nil {
		t.Fatalf("getTpmHandle: %v", err)
	}
	defer tpm.Close()

	ctx, err := tpm.NewResourceContext(tpm2.Handle(AIK_HANDLE))
	if err != nil {
		t.Fatalf("NewResourceContext for AIK 0x%08x: %v", AIK_HANDLE, err)
	}

	pub, _, _, err := tpm.ReadPublic(ctx)
	if err != nil {
		t.Fatalf("ReadPublic: %v", err)
	}

	return pub.Public()
}

// TestCertifyNVCounter verifies the happy path: CertifyNVCounter produces a
// blob that VerifyNVCounter accepts, and the returned counter value matches
// the one returned by DefineMonotonicCounter.
func TestCertifyNVCounter(t *testing.T) {
	aikPub := readAIKPublicKey(t)

	counterVal, err := DefineMonotonicCounter(NV_COUNTER_INDEX)
	if err != nil {
		t.Fatalf("DefineMonotonicCounter: %v", err)
	}

	nonce := make([]byte, 32)
	if _, err := crand.Read(nonce); err != nil {
		t.Fatalf("generate nonce: %v", err)
	}

	cert, err := CertifyNVCounter(AIK_HANDLE, NV_COUNTER_INDEX, nonce)
	if err != nil {
		t.Fatalf("CertifyNVCounter: %v", err)
	}

	certified, err := VerifyNVCounter(&cert, aikPub, nonce)
	if err != nil {
		t.Fatalf("VerifyNVCounter: %v", err)
	}
	if certified != counterVal {
		t.Fatalf("certified value %d does not match counter value %d", certified, counterVal)
	}
}

// TestVerifyNVCounterIncrementedValue verifies that the certified value
// reflects a counter increment: after IncreaseMonotonicCounter the next
// certification must return the updated value.
func TestVerifyNVCounterIncrementedValue(t *testing.T) {
	aikPub := readAIKPublicKey(t)

	_, err := DefineMonotonicCounter(NV_COUNTER_INDEX)
	if err != nil {
		t.Fatalf("DefineMonotonicCounter: %v", err)
	}

	incremented, err := IncreaseMonotonicCounter(NV_COUNTER_INDEX)
	if err != nil {
		t.Fatalf("IncreaseMonotonicCounter: %v", err)
	}

	nonce := make([]byte, 32)
	if _, err := crand.Read(nonce); err != nil {
		t.Fatalf("generate nonce: %v", err)
	}

	cert, err := CertifyNVCounter(AIK_HANDLE, NV_COUNTER_INDEX, nonce)
	if err != nil {
		t.Fatalf("CertifyNVCounter: %v", err)
	}

	certified, err := VerifyNVCounter(&cert, aikPub, nonce)
	if err != nil {
		t.Fatalf("VerifyNVCounter: %v", err)
	}
	if certified != incremented {
		t.Fatalf("certified value %d does not match incremented counter %d", certified, incremented)
	}
}

// TestVerifyNVCounterNonceMismatch verifies that presenting a cert with a
// different nonce is rejected as a potential replay.
func TestVerifyNVCounterNonceMismatch(t *testing.T) {
	aikPub := readAIKPublicKey(t)

	_, err := DefineMonotonicCounter(NV_COUNTER_INDEX)
	if err != nil {
		t.Fatalf("DefineMonotonicCounter: %v", err)
	}

	nonce := make([]byte, 32)
	if _, err := crand.Read(nonce); err != nil {
		t.Fatalf("generate nonce: %v", err)
	}

	cert, err := CertifyNVCounter(AIK_HANDLE, NV_COUNTER_INDEX, nonce)
	if err != nil {
		t.Fatalf("CertifyNVCounter: %v", err)
	}

	differentNonce := make([]byte, 32)
	if _, err := crand.Read(differentNonce); err != nil {
		t.Fatalf("generate different nonce: %v", err)
	}

	_, err = VerifyNVCounter(&cert, aikPub, differentNonce)
	if err == nil {
		t.Fatal("expected nonce mismatch error, got nil")
	}
}

// TestVerifyNVCounterWrongKey verifies that a cert signed by the AIK cannot
// be verified with a different RSA key.
func TestVerifyNVCounterWrongKey(t *testing.T) {
	_, err := DefineMonotonicCounter(NV_COUNTER_INDEX)
	if err != nil {
		t.Fatalf("DefineMonotonicCounter: %v", err)
	}

	nonce := make([]byte, 32)
	if _, err := crand.Read(nonce); err != nil {
		t.Fatalf("generate nonce: %v", err)
	}

	cert, err := CertifyNVCounter(AIK_HANDLE, NV_COUNTER_INDEX, nonce)
	if err != nil {
		t.Fatalf("CertifyNVCounter: %v", err)
	}

	wrongKey, _ := genTpmKeyPairRSA()
	_, err = VerifyNVCounter(&cert, &wrongKey.PublicKey, nonce)
	if err == nil {
		t.Fatal("expected signature verification error with wrong key, got nil")
	}
}

// TestVerifyNVCounterTamperedSignature verifies that flipping a byte in the
// RSA signature causes verification to fail.
func TestVerifyNVCounterTamperedSignature(t *testing.T) {
	aikPub := readAIKPublicKey(t)

	_, err := DefineMonotonicCounter(NV_COUNTER_INDEX)
	if err != nil {
		t.Fatalf("DefineMonotonicCounter: %v", err)
	}

	nonce := make([]byte, 32)
	if _, err := crand.Read(nonce); err != nil {
		t.Fatalf("generate nonce: %v", err)
	}

	cert, err := CertifyNVCounter(AIK_HANDLE, NV_COUNTER_INDEX, nonce)
	if err != nil {
		t.Fatalf("CertifyNVCounter: %v", err)
	}

	cert.RSASig[0] ^= 0xff

	_, err = VerifyNVCounter(&cert, aikPub, nonce)
	if err == nil {
		t.Fatal("expected signature verification error after tampering, got nil")
	}
}

// TestVerifyNVCounterNilCert verifies that a nil cert skips all checks and
// returns (0, nil) without any TPM interaction.
func TestVerifyNVCounterNilCert(t *testing.T) {
	key, _ := genTpmKeyPairRSA()
	val, err := VerifyNVCounter(nil, &key.PublicKey, []byte("nonce"))
	if err != nil {
		t.Fatalf("expected nil error for nil cert, got %v", err)
	}
	if val != 0 {
		t.Fatalf("expected 0 for nil cert, got %d", val)
	}
}

// TestVerifyNVCounterUnsupportedKeyType verifies that a key type other than
// RSA or ECDSA returns an error immediately.
func TestVerifyNVCounterUnsupportedKeyType(t *testing.T) {
	cert := NVCertification{AttestBlob: []byte("dummy")}
	_, err := VerifyNVCounter(&cert, "not-a-real-key", []byte("nonce"))
	if err == nil {
		t.Fatal("expected error for unsupported key type, got nil")
	}
}

// TestVerifyNVCounterRSAMissingSignature verifies that an RSA public key
// paired with a cert that has no RSA signature bytes is rejected.
func TestVerifyNVCounterRSAMissingSignature(t *testing.T) {
	key, _ := genTpmKeyPairRSA()
	cert := NVCertification{AttestBlob: []byte("dummy")} // RSASig intentionally empty
	_, err := VerifyNVCounter(&cert, &key.PublicKey, []byte("nonce"))
	if err == nil {
		t.Fatal("expected error for missing RSA signature, got nil")
	}
}

// TestVerifyNVCounterECCMissingComponents verifies that an ECC cert with only
// one of the two signature components (R, S) is rejected.
func TestVerifyNVCounterECCMissingComponents(t *testing.T) {
	key, _ := genTpmKeyPairECC()

	certMissingS := NVCertification{
		AttestBlob: []byte("dummy"),
		ECCSigR:    []byte{0x01},
		// ECCSigS intentionally absent
	}
	_, err := VerifyNVCounter(&certMissingS, &key.PublicKey, []byte("nonce"))
	if err == nil {
		t.Fatal("expected error for missing ECDSA S component, got nil")
	}

	certMissingR := NVCertification{
		AttestBlob: []byte("dummy"),
		// ECCSigR intentionally absent
		ECCSigS: []byte{0x01},
	}
	_, err = VerifyNVCounter(&certMissingR, &key.PublicKey, []byte("nonce"))
	if err == nil {
		t.Fatal("expected error for missing ECDSA R component, got nil")
	}
}
