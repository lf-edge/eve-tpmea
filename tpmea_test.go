package tpmea

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/canonical/go-tpm2"
)

const (
	RESETABLE_PCR_INDEX = 16
	NV_INDEX            = 0x1500016
	NV_COUNTER_INDEX    = 0x1500017
)

var PCR_INDEXES = []int{0, 1, 2, 3, 4, 5}

type swtpmSocketTCTI struct {
	conn net.Conn
	rsp  *bytes.Reader
}

func TestMain(m *testing.M) {
	if socketPath := os.Getenv("SWTPM_SERVER_PATH"); socketPath != "" {
		getTpmHandle = func() (*tpm2.TPMContext, error) {
			conn, err := net.Dial("unix", socketPath)
			if err != nil {
				return nil, fmt.Errorf("cannot connect to swtpm socket %s: %w", socketPath, err)
			}
			return tpm2.NewTPMContext(&swtpmSocketTCTI{conn: conn}), nil
		}
	}
	os.Exit(m.Run())
}

func (t *swtpmSocketTCTI) Read(data []byte) (int, error) {
	if t.rsp == nil {
		hdr := make([]byte, 6)
		if _, err := io.ReadFull(t.conn, hdr); err != nil {
			return 0, err
		}
		responseSize := binary.BigEndian.Uint32(hdr[2:6])
		buf := make([]byte, responseSize)
		copy(buf, hdr)
		if _, err := io.ReadFull(t.conn, buf[6:]); err != nil {
			return 0, err
		}
		t.rsp = bytes.NewReader(buf)
	}
	n, err := t.rsp.Read(data)
	if err == io.EOF {
		t.rsp = nil
	}
	return n, err
}

func (t *swtpmSocketTCTI) Write(data []byte) (int, error) { return t.conn.Write(data) }
func (t *swtpmSocketTCTI) Close() error                   { return t.conn.Close() }
func (t *swtpmSocketTCTI) MakeSticky(_ tpm2.Handle, _ bool) error {
	return errors.New("not implemented")
}
func (t *swtpmSocketTCTI) SetTimeout(timeout time.Duration) error {
	if timeout == tpm2.InfiniteTimeout {
		return t.conn.SetDeadline(time.Time{})
	}
	return t.conn.SetDeadline(time.Now().Add(timeout))
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

func TestMutablePolicySealUnsealWithKeyRotationRSA(t *testing.T) {
	oldKey, _ := genTpmKeyPairRSA()
	newKey, _ := genTpmKeyPairRSA()
	testMutablePolicySealUnsealWithKeyRotation(t, oldKey, newKey)
}

func TestMutablePolicySealUnsealWithKeyRotationECC(t *testing.T) {
	oldKey, _ := genTpmKeyPairECC()
	newKey, _ := genTpmKeyPairECC()
	testMutablePolicySealUnsealWithKeyRotation(t, oldKey, newKey)
}

func testMutablePolicySealUnsealWithKeyRotation(t *testing.T, oldPrivateKey crypto.PrivateKey, newPrivateKey crypto.PrivateKey) {
	oldPublicKey, err := extractPublicKey(oldPrivateKey)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	authorizationDigest, err := GenerateAuthDigest(oldPublicKey)
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
	sel := PCRSelection{Algo: AlgoSHA256, Indexes: PCR_INDEXES}

	sp, err := GenerateSignedPolicy(oldPrivateKey, pcrsList, rbp)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	writtenSecret := []byte("THIS_IS_VERY_SECRET")
	err = SealSecret(NV_INDEX, authorizationDigest, writtenSecret)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	rotation, newSP, err := RotateAuthDigestWithPolicy(oldPrivateKey, newPrivateKey, pcrs, rbp)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	err = ResealTpmSecretWithVerifiedAuthDigest(NV_INDEX, rotation, sp, sel, rbp)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	readSecret, err := UnsealSecret(NV_INDEX, rotation.NewPublicKey, newSP, sel, rbp)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	if bytes.Equal(writtenSecret, readSecret) != true {
		t.Fatalf("Expected %s, got %s", writtenSecret, readSecret)
	}

	// update sp for subsequent uses with the new key
	sp = newSP

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
	_, err = UnsealSecret(NV_INDEX, rotation.NewPublicKey, sp, sel, rbp)
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

	sp, err = GenerateSignedPolicy(newPrivateKey, pcrsList, rbp)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	readSecret, err = UnsealSecret(NV_INDEX, rotation.NewPublicKey, sp, sel, rbp)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	if bytes.Equal(writtenSecret, readSecret) != true {
		t.Fatalf("Expected %s, got %s", writtenSecret, readSecret)
	}

	// now let's increase the counter
	rbpCounter, err = IncreaseMonotonicCounter(NV_COUNTER_INDEX)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	// this should fail because the counter arithmetic op (ULE) don't hold anymore
	_, err = UnsealSecret(NV_INDEX, rotation.NewPublicKey, sp, sel, rbp)
	if err != nil {
		if strings.Contains(err.Error(), "TPM_RC_POLICY") != true {
			t.Fatalf("Expected TPM_RC_POLICY error, got  \"%v\"", err)
		}
	} else {
		t.Fatalf("Expected TPM_RC_POLICY error, got nil")
	}

	// update the policy and try again
	rbp.Check = rbpCounter
	sp, err = GenerateSignedPolicy(newPrivateKey, pcrsList, rbp)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	readSecret, err = UnsealSecret(NV_INDEX, rotation.NewPublicKey, sp, sel, rbp)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	if bytes.Equal(writtenSecret, readSecret) != true {
		t.Fatalf("Expected %s, got %s", writtenSecret, readSecret)
	}
}

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
