// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// client runs a demo of the full seal/unseal lifecycle against the server.
// Set SWTPM_PATH to the Unix socket of a software TPM before running.
package main

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	tpmea "github.com/lf-edge/eve-tpmea"
	"github.com/lf-edge/eve-tpmea/cmd/api"
)

const (
	nvIndex        = uint32(0x1500016)
	nvCounterIndex = uint32(0x1500017)
	aikHandle      = uint32(0x81000003)
)

type client struct{ base string }

// the PCR indexes we bind the policy to.
var pcrIndexes = []int{0, 1, 2, 3, 4}

func main() {
	serverURL := flag.String("server", "http://localhost:8765", "server base URL")
	aikPub := flag.String("aik-pub", "", "path to DER-encoded AIK public key file")
	flag.Parse()

	if path := os.Getenv("SWTPM_PATH"); path != "" {
		tpmea.ConnectToSwtpm(path)
	}

	c := &client{base: *serverURL}
	secret := []byte("SUPER_SECRET_VALUE")

	step("register AIK with server")
	must(c.registerAIK(*aikPub), "register AIK")
	log.Println("  Passed")

	step("onboarding: fetch auth digest and public key")
	authDigest, publicKey, err := c.init()
	must(err, "init")
	log.Println("  Passed")

	step("create rollback protection counter")
	counterVal, err := tpmea.DefineMonotonicCounter(nvCounterIndex)
	must(err, "define counter")
	rbp := tpmea.RBP{Counter: nvCounterIndex, Check: counterVal}
	log.Printf("  counter value: %d", counterVal)

	step("read current PCR values")
	pcrList, err := tpmea.ReadPCRs(pcrIndexes, tpmea.AlgoSHA256)
	must(err, "read PCRs")
	log.Println("  Passed")

	step("seal secret into TPM")
	must(tpmea.SealSecret(nvIndex, authDigest, secret), "seal secret")
	log.Println("  Passed")

	step("request signed policy from server (with NV certification)")
	sel := tpmea.PCRSelection{Algo: tpmea.AlgoSHA256, Indexes: pcrIndexes}
	nonce, err := c.nonce()
	must(err, "get nonce")
	cert, err := tpmea.CertifyNVCounter(aikHandle, rbp.Counter, nonce)
	must(err, "certify counter")
	sp, newRBP, err := c.signPolicy(pcrList, rbp, cert)
	must(err, "sign policy")
	log.Println("  Passed")

	step("increment counter to match the signed policy")
	counterVal, err = tpmea.IncreaseMonotonicCounter(nvCounterIndex)
	must(err, "increment counter")
	if counterVal != newRBP.Check {
		log.Fatalf("counter after increment %d does not match policy check %d", counterVal, newRBP.Check)
	}
	rbp = newRBP
	log.Printf("  counter value: %d", counterVal)

	step("unseal secret")
	readSecret, err := tpmea.UnsealSecret(nvIndex, publicKey, sp, sel, rbp)
	must(err, "unseal secret")
	checkEqual(secret, readSecret, "unseal")

	step("increment counter then request new policy - old policy must be rejected")
	oldSP, oldRBP := sp, rbp
	counterVal, err = tpmea.IncreaseMonotonicCounter(nvCounterIndex)
	must(err, "increment counter")
	rbp.Check = counterVal
	nonce, err = c.nonce()
	must(err, "get nonce")
	cert, err = tpmea.CertifyNVCounter(aikHandle, rbp.Counter, nonce)
	must(err, "certify counter")
	sp, newRBP, err = c.signPolicy(pcrList, rbp, cert)
	must(err, "sign next counter policy")
	counterVal, err = tpmea.IncreaseMonotonicCounter(nvCounterIndex)
	must(err, "increment counter to policy check")
	if counterVal != newRBP.Check {
		log.Fatalf("counter after increment %d does not match policy check %d", counterVal, newRBP.Check)
	}
	rbp = newRBP
	log.Printf("  counter value: %d", counterVal)

	step("unseal with new policy must succeed")
	readSecret, err = tpmea.UnsealSecret(nvIndex, publicKey, sp, sel, rbp)
	must(err, "unseal with next counter policy")
	checkEqual(secret, readSecret, "unseal with next counter policy")

	step("unseal with old policy must fail after counter increment")
	_, err = tpmea.UnsealSecret(nvIndex, publicKey, oldSP, sel, oldRBP)
	if err == nil {
		log.Fatal("expected error with old policy after counter increment, got nil")
	}
	log.Printf("  correctly rejected: %v", err)

	step("verify NV auth digest matches what the server issued")
	stored, err := tpmea.ReadNVAuthDigest(nvIndex)
	must(err, "read NV auth digest")
	if !bytes.Equal(stored, authDigest) {
		log.Fatalf("auth digest mismatch: stored=%x issued=%x", stored, authDigest)
	}
	log.Println("  auth digest matches")

	step("request policy signed over all-zero PCR values (intentionally wrong)")
	zeroPCRList := zeroPCRs(pcrIndexes)
	nonce, err = c.nonce()
	must(err, "get nonce")
	cert, err = tpmea.CertifyNVCounter(aikHandle, rbp.Counter, nonce)
	must(err, "certify counter")
	wrongSP, _, err := c.signPolicy(zeroPCRList, rbp, cert)
	must(err, "sign wrong policy")
	log.Println("  Passed")

	step("unseal with wrong policy must fail")
	_, err = tpmea.UnsealSecret(nvIndex, publicKey, wrongSP, sel, rbp)
	if err == nil {
		log.Fatal("expected error with wrong PCR policy, got nil")
	}
	log.Printf("  correctly rejected: %v", err)

	step("unseal with original policy still works")
	readSecret, err = tpmea.UnsealSecret(nvIndex, publicKey, sp, sel, rbp)
	must(err, "re-unseal with valid policy")
	checkEqual(secret, readSecret, "re-unseal")

	step("increment counter - old policy must be rejected")
	counterVal, err = tpmea.IncreaseMonotonicCounter(nvCounterIndex)
	must(err, "increment counter")
	_, err = tpmea.UnsealSecret(nvIndex, publicKey, sp, sel, rbp)
	if err == nil {
		log.Fatal("expected error after counter increment, got nil")
	}
	log.Printf("  correctly rejected: %v", err)

	step("certify new counter value, request updated policy")
	rbp.Check = counterVal
	nonce, err = c.nonce()
	must(err, "get nonce")
	cert, err = tpmea.CertifyNVCounter(aikHandle, rbp.Counter, nonce)
	must(err, "certify counter")
	sp, newRBP, err = c.signPolicy(pcrList, rbp, cert)
	must(err, "sign updated policy")
	counterVal, err = tpmea.IncreaseMonotonicCounter(nvCounterIndex)
	must(err, "increment counter to policy check")
	if counterVal != newRBP.Check {
		log.Fatalf("counter after increment %d does not match policy check %d", counterVal, newRBP.Check)
	}
	rbp = newRBP
	log.Printf("  counter value: %d", counterVal)

	step("unseal with updated counter policy")
	readSecret, err = tpmea.UnsealSecret(nvIndex, publicKey, sp, sel, rbp)
	must(err, "unseal with updated counter")
	checkEqual(secret, readSecret, "unseal after counter update")

	step("activate read lock on the NV index")
	must(tpmea.ActivateReadLock(nvIndex, publicKey, sp, sel, rbp), "activate read lock")
	log.Println("  Passed")

	step("unseal must fail after lock (until next TPM reset)")
	_, err = tpmea.UnsealSecret(nvIndex, publicKey, sp, sel, rbp)
	if err == nil {
		log.Fatal("expected error after read lock, got nil")
	}
	log.Printf("  correctly rejected: %v", err)

	fmt.Println()
	log.Println("=== demo complete ===")
}

func (c *client) registerAIK(aikPubPath string) error {
	der, err := os.ReadFile(aikPubPath)
	if err != nil {
		return fmt.Errorf("read AIK public key file %q: %w", aikPubPath, err)
	}
	return c.postNoResp("/api/register-aik", api.RegisterAIKReq{AIKPublicKeyDER: der})
}

func (c *client) init() (authDigest []byte, publicKey crypto.PublicKey, err error) {
	resp, err := http.Get(c.base + "/api/init")
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, httpErr(resp)
	}
	var r api.InitResp
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, nil, err
	}
	pub, err := x509.ParsePKIXPublicKey(r.PublicKeyDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parse public key: %w", err)
	}
	return r.AuthDigest, pub, nil
}

func (c *client) signPolicy(pcrList tpmea.PCRList, rbp tpmea.RBP, cert tpmea.NVCertification) (tpmea.SignedPolicy, tpmea.RBP, error) {
	var resp api.SignPolicyResp
	err := c.post("/api/sign-policy", api.SignPolicyReq{
		PCRList: toAPIPCRList(pcrList),
		RBP:     toAPIRBP(rbp),
		NVCert:  toAPINVCert(cert),
	}, &resp)
	if err != nil {
		return tpmea.SignedPolicy{}, tpmea.RBP{}, err
	}
	newRBP := tpmea.RBP{Counter: resp.NewRBP.Counter, Check: resp.NewRBP.Check}
	return fromAPISP(resp.SignedPolicy), newRBP, nil
}

func (c *client) nonce() ([]byte, error) {
	resp, err := http.Get(c.base + "/api/nonce")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, httpErr(resp)
	}
	var r api.NonceResp
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, err
	}
	return r.Nonce, nil
}

func (c *client) post(path string, body, result interface{}) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	resp, err := http.Post(c.base+path, "application/json", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return httpErr(resp)
	}
	return json.NewDecoder(resp.Body).Decode(result)
}

func (c *client) postNoResp(path string, body interface{}) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	resp, err := http.Post(c.base+path, "application/json", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return httpErr(resp)
	}
	return nil
}

func httpErr(resp *http.Response) error {
	body, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("server %d: %s", resp.StatusCode, bytes.TrimSpace(body))
}

func toAPIPCRList(l tpmea.PCRList) api.PCRList {
	pcrs := make([]api.PCR, len(l.Pcrs))
	for i, p := range l.Pcrs {
		pcrs[i] = api.PCR{Index: p.Index, Digest: p.Digest}
	}
	return api.PCRList{Algo: int(l.Algo), PCRs: pcrs}
}

func toAPIRBP(r tpmea.RBP) api.RBP {
	return api.RBP{Counter: r.Counter, Check: r.Check}
}

func toAPINVCert(c tpmea.NVCertification) *api.NVCert {
	return &api.NVCert{
		Nonce:      c.Nonce,
		AttestBlob: c.AttestBlob,
		RSASig:     c.RSASig,
		ECCSigR:    c.ECCSigR,
		ECCSigS:    c.ECCSigS,
	}
}

func fromAPISP(sp api.SignedPolicy) tpmea.SignedPolicy {
	return tpmea.SignedPolicy{
		Digest: sp.Digest,
		Sig: &tpmea.PolicySignature{
			RSASignature:  sp.Sig.RSASignature,
			ECCSignatureR: sp.Sig.ECCSignatureR,
			ECCSignatureS: sp.Sig.ECCSignatureS,
		},
	}
}

func zeroPCRs(indexes []int) tpmea.PCRList {
	pcrs := make(tpmea.PCRS, len(indexes))
	for i, idx := range indexes {
		pcrs[i] = tpmea.PCR{Index: idx, Digest: make([]byte, 32)}
	}
	return tpmea.PCRList{Algo: tpmea.AlgoSHA256, Pcrs: pcrs}
}

func step(msg string) {
	fmt.Println()
	log.Printf("=== %s ===", msg)
}

func must(err error, label string) {
	if err != nil {
		log.Fatalf("%s: %v", label, err)
	}
}

func checkEqual(want, got []byte, label string) {
	if !bytes.Equal(want, got) {
		log.Fatalf("%s: want %q got %q", label, want, got)
	}
	log.Printf("  %s: OK (%q)", label, got)
}
