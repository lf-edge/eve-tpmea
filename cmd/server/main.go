// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// server is a simple HTTP controller that holds a signing key and issues
// authorization digests and signed policies for client devices. In a real
// deployment this process would run on the attestation server, not on the
// device itself.
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"

	tpmea "github.com/lf-edge/eve-tpmea"
	"github.com/lf-edge/eve-tpmea/cmd/api"
)

type srv struct {
	mu         sync.RWMutex
	privateKey crypto.PrivateKey
	authDigest []byte

	// aikPub is the client's AIK public key, registered via /api/register-aik.
	// When set, the server verifies NV counter certifications before signing.
	aikPub crypto.PublicKey

	// latestNonce is the last freshness token issued via /api/nonce.
	latestNonce []byte
}

func main() {
	addr    := flag.String("addr", ":8765", "listen address")
	keyType := flag.String("key-type", "rsa", "signing key type: rsa or ecc")
	flag.Parse()

	if path := os.Getenv("SWTPM_PATH"); path != "" {
		tpmea.ConnectToSwtpm(path)
	}

	priv, pub, err := generateKey(*keyType)
	if err != nil {
		log.Fatalf("generate key: %v", err)
	}

	authDigest, err := tpmea.GenerateAuthDigest(pub)
	if err != nil {
		log.Fatalf("generate auth digest: %v", err)
	}

	s := &srv{privateKey: priv, authDigest: authDigest}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/init",         s.handleInit)
	mux.HandleFunc("/api/register-aik", s.handleRegisterAIK)
	mux.HandleFunc("/api/nonce",        s.handleNonce)
	mux.HandleFunc("/api/sign-policy",  s.handleSignPolicy)
	mux.HandleFunc("/api/rotate",       s.handleRotate)

	log.Printf("server listening on %s (key type: %s)", *addr, *keyType)
	log.Fatal(http.ListenAndServe(*addr, mux))
}

// handleInit returns the current authorization digest and public key so the
// client can seal a secret for the first time.
func (s *srv) handleInit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	pub, err := publicKeyOf(s.privateKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, api.InitResp{
		AuthDigest:   s.authDigest,
		PublicKeyDER: pubDER,
	})
}

// handleRegisterAIK stores the client's AIK public key. The server uses it to
// verify NV counter certifications on subsequent sign-policy requests.
func (s *srv) handleRegisterAIK(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req api.RegisterAIKReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	pub, err := x509.ParsePKIXPublicKey(req.AIKPublicKeyDER)
	if err != nil {
		http.Error(w, fmt.Sprintf("parse AIK: %v", err), http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	s.aikPub = pub
	s.mu.Unlock()

	log.Printf("AIK registered (%T)", pub)
	w.WriteHeader(http.StatusNoContent)
}

// handleNonce returns a fresh random nonce. The client must include this nonce
// when certifying its NV counter so the server can confirm freshness.
func (s *srv) handleNonce(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.mu.Lock()
	s.latestNonce = nonce
	s.mu.Unlock()

	writeJSON(w, api.NonceResp{Nonce: nonce})
}

// handleSignPolicy signs a policy for the PCR values and rollback protection
// counter that the client sends. If the client includes an NV certification
// the server verifies the counter value against it before signing; otherwise
// the counter value is trusted as-is.
func (s *srv) handleSignPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req api.SignPolicyReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.mu.RLock()
	priv     := s.privateKey
	aikPub   := s.aikPub
	issuedNonce := s.latestNonce
	s.mu.RUnlock()

	rbp := fromAPIRBP(req.RBP)

	if req.NVCert != nil {
		if aikPub == nil {
			http.Error(w, "NV certification provided but no AIK registered", http.StatusBadRequest)
			return
		}
		cert := fromAPINVCert(req.NVCert)
		certified, err := tpmea.VerifyNVCounter(&cert, aikPub, issuedNonce)
		if err != nil {
			http.Error(w, fmt.Sprintf("NV counter verification failed: %v", err), http.StatusUnauthorized)
			return
		}
		if certified != req.RBP.Check {
			http.Error(w, fmt.Sprintf("counter mismatch: certified=%d policy-check=%d", certified, req.RBP.Check), http.StatusUnauthorized)
			return
		}
		log.Printf("NV counter certified: value=%d", certified)
		// Sign the next counter value - client must increment before unsealing.
		rbp.Check = certified + 1
	}

	sp, err := tpmea.GenerateSignedPolicy(priv, fromAPIPCRList(req.PCRList), rbp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, api.SignPolicyResp{
		SignedPolicy: toAPISP(sp),
		NewRBP:       api.RBP{Counter: rbp.Counter, Check: rbp.Check},
	})
}

// handleRotate generates a new signing key of the same type, signs it with
// the current key to establish a chain of trust, and returns the rotation
// bundle along with a freshly signed policy. After this the server discards
// the old key.
func (s *srv) handleRotate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req api.RotateReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.mu.RLock()
	newKey, err := generateSameTypeKey(s.privateKey)
	s.mu.RUnlock()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.mu.Lock()
	rotation, newSP, err := tpmea.RotateAuthDigestWithPolicy(
		s.privateKey, newKey, fromAPIPCRList(req.PCRList), fromAPIRBP(req.RBP))
	if err != nil {
		s.mu.Unlock()
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.privateKey = newKey
	s.authDigest = rotation.NewAuthDigest
	s.mu.Unlock()

	oldDER, err := x509.MarshalPKIXPublicKey(rotation.OldPublicKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	newDER, err := x509.MarshalPKIXPublicKey(rotation.NewPublicKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, api.RotateResp{
		OldPublicKeyDER: oldDER,
		NewPublicKeyDER: newDER,
		NewKeySig:       rotation.NewKeySig,
		NewAuthDigest:   rotation.NewAuthDigest,
		SignedPolicy:    toAPISP(newSP),
	})
}

// helpers

func generateKey(keyType string) (crypto.PrivateKey, crypto.PublicKey, error) {
	switch keyType {
	case "rsa":
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, nil, err
		}
		return k, &k.PublicKey, nil
	case "ecc":
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return k, &k.PublicKey, nil
	default:
		return nil, nil, fmt.Errorf("unknown key type %q, want rsa or ecc", keyType)
	}
}

func generateSameTypeKey(priv crypto.PrivateKey) (crypto.PrivateKey, error) {
	switch priv.(type) {
	case *ecdsa.PrivateKey:
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		return k, err
	default:
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		return k, err
	}
}

func publicKeyOf(priv crypto.PrivateKey) (crypto.PublicKey, error) {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey, nil
	case *ecdsa.PrivateKey:
		return &k.PublicKey, nil
	default:
		return nil, fmt.Errorf("unknown key type %T", priv)
	}
}

func fromAPIPCRList(a api.PCRList) tpmea.PCRList {
	pcrs := make(tpmea.PCRS, len(a.PCRs))
	for i, p := range a.PCRs {
		pcrs[i] = tpmea.PCR{Index: p.Index, Digest: p.Digest}
	}
	return tpmea.PCRList{Algo: tpmea.PCRHashAlgo(a.Algo), Pcrs: pcrs}
}

func fromAPIRBP(a api.RBP) tpmea.RBP {
	return tpmea.RBP{Counter: a.Counter, Check: a.Check}
}

func fromAPINVCert(a *api.NVCert) tpmea.NVCertification {
	return tpmea.NVCertification{
		Nonce:      a.Nonce,
		AttestBlob: a.AttestBlob,
		RSASig:     a.RSASig,
		ECCSigR:    a.ECCSigR,
		ECCSigS:    a.ECCSigS,
	}
}

func toAPISP(sp tpmea.SignedPolicy) api.SignedPolicy {
	out := api.SignedPolicy{Digest: sp.Digest}
	if sp.Sig != nil {
		out.Sig = api.PolicySig{
			RSASignature:  sp.Sig.RSASignature,
			ECCSignatureR: sp.Sig.ECCSignatureR,
			ECCSignatureS: sp.Sig.ECCSignatureS,
		}
	}
	return out
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("write JSON: %v", err)
	}
}
