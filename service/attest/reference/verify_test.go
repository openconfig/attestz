// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	cpb "github.com/openconfig/attestz/proto/common_definitions"
	apb "github.com/openconfig/attestz/proto/tpm_attestz"
)

type testCertChain struct {
	rootCert      *x509.Certificate
	interCert     *x509.Certificate
	interKey      *rsa.PrivateKey
	oiakCert      *x509.Certificate
	oiakKey       *rsa.PrivateKey
	oiakPEM       string
	rootPool      *x509.CertPool
	interPool     *x509.CertPool
	untrustedPool *x509.CertPool
}

func generateTestCertChain(t *testing.T) *testCertChain {
	t.Helper()

	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate root RSA key: %v", err)
	}

	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Root CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("failed to create root cert: %v", err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("failed to parse root cert: %v", err)
	}

	interKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate intermediate RSA key: %v", err)
	}

	interTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "Test Intermediate CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	interDER, err := x509.CreateCertificate(rand.Reader, interTemplate, rootCert, &interKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("failed to create intermediate cert: %v", err)
	}
	interCert, err := x509.ParseCertificate(interDER)
	if err != nil {
		t.Fatalf("failed to parse intermediate cert: %v", err)
	}

	oiakKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate OIAK RSA key: %v", err)
	}

	oiakTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			CommonName: "Test OIAK",
		},
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	oiakDER, err := x509.CreateCertificate(rand.Reader, oiakTemplate, interCert, &oiakKey.PublicKey, interKey)
	if err != nil {
		t.Fatalf("failed to create OIAK cert: %v", err)
	}
	oiakCert, err := x509.ParseCertificate(oiakDER)
	if err != nil {
		t.Fatalf("failed to parse OIAK cert: %v", err)
	}

	oiakPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: oiakDER})

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	interPool := x509.NewCertPool()
	interPool.AddCert(interCert)

	untrustedPool := x509.NewCertPool()

	return &testCertChain{
		rootCert:      rootCert,
		interCert:     interCert,
		interKey:      interKey,
		oiakCert:      oiakCert,
		oiakKey:       oiakKey,
		oiakPEM:       string(oiakPEM),
		rootPool:      rootPool,
		interPool:     interPool,
		untrustedPool: untrustedPool,
	}
}

type testECDSACertChain struct {
	rootCert  *x509.Certificate
	interCert *x509.Certificate
	interKey  *ecdsa.PrivateKey
	oiakCert  *x509.Certificate
	oiakKey   *ecdsa.PrivateKey
	oiakPEM   string
	rootPool  *x509.CertPool
	interPool *x509.CertPool
}

func generateTestECDSACertChain(t *testing.T, curve elliptic.Curve) *testECDSACertChain {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate root ECDSA key: %v", err)
	}

	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test ECDSA Root CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("failed to create root cert: %v", err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("failed to parse root cert: %v", err)
	}

	interKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate intermediate ECDSA key: %v", err)
	}

	interTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "Test ECDSA Intermediate CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	interDER, err := x509.CreateCertificate(rand.Reader, interTemplate, rootCert, &interKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("failed to create intermediate cert: %v", err)
	}
	interCert, err := x509.ParseCertificate(interDER)
	if err != nil {
		t.Fatalf("failed to parse intermediate cert: %v", err)
	}

	oiakKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate OIAK ECDSA key: %v", err)
	}

	oiakTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			CommonName: "Test ECDSA OIAK",
		},
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	oiakDER, err := x509.CreateCertificate(rand.Reader, oiakTemplate, interCert, &oiakKey.PublicKey, interKey)
	if err != nil {
		t.Fatalf("failed to create OIAK cert: %v", err)
	}
	oiakCert, err := x509.ParseCertificate(oiakDER)
	if err != nil {
		t.Fatalf("failed to parse OIAK cert: %v", err)
	}

	oiakPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: oiakDER})

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	interPool := x509.NewCertPool()
	interPool.AddCert(interCert)

	return &testECDSACertChain{
		rootCert:  rootCert,
		interCert: interCert,
		interKey:  interKey,
		oiakCert:  oiakCert,
		oiakKey:   oiakKey,
		oiakPEM:   string(oiakPEM),
		rootPool:  rootPool,
		interPool: interPool,
	}
}

func createRawECDSASignature(t *testing.T, key *ecdsa.PrivateKey, hash []byte) []byte {
	t.Helper()
	r, s, err := ecdsa.Sign(rand.Reader, key, hash)
	if err != nil {
		t.Fatalf("failed to sign with ECDSA: %v", err)
	}
	curveByteLen := (key.Curve.Params().N.BitLen() + 7) / 8
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	sig := make([]byte, 2*curveByteLen)
	copy(sig[curveByteLen-len(rBytes):curveByteLen], rBytes)
	copy(sig[2*curveByteLen-len(sBytes):], sBytes)
	return sig
}

func createTPMTECDSASignature(t *testing.T, key *ecdsa.PrivateKey, hash []byte, tpmAlg tpm2.TPMAlgID) []byte {
	t.Helper()
	r, s, err := ecdsa.Sign(rand.Reader, key, hash)
	if err != nil {
		t.Fatalf("failed to sign with ECDSA: %v", err)
	}
	tpmSig := &tpm2.TPMTSignature{
		SigAlg: tpm2.TPMAlgECDSA,
		Signature: tpm2.NewTPMUSignature(tpm2.TPMAlgECDSA, &tpm2.TPMSSignatureECC{
			Hash:       tpmAlg,
			SignatureR: tpm2.TPM2BECCParameter{Buffer: r.Bytes()},
			SignatureS: tpm2.TPM2BECCParameter{Buffer: s.Bytes()},
		}),
	}
	return tpm2.Marshal(tpmSig)
}

func createTPMSSignatureECC(t *testing.T, key *ecdsa.PrivateKey, hash []byte, tpmAlg tpm2.TPMAlgID) []byte {
	t.Helper()
	r, s, err := ecdsa.Sign(rand.Reader, key, hash)
	if err != nil {
		t.Fatalf("failed to sign with ECDSA: %v", err)
	}
	eccSig := &tpm2.TPMSSignatureECC{
		Hash:       tpmAlg,
		SignatureR: tpm2.TPM2BECCParameter{Buffer: r.Bytes()},
		SignatureS: tpm2.TPM2BECCParameter{Buffer: s.Bytes()},
	}
	return tpm2.Marshal(eccSig)
}

func createAttestResponse(oiakPEM string, quoted, sig []byte, pcrValues map[int32][]byte) *apb.AttestResponse {
	return &apb.AttestResponse{
		AttestationCert: &apb.AttestResponse_AttestationCert{
			Value: &apb.AttestResponse_AttestationCert_OiakCert{
				OiakCert: oiakPEM,
			},
		},
		Quoted:         quoted,
		QuoteSignature: sig,
		PcrValues:      pcrValues,
	}
}

func createValidQuote(t *testing.T, requestedIndices []int32, pcrValues map[int32][]byte, nonce []byte, key crypto.PrivateKey, hashAlgo cpb.Tpm20HashAlgo) ([]byte, []byte) {
	t.Helper()

	var (
		cryptoHash    crypto.Hash
		tpmAlg        tpm2.TPMAlgID
		computeDigest func([]byte) []byte
	)
	switch hashAlgo {
	case cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA256:
		cryptoHash = crypto.SHA256
		tpmAlg = tpm2.TPMAlgSHA256
		computeDigest = func(b []byte) []byte {
			d := sha256.Sum256(b)
			return d[:]
		}
	case cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA384:
		cryptoHash = crypto.SHA384
		tpmAlg = tpm2.TPMAlgSHA384
		computeDigest = func(b []byte) []byte {
			d := sha512.Sum384(b)
			return d[:]
		}
	default:
		t.Fatalf("unsupported hash algorithm in createValidQuote: %v", hashAlgo)
	}

	var sortedIndices []int32
	sortedIndices = append(sortedIndices, requestedIndices...)
	sort.Slice(sortedIndices, func(i, j int) bool { return sortedIndices[i] < sortedIndices[j] })

	pcrBitmask := make([]byte, 3)
	for _, idx := range sortedIndices {
		if idx >= 0 && idx <= 23 {
			pcrBitmask[idx/8] |= (1 << (idx % 8))
		}
	}

	expectedPcrSelect := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				Hash:      tpmAlg,
				PCRSelect: pcrBitmask,
			},
		},
	}

	var pcrConcat []byte
	for _, idx := range sortedIndices {
		val, ok := pcrValues[int32(idx)]
		if !ok {
			t.Fatalf("missing PCR index %d in pcrValues", idx)
		}
		pcrConcat = append(pcrConcat, val...)
	}
	reportedDigest := computeDigest(pcrConcat)

	attest := tpm2.TPMSAttest{
		Magic:     tpm2.TPMGeneratedValue,
		Type:      tpm2.TPMSTAttestQuote,
		ExtraData: tpm2.TPM2BData{Buffer: nonce},
		Attested: tpm2.NewTPMUAttest(tpm2.TPMSTAttestQuote, &tpm2.TPMSQuoteInfo{
			PCRSelect: expectedPcrSelect,
			PCRDigest: tpm2.TPM2BDigest{Buffer: reportedDigest},
		}),
	}

	quoted := tpm2.Marshal(attest)
	hash := computeDigest(quoted)
	var (
		sig []byte
		err error
	)
	switch k := key.(type) {
	case *rsa.PrivateKey:
		sig, err = rsa.SignPKCS1v15(rand.Reader, k, cryptoHash, hash)
		if err != nil {
			t.Fatalf("failed to sign quote with RSA: %v", err)
		}
	case *ecdsa.PrivateKey:
		sig, err = ecdsa.SignASN1(rand.Reader, k, hash)
		if err != nil {
			t.Fatalf("failed to sign quote with ECDSA: %v", err)
		}
	default:
		t.Fatalf("unsupported key type in createValidQuote: %T", key)
	}

	return quoted, sig
}

func TestVerifyRemoteAttestationSuccess(t *testing.T) {
	chain := generateTestCertChain(t)

	tests := []struct {
		name      string
		hashAlgo  cpb.Tpm20HashAlgo
		digestLen int
	}{
		{
			name:      "SHA256",
			hashAlgo:  cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA256,
			digestLen: 32,
		},
		{
			name:      "SHA384",
			hashAlgo:  cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA384,
			digestLen: 48,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			requestedIndices := []int32{0, 4, 7}
			pcrValues := map[int32][]byte{
				0: bytesRepeat(0x01, tc.digestLen),
				4: bytesRepeat(0x02, tc.digestLen),
				7: bytesRepeat(0x03, tc.digestLen),
			}
			expectedPCRs := map[int][]byte{
				0: bytesRepeat(0x01, tc.digestLen),
				4: bytesRepeat(0x02, tc.digestLen),
				7: bytesRepeat(0x03, tc.digestLen),
			}
			expectedNonce := []byte("test-random-nonce-12345678901234")

			quoted, sig := createValidQuote(t, requestedIndices, pcrValues, expectedNonce, chain.oiakKey, tc.hashAlgo)

			resp := createAttestResponse(chain.oiakPEM, quoted, sig, pcrValues)

			if err := VerifyRemoteAttestation(resp, expectedPCRs, requestedIndices, expectedNonce, chain.rootPool, chain.interPool, tc.hashAlgo); err != nil {
				t.Fatalf("VerifyRemoteAttestation() failed unexpectedly: %v", err)
			}
		})
	}
}

func TestVerifyRemoteAttestationECDSASuccess(t *testing.T) {
	tests := []struct {
		name      string
		curve     elliptic.Curve
		hashAlgo  cpb.Tpm20HashAlgo
		tpmAlg    tpm2.TPMAlgID
		digestLen int
	}{
		{
			name:      "P256_SHA256",
			curve:     elliptic.P256(),
			hashAlgo:  cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA256,
			tpmAlg:    tpm2.TPMAlgSHA256,
			digestLen: 32,
		},
		{
			name:      "P384_SHA384",
			curve:     elliptic.P384(),
			hashAlgo:  cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA384,
			tpmAlg:    tpm2.TPMAlgSHA384,
			digestLen: 48,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			chain := generateTestECDSACertChain(t, tc.curve)
			requestedIndices := []int32{0, 4, 7}
			pcrValues := map[int32][]byte{
				0: bytesRepeat(0x01, tc.digestLen),
				4: bytesRepeat(0x02, tc.digestLen),
				7: bytesRepeat(0x03, tc.digestLen),
			}
			expectedPCRs := map[int][]byte{
				0: bytesRepeat(0x01, tc.digestLen),
				4: bytesRepeat(0x02, tc.digestLen),
				7: bytesRepeat(0x03, tc.digestLen),
			}
			expectedNonce := []byte("test-random-nonce-12345678901234")

			quoted, asn1Sig := createValidQuote(t, requestedIndices, pcrValues, expectedNonce, chain.oiakKey, tc.hashAlgo)

			var hash []byte
			if tc.hashAlgo == cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA256 {
				h := sha256.Sum256(quoted)
				hash = h[:]
			} else {
				h := sha512.Sum384(quoted)
				hash = h[:]
			}

			sigFormats := []struct {
				formatName string
				sig        []byte
			}{
				{"ASN1", asn1Sig},
				{"RawIEEEP1363", createRawECDSASignature(t, chain.oiakKey, hash)},
				{"TPMTSignature", createTPMTECDSASignature(t, chain.oiakKey, hash, tc.tpmAlg)},
				{"TPMSSignatureECC", createTPMSSignatureECC(t, chain.oiakKey, hash, tc.tpmAlg)},
			}

			for _, sf := range sigFormats {
				t.Run(sf.formatName, func(t *testing.T) {
					resp := createAttestResponse(chain.oiakPEM, quoted, sf.sig, pcrValues)
					if err := VerifyRemoteAttestation(resp, expectedPCRs, requestedIndices, expectedNonce, chain.rootPool, chain.interPool, tc.hashAlgo); err != nil {
						t.Fatalf("VerifyRemoteAttestation() failed with format %s: %v", sf.formatName, err)
					}
				})
			}
		})
	}

	t.Run("HybridChain_RSAIntermediate_ECDSAOIAK", func(t *testing.T) {
		rsaChain := generateTestCertChain(t)
		ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate ecdsa key: %v", err)
		}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(99),
			Subject:      pkix.Name{CommonName: "Hybrid ECDSA OIAK"},
			NotBefore:    time.Now().Add(-1 * time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}
		ecdsaDER, err := x509.CreateCertificate(rand.Reader, template, rsaChain.interCert, &ecdsaKey.PublicKey, rsaChain.interKey)
		if err != nil {
			t.Fatalf("failed to create hybrid ecdsa cert: %v", err)
		}
		ecdsaPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ecdsaDER})

		requestedIndices := []int32{0}
		pcrValues := map[int32][]byte{0: bytesRepeat(0xAA, 32)}
		expectedPCRs := map[int][]byte{0: bytesRepeat(0xAA, 32)}
		nonce := []byte("test-nonce")

		quoted, sig := createValidQuote(t, requestedIndices, pcrValues, nonce, ecdsaKey, cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA256)
		resp := createAttestResponse(string(ecdsaPEM), quoted, sig, pcrValues)

		if err := VerifyRemoteAttestation(resp, expectedPCRs, requestedIndices, nonce, rsaChain.rootPool, rsaChain.interPool, cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA256); err != nil {
			t.Fatalf("hybrid chain verification failed: %v", err)
		}
	})
}

func TestVerifyRemoteAttestationCertificateErrors(t *testing.T) {
	chain := generateTestCertChain(t)
	requestedIndices := []int32{0}
	pcrValues := map[int32][]byte{0: bytesRepeat(0xAA, 48)}
	expectedPCRs := map[int][]byte{0: bytesRepeat(0xAA, 48)}
	nonce := []byte("test-nonce")
	quoted, sig := createValidQuote(t, requestedIndices, pcrValues, nonce, chain.oiakKey, cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA384)

	t.Run("InvalidPEM", func(t *testing.T) {
		resp := createAttestResponse("not-a-valid-pem", quoted, sig, pcrValues)
		err := VerifyRemoteAttestation(resp, expectedPCRs, requestedIndices, nonce, chain.rootPool, chain.interPool, cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA384)
		if err == nil || !strings.Contains(err.Error(), "failed to decode OIAK PEM block") {
			t.Errorf("expected error 'failed to decode OIAK PEM block', got: %v", err)
		}
	})

	t.Run("InvalidCertBytes", func(t *testing.T) {
		corruptedPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("corrupted certificate bytes")})
		resp := createAttestResponse(string(corruptedPEM), quoted, sig, pcrValues)
		err := VerifyRemoteAttestation(resp, expectedPCRs, requestedIndices, nonce, chain.rootPool, chain.interPool, cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA384)
		if err == nil || !strings.Contains(err.Error(), "failed to parse OIAK certificate") {
			t.Errorf("expected error 'failed to parse OIAK certificate', got: %v", err)
		}
	})

	t.Run("UntrustedChain", func(t *testing.T) {
		resp := createAttestResponse(chain.oiakPEM, quoted, sig, pcrValues)
		err := VerifyRemoteAttestation(resp, expectedPCRs, requestedIndices, nonce, chain.untrustedPool, chain.interPool, cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA384)
		if err == nil || !strings.Contains(err.Error(), "certificate chain of trust validation failed") {
			t.Errorf("expected error 'certificate chain of trust validation failed', got: %v", err)
		}
	})

	t.Run("UnsupportedPublicKeyType", func(t *testing.T) {
		edPub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate ed25519 key: %v", err)
		}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(99),
			Subject:      pkix.Name{CommonName: "Ed25519 Cert"},
			NotBefore:    time.Now().Add(-1 * time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}
		edDER, err := x509.CreateCertificate(rand.Reader, template, chain.interCert, edPub, chain.interKey)
		if err != nil {
			t.Fatalf("failed to create ed25519 cert: %v", err)
		}
		edPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: edDER})

		resp := createAttestResponse(string(edPEM), quoted, sig, pcrValues)
		err = VerifyRemoteAttestation(resp, expectedPCRs, requestedIndices, nonce, chain.rootPool, chain.interPool, cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA384)
		if err == nil || !strings.Contains(err.Error(), "OIAK certificate does not contain an RSA or ECDSA public key") {
			t.Errorf("expected error 'OIAK certificate does not contain an RSA or ECDSA public key', got: %v", err)
		}
	})
}

func TestVerifyRemoteAttestationSignatureError(t *testing.T) {
	chain := generateTestCertChain(t)
	requestedIndices := []int32{0}
	pcrValues := map[int32][]byte{0: bytesRepeat(0xAA, 48)}
	expectedPCRs := map[int][]byte{0: bytesRepeat(0xAA, 48)}
	nonce := []byte("test-nonce")
	quoted, sig := createValidQuote(t, requestedIndices, pcrValues, nonce, chain.oiakKey, cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA384)

	// Tamper with the signature.
	corruptedSig := make([]byte, len(sig))
	copy(corruptedSig, sig)
	corruptedSig[0] ^= 0xFF

	resp := createAttestResponse(chain.oiakPEM, quoted, corruptedSig, pcrValues)

	err := VerifyRemoteAttestation(resp, expectedPCRs, requestedIndices, nonce, chain.rootPool, chain.interPool, cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA384)
	if err == nil || !strings.Contains(err.Error(), "quote signature verification failed") {
		t.Errorf("expected error 'quote signature verification failed', got: %v", err)
	}
}

func TestVerifyRemoteAttestationECDSASignatureErrors(t *testing.T) {
	chain := generateTestECDSACertChain(t, elliptic.P256())
	requestedIndices := []int32{0}
	pcrValues := map[int32][]byte{0: bytesRepeat(0xAA, 32)}
	expectedPCRs := map[int][]byte{0: bytesRepeat(0xAA, 32)}
	nonce := []byte("test-nonce")
	quoted, sig := createValidQuote(t, requestedIndices, pcrValues, nonce, chain.oiakKey, cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA256)

	t.Run("CorruptedSignature", func(t *testing.T) {
		corruptedSig := make([]byte, len(sig))
		copy(corruptedSig, sig)
		corruptedSig[len(corruptedSig)-1] ^= 0xFF

		resp := createAttestResponse(chain.oiakPEM, quoted, corruptedSig, pcrValues)
		err := VerifyRemoteAttestation(resp, expectedPCRs, requestedIndices, nonce, chain.rootPool, chain.interPool, cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA256)
		if err == nil || !strings.Contains(err.Error(), "quote signature verification failed") {
			t.Errorf("expected error 'quote signature verification failed', got: %v", err)
		}
	})

	t.Run("WrongKeySignature", func(t *testing.T) {
		otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}
		_, otherSig := createValidQuote(t, requestedIndices, pcrValues, nonce, otherKey, cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA256)

		resp := createAttestResponse(chain.oiakPEM, quoted, otherSig, pcrValues)
		err = VerifyRemoteAttestation(resp, expectedPCRs, requestedIndices, nonce, chain.rootPool, chain.interPool, cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA256)
		if err == nil || !strings.Contains(err.Error(), "quote signature verification failed") {
			t.Errorf("expected error 'quote signature verification failed', got: %v", err)
		}
	})

	t.Run("HashAlgoMismatch", func(t *testing.T) {
		// Quote created with SHA256 verified with SHA384
		err := VerifyRemoteAttestation(createAttestResponse(chain.oiakPEM, quoted, sig, pcrValues), expectedPCRs, requestedIndices, nonce, chain.rootPool, chain.interPool, cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA384)
		if err == nil || !strings.Contains(err.Error(), "quote signature verification failed") {
			t.Errorf("expected error 'quote signature verification failed', got: %v", err)
		}
	})
}

func TestVerifyRemoteAttestationQuoteErrors(t *testing.T) {
	chain := generateTestCertChain(t)
	requestedIndices := []int32{0, 4}
	pcrValues := map[int32][]byte{
		0: bytesRepeat(0x11, 48),
		4: bytesRepeat(0x22, 48),
	}
	expectedPCRs := map[int][]byte{
		0: bytesRepeat(0x11, 48),
		4: bytesRepeat(0x22, 48),
	}
	nonce := []byte("test-nonce-12345")

	t.Run("BadAttestationBytes", func(t *testing.T) {
		corruptedQuoted := []byte("not-a-tpms-attest-structure")
		hash := sha512.Sum384(corruptedQuoted)
		sig, _ := rsa.SignPKCS1v15(rand.Reader, chain.oiakKey, crypto.SHA384, hash[:])

		resp := createAttestResponse(chain.oiakPEM, corruptedQuoted, sig, pcrValues)
		err := VerifyRemoteAttestation(resp, expectedPCRs, requestedIndices, nonce, chain.rootPool, chain.interPool, cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA384)
		if err == nil || !strings.Contains(err.Error(), "bad Quote attestation") {
			t.Errorf("expected error 'bad Quote attestation', got: %v", err)
		}
	})

	t.Run("WrongMagicValue", func(t *testing.T) {
		attest := tpm2.TPMSAttest{
			Magic:     0x12345678, // Wrong magic
			Type:      tpm2.TPMSTAttestQuote,
			ExtraData: tpm2.TPM2BData{Buffer: nonce},
			Attested: tpm2.NewTPMUAttest(tpm2.TPMSTAttestQuote, &tpm2.TPMSQuoteInfo{
				PCRSelect: tpm2.TPMLPCRSelection{
					PCRSelections: []tpm2.TPMSPCRSelection{{Hash: tpm2.TPMAlgSHA384, PCRSelect: []byte{0x11, 0x00, 0x00}}},
				},
				PCRDigest: tpm2.TPM2BDigest{Buffer: bytesRepeat(0x00, 48)},
			}),
		}
		quoted := tpm2.Marshal(attest)
		hash := sha512.Sum384(quoted)
		sig, _ := rsa.SignPKCS1v15(rand.Reader, chain.oiakKey, crypto.SHA384, hash[:])

		resp := createAttestResponse(chain.oiakPEM, quoted, sig, pcrValues)
		err := VerifyRemoteAttestation(resp, expectedPCRs, requestedIndices, nonce, chain.rootPool, chain.interPool, cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA384)
		if err == nil || !strings.Contains(err.Error(), "wrong magic value") {
			t.Errorf("expected error 'wrong magic value', got: %v", err)
		}
	})

	t.Run("WrongQuoteAttestationType", func(t *testing.T) {
		attest := tpm2.TPMSAttest{
			Magic:     tpm2.TPMGeneratedValue,
			Type:      tpm2.TPMSTAttestCertify, // Wrong type
			ExtraData: tpm2.TPM2BData{Buffer: nonce},
			Attested:  tpm2.NewTPMUAttest(tpm2.TPMSTAttestCertify, &tpm2.TPMSCertifyInfo{}),
		}
		quoted := tpm2.Marshal(attest)
		hash := sha512.Sum384(quoted)
		sig, _ := rsa.SignPKCS1v15(rand.Reader, chain.oiakKey, crypto.SHA384, hash[:])

		resp := createAttestResponse(chain.oiakPEM, quoted, sig, pcrValues)
		err := VerifyRemoteAttestation(resp, expectedPCRs, requestedIndices, nonce, chain.rootPool, chain.interPool, cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA384)
		if err == nil || !strings.Contains(err.Error(), "wrong Quote attestation type") {
			t.Errorf("expected error 'wrong Quote attestation type', got: %v", err)
		}
	})

	t.Run("NonceMismatch", func(t *testing.T) {
		wrongNonce := []byte("different-nonce-12345")
		quoted, sig := createValidQuote(t, requestedIndices, pcrValues, wrongNonce, chain.oiakKey, cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA384)

		resp := createAttestResponse(chain.oiakPEM, quoted, sig, pcrValues)
		err := VerifyRemoteAttestation(resp, expectedPCRs, requestedIndices, nonce, chain.rootPool, chain.interPool, cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA384)
		if err == nil || !strings.Contains(err.Error(), "wrong nonce") {
			t.Errorf("expected error 'wrong nonce', got: %v", err)
		}
	})

	t.Run("PCRSelectionMismatch", func(t *testing.T) {
		// Quote contains PCR selection for indices {0} instead of {0, 4}.
		quoted, sig := createValidQuote(t, []int32{0}, pcrValues, nonce, chain.oiakKey, cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA384)

		resp := createAttestResponse(chain.oiakPEM, quoted, sig, pcrValues)
		err := VerifyRemoteAttestation(resp, expectedPCRs, requestedIndices, nonce, chain.rootPool, chain.interPool, cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA384)
		if err == nil || !strings.Contains(err.Error(), "PCR selection strictly mismatched against requested quote indices") {
			t.Errorf("expected error 'PCR selection strictly mismatched against requested quote indices', got: %v", err)
		}
	})
}

func TestVerifyRemoteAttestationPCRValuesErrors(t *testing.T) {
	chain := generateTestCertChain(t)
	requestedIndices := []int32{0, 4}
	pcrValues := map[int32][]byte{
		0: bytesRepeat(0x11, 48),
		4: bytesRepeat(0x22, 48),
	}
	expectedPCRs := map[int][]byte{
		0: bytesRepeat(0x11, 48),
		4: bytesRepeat(0x22, 48),
	}
	nonce := []byte("test-nonce-12345")
	quoted, sig := createValidQuote(t, requestedIndices, pcrValues, nonce, chain.oiakKey, cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA384)

	t.Run("MissingRequestedPCR", func(t *testing.T) {
		incompletePCRValues := map[int32][]byte{
			0: bytesRepeat(0x11, 48),
		}
		resp := createAttestResponse(chain.oiakPEM, quoted, sig, incompletePCRValues)
		err := VerifyRemoteAttestation(resp, expectedPCRs, requestedIndices, nonce, chain.rootPool, chain.interPool, cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA384)
		if err == nil || !strings.Contains(err.Error(), "device failed to map standard requested PCR index 4") {
			t.Errorf("expected error 'device failed to map standard requested PCR index 4', got: %v", err)
		}
	})

	t.Run("PCRCompositeDigestMismatch", func(t *testing.T) {
		tamperedPCRValues := map[int32][]byte{
			0: bytesRepeat(0x11, 48),
			4: bytesRepeat(0x99, 48), // tampered value
		}
		resp := createAttestResponse(chain.oiakPEM, quoted, sig, tamperedPCRValues)
		err := VerifyRemoteAttestation(resp, expectedPCRs, requestedIndices, nonce, chain.rootPool, chain.interPool, cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA384)
		if err == nil || !strings.Contains(err.Error(), "integrity violation: raw PCR values provided do not logically yield the quote's PCR digest") {
			t.Errorf("expected error 'integrity violation: raw PCR values provided do not logically yield the quote's PCR digest', got: %v", err)
		}
	})

	t.Run("MissingExpectedPCRPolicy", func(t *testing.T) {
		expPCRs := map[int][]byte{
			0: bytesRepeat(0x11, 48),
			4: bytesRepeat(0x22, 48),
			8: bytesRepeat(0x33, 48), // PCR 8 not in resp.PcrValues
		}
		resp := createAttestResponse(chain.oiakPEM, quoted, sig, pcrValues)
		err := VerifyRemoteAttestation(resp, expPCRs, requestedIndices, nonce, chain.rootPool, chain.interPool, cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA384)
		if err == nil || !strings.Contains(err.Error(), "policy failure: expected PCR 8 was totally absent from payload") {
			t.Errorf("expected error 'policy failure: expected PCR 8 was totally absent from payload', got: %v", err)
		}
	})

	t.Run("ExpectedPCRValueMismatchPolicy", func(t *testing.T) {
		expPCRs := map[int][]byte{
			0: bytesRepeat(0xFF, 48), // mismatch against reported 0x11
			4: bytesRepeat(0x22, 48),
		}
		resp := createAttestResponse(chain.oiakPEM, quoted, sig, pcrValues)
		err := VerifyRemoteAttestation(resp, expPCRs, requestedIndices, nonce, chain.rootPool, chain.interPool, cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA384)
		if err == nil || !strings.Contains(err.Error(), "policy failure: PCR 0 expected") {
			t.Errorf("expected error 'policy failure: PCR 0 expected ...', got: %v", err)
		}
	})
}

func TestVerifyRemoteAttestationHashAlgoErrors(t *testing.T) {
	chain := generateTestCertChain(t)
	requestedIndices := []int32{0}
	pcrValues := map[int32][]byte{0: bytesRepeat(0xAA, 48)}
	expectedPCRs := map[int][]byte{0: bytesRepeat(0xAA, 48)}
	nonce := []byte("test-nonce")
	quoted, sig := createValidQuote(t, requestedIndices, pcrValues, nonce, chain.oiakKey, cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA384)
	resp := createAttestResponse(chain.oiakPEM, quoted, sig, pcrValues)

	t.Run("UnsupportedAlgorithmUnspecified", func(t *testing.T) {
		err := VerifyRemoteAttestation(resp, expectedPCRs, requestedIndices, nonce, chain.rootPool, chain.interPool, cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_UNSPECIFIED)
		if err == nil || !strings.Contains(err.Error(), "unsupported hash algorithm") {
			t.Errorf("expected error 'unsupported hash algorithm', got: %v", err)
		}
	})

	t.Run("UnsupportedAlgorithmSHA512", func(t *testing.T) {
		err := VerifyRemoteAttestation(resp, expectedPCRs, requestedIndices, nonce, chain.rootPool, chain.interPool, cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA512)
		if err == nil || !strings.Contains(err.Error(), "unsupported hash algorithm") {
			t.Errorf("expected error 'unsupported hash algorithm', got: %v", err)
		}
	})

	t.Run("AlgorithmMismatch", func(t *testing.T) {
		// Quoted with SHA384 but verified with SHA256 should fail signature verification.
		err := VerifyRemoteAttestation(resp, expectedPCRs, requestedIndices, nonce, chain.rootPool, chain.interPool, cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA256)
		if err == nil || !strings.Contains(err.Error(), "quote signature verification failed") {
			t.Errorf("expected error 'quote signature verification failed', got: %v", err)
		}
	})
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
