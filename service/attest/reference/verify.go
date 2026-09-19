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
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"sort"

	"github.com/google/go-tpm/tpm2"
	apb "github.com/openconfig/attestz/proto/tpm_attestz"
)

// VerifyRemoteAttestation fully validates evidence. Requires standard root/intermediate CA pools.
func VerifyRemoteAttestation(resp *apb.AttestResponse, expectedPCRs map[int32][]byte, requestedIndices []int32, expectedNonce []byte, trustedRoots *x509.CertPool, intermediates *x509.CertPool) error {
	// 1. Parse and cryptographically verify the OIAK against the Root/Intermediate CA chain.
	var certs []*x509.Certificate
	for rest := []byte(resp.GetAttestationCert().GetOiakCert()); len(rest) > 0; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse OIAK certificate: %v", err)
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return errors.New("failed to decode OIAK PEM block")
	}
	cert := certs[0]

	interPool := intermediates
	if len(certs) > 1 {
		if interPool != nil {
			interPool = interPool.Clone()
		} else {
			interPool = x509.NewCertPool()
		}
		for _, c := range certs[1:] {
			interPool.AddCert(c)
		}
	}

	opts := x509.VerifyOptions{
		Roots:         trustedRoots,
		Intermediates: interPool,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	if _, err := cert.Verify(opts); err != nil {
		return fmt.Errorf("certificate chain of trust validation failed: %v", err)
	}

	// 2. Extract public key to verify Quote signature against the Quote.
	quoted := resp.GetQuoted()
	sha256QuoteHash := sha256.Sum256(quoted)
	sha384QuoteHash := sha512.Sum384(quoted)
	switch pubKey := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if err := verifyRSASignature(pubKey, crypto.SHA256, sha256QuoteHash[:], resp.GetQuoteSignature()); err != nil {
			if err := verifyRSASignature(pubKey, crypto.SHA384, sha384QuoteHash[:], resp.GetQuoteSignature()); err != nil {
				return fmt.Errorf("quote signature verification failed: %v", err)
			}
		}
	case *ecdsa.PublicKey:
		if err := verifyECDSASignature(pubKey, sha256QuoteHash[:], resp.GetQuoteSignature()); err != nil {
			if err := verifyECDSASignature(pubKey, sha384QuoteHash[:], resp.GetQuoteSignature()); err != nil {
				return fmt.Errorf("quote signature verification failed: %v", err)
			}
		}
	default:
		return errors.New("OIAK certificate does not contain an RSA or ECDSA public key")
	}

	// 3. Verify unencoded, raw binary data for the TPM2 PCR Quote (TPMS_ATTEST).
	var attest *tpm2.TPMSAttest
	if attest2B, err := tpm2.Unmarshal[tpm2.TPM2BAttest](resp.GetQuoted()); err == nil {
		if contents, err := attest2B.Contents(); err == nil {
			attest = contents
		}
	}
	if attest == nil {
		var err error
		attest, err = tpm2.Unmarshal[tpm2.TPMSAttest](resp.GetQuoted())
		if err != nil {
			return fmt.Errorf("bad Quote attestation: %v", err)
		}
	}

	// 4. Check that TPM2 magic number is TPM_GENERATED_VALUE.
	if attest.Magic != tpm2.TPMGeneratedValue {
		return fmt.Errorf("wrong magic value")
	}

	// 5. Check that Quote type is TPM_ST_ATTEST_QUOTE.
	if attest.Type != tpm2.TPMSTAttestQuote {
		return fmt.Errorf("wrong Quote attestation type 0x%x", attest.Type)
	}

	// 6. Check that nonce matches.
	if !bytes.Equal(attest.ExtraData.Buffer, expectedNonce) {
		return fmt.Errorf("wrong nonce %x, expected %x", attest.ExtraData.Buffer, expectedNonce)
	}

	quote, err := attest.Attested.Quote()
	if err != nil {
		return fmt.Errorf("attestation was not a Quote: %v", err)
	}

	// 7. Verify PCR Selections match by calculating bitmask from requested PCR indices.
	var sortedIndices []int32
	sortedIndices = append(sortedIndices, requestedIndices...)
	sort.Slice(sortedIndices, func(i, j int) bool { return sortedIndices[i] < sortedIndices[j] })

	pcrBitmask := make([]byte, 3)
	for _, idx := range sortedIndices {
		if idx >= 0 && idx <= 23 {
			pcrBitmask[idx/8] |= (1 << (idx % 8))
		}
	}

	expectedSHA256Select := tpm2.Marshal(tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				Hash:      tpm2.TPMAlgSHA256,
				PCRSelect: pcrBitmask,
			},
		},
	})
	expectedSHA384Select := tpm2.Marshal(tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				Hash:      tpm2.TPMAlgSHA384,
				PCRSelect: pcrBitmask,
			},
		},
	})
	quoteBytes := tpm2.Marshal(quote.PCRSelect)

	if !bytes.Equal(expectedSHA256Select, quoteBytes) && !bytes.Equal(expectedSHA384Select, quoteBytes) {
		return fmt.Errorf("PCR selection strictly mismatched against requested quote indices")
	}

	// 8. Verify the PCR composite digest matches recomputed concatenation of device PCRs.
	var pcrConcat []byte
	for _, idx := range sortedIndices {
		devicePcrBytes, ok := resp.GetPcrValues()[idx]
		if !ok {
			return fmt.Errorf("device failed to map standard requested PCR index %d", idx)
		}
		pcrConcat = append(pcrConcat, devicePcrBytes...)
	}

	sha256PcrDigest := sha256.Sum256(pcrConcat)
	sha384PcrDigest := sha512.Sum384(pcrConcat)
	if !bytes.Equal(quote.PCRDigest.Buffer, sha256PcrDigest[:]) && !bytes.Equal(quote.PCRDigest.Buffer, sha384PcrDigest[:]) {
		return fmt.Errorf("integrity violation: raw PCR values provided do not logically yield the quote's PCR digest")
	}

	// 9. Verify individual device PCRs match the individual reference PCRs.
	for expIdx, expVal := range expectedPCRs {
		reportedVal, ok := resp.GetPcrValues()[expIdx]
		if !ok {
			return fmt.Errorf("policy failure: expected PCR %d was totally absent from payload", expIdx)
		}
		if !bytes.Equal(reportedVal, expVal) {
			return fmt.Errorf("policy failure: PCR %d expected %x, got %x", expIdx, expVal, reportedVal)
		}
	}

	return nil
}

func verifyRSASignature(pubKey *rsa.PublicKey, cryptoHash crypto.Hash, hash, sig []byte) error {
	if tpmSig, err := tpm2.Unmarshal[tpm2.TPMTSignature](sig); err == nil {
		if rsaSig, err := tpmSig.Signature.RSASSA(); err == nil {
			if err := rsa.VerifyPKCS1v15(pubKey, cryptoHash, hash, rsaSig.Sig.Buffer); err == nil {
				return nil
			}
		}
	}
	if err := rsa.VerifyPKCS1v15(pubKey, cryptoHash, hash, sig); err == nil {
		return nil
	}
	return errors.New("RSA PKCS#1 v1.5 verification failed")
}

func verifyECDSASignature(pubKey *ecdsa.PublicKey, hash, sig []byte) error {
	// Try ASN.1 DER-encoded signature (standard in Go crypto, X.509, TLS).
	if ecdsa.VerifyASN1(pubKey, hash, sig) {
		return nil
	}

	// Try raw IEEE P1363 (r || s) format.
	curveOrderByteLen := (pubKey.Params().N.BitLen() + 7) / 8
	if len(sig) == 2*curveOrderByteLen {
		r := new(big.Int).SetBytes(sig[:curveOrderByteLen])
		s := new(big.Int).SetBytes(sig[curveOrderByteLen:])
		if ecdsa.Verify(pubKey, hash, r, s) {
			return nil
		}
	}

	// Try TPM2 TPMT_SIGNATURE format if provided.
	if tpmSig, err := tpm2.Unmarshal[tpm2.TPMTSignature](sig); err == nil {
		if eccSig, err := tpmSig.Signature.ECDSA(); err == nil {
			r := new(big.Int).SetBytes(eccSig.SignatureR.Buffer)
			s := new(big.Int).SetBytes(eccSig.SignatureS.Buffer)
			if ecdsa.Verify(pubKey, hash, r, s) {
				return nil
			}
		}
	}

	// Try TPM2 TPMSSignatureECC format if provided.
	if eccSig, err := tpm2.Unmarshal[tpm2.TPMSSignatureECC](sig); err == nil {
		r := new(big.Int).SetBytes(eccSig.SignatureR.Buffer)
		s := new(big.Int).SetBytes(eccSig.SignatureS.Buffer)
		if ecdsa.Verify(pubKey, hash, r, s) {
			return nil
		}
	}

	return errors.New("ECDSA verification failed")
}
