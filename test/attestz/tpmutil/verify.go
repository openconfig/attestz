package tpmutil

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"maps"
	"slices"
	"sort"

	"github.com/google/go-tpm/tpm2"
	"github.com/openconfig/attestz/service/biz"

	cpb "github.com/openconfig/attestz/proto/common_definitions"
)

// VerifyPCRQuoteAndQuoteSignature verifies the PCR quote and quote signature against the oIAK certificate.
func VerifyPCRQuoteAndQuoteSignature(ctx context.Context, tpmUtils TPMCertUtils, cert *x509.Certificate,
	quoted []byte, signature []byte, pcrs map[int32][]byte, nonce []byte, hashAlgo cpb.Tpm20HashAlgo) error {
	sig, err := tpm2.Unmarshal[tpm2.TPMTSignature](signature)
	if err != nil {
		return fmt.Errorf("failed to unmarshal signature: %w", err)
	}
	tpmtPubKey, err := tpmUtils.ToTPMTPublic(cert)
	if err != nil {
		return fmt.Errorf("failed to convert certificate public key to TPMT_PUBLIC: %w", err)
	}
	u := &biz.DefaultTPM20Utils{}
	if err := u.VerifyTPMTSignature(quoted, sig, tpmtPubKey); err != nil {
		return fmt.Errorf("failed to verify PCR quote signature: %w", err)
	}

	attest, err := tpm2.Unmarshal[tpm2.TPMSAttest](quoted)
	if err != nil {
		return fmt.Errorf("failed to unmarshal quoted data: %w", err)
	}
	if attest.Magic != tpm2.TPMGeneratedValue {
		return fmt.Errorf("wrong magic value")
	}
	if attest.Type != tpm2.TPMSTAttestQuote {
		return fmt.Errorf("wrong Quote attestation type")
	}
	if !bytes.Equal(attest.ExtraData.Buffer, nonce) {
		return fmt.Errorf("wrong nonce %x, expected %x", attest.ExtraData.Buffer, nonce)
	}
	quote, err := attest.Attested.Quote()
	if err != nil {
		return fmt.Errorf("attestation is not a Quote")
	}
	tpmHashAlg, err := hashAlgoToTPMAlg(hashAlgo)
	if err != nil {
		return fmt.Errorf("failed to convert hash algorithm to TPM algorithm: %w", err)
	}
	pcrSelect, err := pcrSelectList(slices.Collect(maps.Keys(pcrs)), tpmHashAlg)
	if err != nil {
		return fmt.Errorf("failed to build PCR select list: %w", err)
	}
	if !bytes.Equal(tpm2.Marshal(quote.PCRSelect), pcrSelect) {
		return fmt.Errorf("PCR selection in quote does not match expected selection")
	}
	cryptoHash, err := hashAlgoToCryptoHash(hashAlgo)
	if err != nil {
		return fmt.Errorf("failed to convert hash algorithm to crypto.Hash: %w", err)
	}
	pcrDigest, err := computePCRDigest(pcrs, cryptoHash)
	if err != nil {
		return fmt.Errorf("failed to compute PCR digest: %w", err)
	}
	if !bytes.Equal(quote.PCRDigest.Buffer, pcrDigest) {
		return fmt.Errorf("PCR digest in quote does not match expected digest")
	}
	return nil
}

// ValidatePCRs compares received PCR values against expected PCR values.
func ValidatePCRs(expected map[int32][]byte, received map[int32][]byte) error {
	var mismatches []int32
	for idx, expVal := range expected {
		recVal, ok := received[idx]
		if !ok || !bytes.Equal(recVal, expVal) {
			mismatches = append(mismatches, idx)
		}
	}
	if len(mismatches) > 0 {
		return fmt.Errorf("PCR mismatches in indices %v; expected: %v, received: %v", mismatches, expected, received)
	}
	return nil
}

func hashAlgoToCryptoHash(hashAlgo cpb.Tpm20HashAlgo) (crypto.Hash, error) {
	switch hashAlgo {
	case cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA256:
		return crypto.SHA256, nil
	case cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA384:
		return crypto.SHA384, nil
	case cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA512:
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("unsupported hash algorithm: %v", hashAlgo)
	}
}

func hashAlgoToTPMAlg(hashAlgo cpb.Tpm20HashAlgo) (tpm2.TPMIAlgHash, error) {
	switch hashAlgo {
	case cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA256:
		return tpm2.TPMAlgSHA256, nil
	case cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA384:
		return tpm2.TPMAlgSHA384, nil
	case cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA512:
		return tpm2.TPMAlgSHA512, nil
	default:
		return 0, fmt.Errorf("unsupported hash algorithm: %v", hashAlgo)
	}
}

func pcrSelectList(pcrs []int32, hash tpm2.TPMIAlgHash) ([]byte, error) {
	pcrSelect, err := makePCRSelect(pcrs)
	if err != nil {
		return nil, err
	}
	pcrSelectList := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				Hash:      hash,
				PCRSelect: pcrSelect,
			},
		},
	}
	return tpm2.Marshal(pcrSelectList), nil
}

func makePCRSelect(pcrs []int32) ([]byte, error) {
	pcrSelect := make([]byte, 3)
	for _, pcr := range pcrs {
		if pcr < 0 || 23 < pcr {
			return nil, fmt.Errorf("PCR %d is out of the valid range [0, 23]", pcr)
		}
		byteIndex := pcr / 8
		bitIndex := uint(pcr % 8)
		pcrSelect[byteIndex] |= (1 << bitIndex)
	}
	return pcrSelect, nil
}

func computePCRDigest(pcrs map[int32][]byte, h crypto.Hash) ([]byte, error) {
	var keys []int32
	for k := range pcrs {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })

	digest := h.New()
	for _, key := range keys {
		_, err := digest.Write(pcrs[key])
		if err != nil {
			return nil, fmt.Errorf("failed to compute PCR index %d digest: %w", key, err)
		}
	}
	return digest.Sum(nil), nil
}
