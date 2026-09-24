package tpmutil

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"maps"
	"slices"
	"testing"

	"github.com/google/go-tpm/tpm2"

	cpb "github.com/openconfig/attestz/proto/common_definitions"
)

func TestMakePCRSelect(t *testing.T) {
	tests := []struct {
		name    string
		pcrs    []int32
		want    []byte
		wantErr bool
	}{
		{
			name:    "Single PCR in first byte",
			pcrs:    []int32{0},
			want:    []byte{0x01, 0x00, 0x00},
			wantErr: false,
		},
		{
			name:    "Multiple PCRs across bytes",
			pcrs:    []int32{0, 1, 2, 8, 23},
			want:    []byte{0x07, 0x01, 0x80},
			wantErr: false,
		},
		{
			name:    "Out of range low",
			pcrs:    []int32{-1},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "Out of range high",
			pcrs:    []int32{24},
			want:    nil,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := makePCRSelect(tc.pcrs)
			if (err != nil) != tc.wantErr {
				t.Fatalf("makePCRSelect() error = %v, wantErr %v", err, tc.wantErr)
			}
			if !tc.wantErr && !bytes.Equal(got, tc.want) {
				t.Errorf("makePCRSelect() = %x, want %x", got, tc.want)
			}
		})
	}
}

func TestPCRSelectList_ValidIndices_ReturnsMarshaledSelection(t *testing.T) {
	pcrs := []int32{0, 7, 8}
	got, err := pcrSelectList(pcrs, tpm2.TPMAlgSHA256)
	if err != nil {
		t.Fatalf("pcrSelectList() unexpected error: %v", err)
	}
	if len(got) == 0 {
		t.Error("pcrSelectList() returned empty byte slice")
	}

	unmarshaled, err := tpm2.Unmarshal[tpm2.TPMLPCRSelection](got)
	if err != nil {
		t.Fatalf("Failed to unmarshal result of pcrSelectList: %v", err)
	}
	if len(unmarshaled.PCRSelections) != 1 {
		t.Fatalf("PCRSelections len = %d, want 1", len(unmarshaled.PCRSelections))
	}
	if unmarshaled.PCRSelections[0].Hash != tpm2.TPMAlgSHA256 {
		t.Errorf("Hash = %v, want %v", unmarshaled.PCRSelections[0].Hash, tpm2.TPMAlgSHA256)
	}
}

func TestComputePCRDigest_DeterministicOrder(t *testing.T) {
	pcrs1 := map[int32][]byte{
		2: []byte("pcr_value_2"),
		0: []byte("pcr_value_0"),
		1: []byte("pcr_value_1"),
	}
	pcrs2 := map[int32][]byte{
		0: []byte("pcr_value_0"),
		1: []byte("pcr_value_1"),
		2: []byte("pcr_value_2"),
	}

	digest1, err := computePCRDigest(pcrs1, crypto.SHA256)
	if err != nil {
		t.Fatalf("computePCRDigest(pcrs1) unexpected error: %v", err)
	}
	digest2, err := computePCRDigest(pcrs2, crypto.SHA256)
	if err != nil {
		t.Fatalf("computePCRDigest(pcrs2) unexpected error: %v", err)
	}

	if !bytes.Equal(digest1, digest2) {
		t.Errorf("computePCRDigest() is not deterministic: %x != %x", digest1, digest2)
	}

	expectedHasher := sha256.New()
	if _, err := expectedHasher.Write([]byte("pcr_value_0")); err != nil {
		t.Fatalf("expectedHasher.Write(pcr_value_0) error: %v", err)
	}
	if _, err := expectedHasher.Write([]byte("pcr_value_1")); err != nil {
		t.Fatalf("expectedHasher.Write(pcr_value_1) error: %v", err)
	}
	if _, err := expectedHasher.Write([]byte("pcr_value_2")); err != nil {
		t.Fatalf("expectedHasher.Write(pcr_value_2) error: %v", err)
	}
	expectedDigest := expectedHasher.Sum(nil)

	if !bytes.Equal(digest1, expectedDigest) {
		t.Errorf("computePCRDigest() = %x, want %x", digest1, expectedDigest)
	}
}

// buildSimulatedQuoteAndSignature builds simulated TPM quote data and its RSA signature for
// testing VerifyPCRQuoteAndQuoteSignature.
func buildSimulatedQuoteAndSignature(t *testing.T, privKey *rsa.PrivateKey, pcrs map[int32][]byte, nonce []byte, hashAlgo cpb.Tpm20HashAlgo) ([]byte, []byte) {
	t.Helper()
	tpmAlg, err := hashAlgoToTPMAlg(hashAlgo)
	if err != nil {
		t.Fatalf("hashAlgoToTPMAlg() error: %v", err)
	}
	cryptoHash, err := hashAlgoToCryptoHash(hashAlgo)
	if err != nil {
		t.Fatalf("hashAlgoToCryptoHash() error: %v", err)
	}

	pcrSelectBytes, err := pcrSelectList(slices.Collect(maps.Keys(pcrs)), tpmAlg)
	if err != nil {
		t.Fatalf("pcrSelectList() error: %v", err)
	}
	pcrSelect, err := tpm2.Unmarshal[tpm2.TPMLPCRSelection](pcrSelectBytes)
	if err != nil {
		t.Fatalf("Unmarshal TPMLPCRSelection error: %v", err)
	}
	pcrDigest, err := computePCRDigest(pcrs, cryptoHash)
	if err != nil {
		t.Fatalf("computePCRDigest() error: %v", err)
	}

	attest := tpm2.TPMSAttest{
		Magic:           tpm2.TPMGeneratedValue,
		Type:            tpm2.TPMSTAttestQuote,
		QualifiedSigner: tpm2.TPM2BName{Buffer: []byte("dummy_signer")},
		ExtraData:       tpm2.TPM2BData{Buffer: nonce},
		Attested: tpm2.NewTPMUAttest(
			tpm2.TPMSTAttestQuote,
			&tpm2.TPMSQuoteInfo{
				PCRSelect: *pcrSelect,
				PCRDigest: tpm2.TPM2BDigest{Buffer: pcrDigest},
			},
		),
	}
	quoted := tpm2.Marshal(attest)

	hashed := sha256.Sum256(quoted)
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hashed[:])
	if err != nil {
		t.Fatalf("rsa.SignPKCS1v15 error: %v", err)
	}

	tpmSig := tpm2.TPMTSignature{
		SigAlg: tpm2.TPMAlgRSASSA,
		Signature: tpm2.NewTPMUSignature(
			tpm2.TPMAlgRSASSA,
			&tpm2.TPMSSignatureRSA{
				Hash: tpm2.TPMAlgSHA256,
				Sig:  tpm2.TPM2BPublicKeyRSA{Buffer: sigBytes},
			},
		),
	}
	signature := tpm2.Marshal(tpmSig)
	return quoted, signature
}

// NOTE: Implementers are recommended to add a TestVerifyPCRQuoteAndQuoteSignature_Success test case
// once a concrete TPMCertUtils implementation (specifically ToTPMTPublic) is provided.
func TestVerifyPCRQuoteAndQuoteSignature_Failure(t *testing.T) {
	ctx := t.Context()
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	cert := &x509.Certificate{
		PublicKey:          &privKey.PublicKey,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	pcrs := map[int32][]byte{0: []byte("pcr0")}
	nonce := []byte("nonce")
	hashAlgo := cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA256

	quoted, signature := buildSimulatedQuoteAndSignature(t, privKey, pcrs, nonce, hashAlgo)
	if len(signature) <= 10 {
		t.Fatalf("buildSimulatedQuoteAndSignature returned signature of length %d, want > 10", len(signature))
	}

	corruptedSig := slices.Clone(signature)
	// We corrupt byte index 10 (inside the raw RSA signature payload buffer) rather than
	// bytes 0-5 (which contain the TPMAlgRSASSA and TPM2B size headers). This ensures that
	// tpm2.Unmarshal succeeds cleanly, but cryptographic signature verification fails.
	corruptedSig[10] ^= 0xFF

	tests := []struct {
		name      string
		cert      *x509.Certificate
		quoted    []byte
		signature []byte
		pcrs      map[int32][]byte
		nonce     []byte
		hashAlgo  cpb.Tpm20HashAlgo
	}{
		{
			name:      "Wrong nonce",
			cert:      cert,
			quoted:    quoted,
			signature: signature,
			pcrs:      pcrs,
			nonce:     []byte("wrong_nonce"),
			hashAlgo:  hashAlgo,
		},
		{
			name:      "PCR digest mismatch",
			cert:      cert,
			quoted:    quoted,
			signature: signature,
			pcrs:      map[int32][]byte{0: []byte("pcr0_different_value")},
			nonce:     nonce,
			hashAlgo:  hashAlgo,
		},
		{
			name:      "Invalid signature",
			cert:      cert,
			quoted:    quoted,
			signature: corruptedSig,
			pcrs:      pcrs,
			nonce:     nonce,
			hashAlgo:  hashAlgo,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := VerifyPCRQuoteAndQuoteSignature(ctx, NewTPMCertUtils(), tc.cert, tc.quoted, tc.signature, tc.pcrs, tc.nonce, tc.hashAlgo); err == nil {
				t.Error("VerifyPCRQuoteAndQuoteSignature() expected error, got nil")
			}
		})
	}
}
