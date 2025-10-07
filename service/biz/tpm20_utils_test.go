package biz

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"math/big"

	// #nosec

	"testing"

	tpm20 "github.com/google/go-tpm/tpm2"
)

func TestGenerateRestrictedHMACKey(t *testing.T) {
	u := &DefaultTPM20Utils{}
	pub, priv := u.GenerateRestrictedHMACKey()
	hash, _ := pub.Unique.KeyedHash()
	got := hash.Buffer
	bits, _ := priv.Sensitive.Bits()
	sha := sha256.New()
	sha.Write(append(priv.SeedValue.Buffer, bits.Buffer...))
	want := sha.Sum(nil)
	if !bytes.Equal(got, want) {
		t.Fatalf("TestGenerateRestrictedHMACKey() failed: got %v, want %v", got, want)
	}
}

func TestCreateHMACChallenge(t *testing.T) {
	u := &DefaultTPM20Utils{}
	goodPub, goodPriv := u.GenerateRestrictedHMACKey()
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	goodEK := &rsaKey.PublicKey
	badEK := &rsa.PublicKey{
		N: big.NewInt(0),
		E: 0,
	}

	testCases := []struct {
		name    string
		pub     *tpm20.TPMTPublic
		priv    *tpm20.TPMTSensitive
		ek      *rsa.PublicKey
		wantErr bool
	}{
		{
			name: "Success",
			pub:  goodPub,
			priv: goodPriv,
			ek:   goodEK,
		},
		{
			name:    "Failure",
			pub:     goodPub,
			priv:    goodPriv,
			ek:      badEK,
			wantErr: true,
		},
		{
			name:    "Nil EK",
			pub:     goodPub,
			priv:    goodPriv,
			wantErr: true,
		},
		{
			name:    "Nil HMAC Pub",
			priv:    goodPriv,
			ek:      goodEK,
			wantErr: true,
		},
		{
			name:    "Nil HMAC Priv",
			pub:     goodPub,
			ek:      goodEK,
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := u.CreateHMACChallenge(tc.pub, tc.priv, tc.ek)
			if (err != nil) != tc.wantErr {
				t.Errorf("TestCreateHMACChallenge() failed, got error %v, want error %v", err, tc.wantErr)
			}
		})
	}
}
