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

package biz

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestVerifyAndParseIakAndIDevIdCerts(t *testing.T) {
	/*
		TODO(jenia-grunin):
		* Generate certs/keys on the fly.
		* Tests to add:
			- Unsupported algo such as DSA.
			- Bad pub key length for RSA.
			- Bad pub key length for ECC.
			- IAK and IDevID cert serials don't match.
			- Bad cert pem header.
			- Good pem cert header, but bad x509 structure.
			- Repeat above for both IAK and IDevID certs.
	*/
	iakCertPemRsa2048 := `-----BEGIN CERTIFICATE-----
MIIDFzCCAf+gAwIBAgIUfUNGVC/ZruAQ/cq3fLBEyQUKRgIwDQYJKoZIhvcNAQEL
BQAwGzEZMBcGA1UEBRMQUzBNM1MzUjFBTE5VTUIzUjAeFw0yNDAyMTMyMTE3MTRa
Fw0yNTAyMTIyMTE3MTRaMBsxGTAXBgNVBAUTEFMwTTNTM1IxQUxOVU1CM1IwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7nNplof1PdnR64cEt3kPvuelS
Lf7SinAwFfCCekFCH/G8QFzlynf80RRCgp2Lqku8x6pPTQ9R62X7WXric26L47tt
WHnBLsb4nutnmtrz+hsVdoKw8SQRxm0ptR7LIBxyy9mcqwGKN6ROB1S/wr9gJFBD
fW/3rVpV3vOyP7crVq7l05S0fYmc7f2r1ikrNnl9jngQiSoAmMGBb8sKNDJ6ogNb
IbS/t7RqdzklCEPcbhXmIHkssWHO4MmWptzZTr6yCDGfXXDoB+OrfyvszwYeY6z2
/++H2QuM22U86khEkyRy2hvTJRdEnfBW1nrMH6x9eyXDwDJRl5yFH0rf+I3DAgMB
AAGjUzBRMB0GA1UdDgQWBBSO+5dAexztMj1Q2Sqdvjhhr0rpeTAfBgNVHSMEGDAW
gBSO+5dAexztMj1Q2Sqdvjhhr0rpeTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3
DQEBCwUAA4IBAQCB6bzFeszPzNHD2X1UxIXvvvdXHu1rkUybvb3jpa1nW3jNgoG1
+DgRcNew1dX+k2QYhDJkz+zvnZRlaclv+pAqgeN4tdrjBw3UHCkIzSJl+fMh38+S
UkBGC4PnnFhxZsk1gf4NmPqvv8pjwqgy/IGS/CIuQOQnYRUnXrbhBqAQYrwuluxe
bundQKLNTN1ZEtfGZS51Ebcq9zipiBFNzOx5KlmWE7WqzM7y+tq+Avqj47dgtF4Y
WDhEbBEryEh8y2nreLi4UPdiZ3NCdwjnQvri/GQLW6NXGu1Ofgd2OEGxaS9L9ziz
Rn5w8rtwirOLSVfWoK2LUxqR41Eo8xyGQUtA
-----END CERTIFICATE-----
`

	iDevIdCertPemEcc384 := `-----BEGIN CERTIFICATE-----
MIIByDCCAU6gAwIBAgIUNjjwIU22SPnoTQSEf1XJZvIorBkwCgYIKoZIzj0EAwIw
GzEZMBcGA1UEBRMQUzBNM1MzUjFBTE5VTUIzUjAeFw0yNDAyMTMyMTEzNDlaFw0y
NTAyMDcyMTEzNDlaMBsxGTAXBgNVBAUTEFMwTTNTM1IxQUxOVU1CM1IwdjAQBgcq
hkjOPQIBBgUrgQQAIgNiAARYOauAEC4OpH+4H/0RiLDRqIsqDC/YL7NEPZ1bWSM2
MoV5nQePwDpbSKIQA0LvmFtNWyi+KBd/8ZAZkocu1jB+z5uxLtzwCgHo0OGWSo/3
R9dNlSmFL/R8oO13VJJkF+2jUzBRMB0GA1UdDgQWBBRu1oJXErO4dLAOgcHAwIQC
BgrT0TAfBgNVHSMEGDAWgBRu1oJXErO4dLAOgcHAwIQCBgrT0TAPBgNVHRMBAf8E
BTADAQH/MAoGCCqGSM49BAMCA2gAMGUCMQDMY+Bj5VdGibkv7rCc0fa8h1DaIarX
1s4zOn4SPNTL3fPDRibWFsyDGshWilUZJs8CMBabnxNdDp7muR1f6+wsQ8iQRC2F
Vd4VhhdrXWRI82nVHofgP0EhHHHE70fKMVIxBA==
-----END CERTIFICATE-----
`

	wantIakPubPem := `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu5zaZaH9T3Z0euHBLd5D
77npUi3+0opwMBXwgnpBQh/xvEBc5cp3/NEUQoKdi6pLvMeqT00PUetl+1l64nNu
i+O7bVh5wS7G+J7rZ5ra8/obFXaCsPEkEcZtKbUeyyAccsvZnKsBijekTgdUv8K/
YCRQQ31v961aVd7zsj+3K1au5dOUtH2JnO39q9YpKzZ5fY54EIkqAJjBgW/LCjQy
eqIDWyG0v7e0anc5JQhD3G4V5iB5LLFhzuDJlqbc2U6+sggxn11w6Afjq38r7M8G
HmOs9v/vh9kLjNtlPOpIRJMkctob0yUXRJ3wVtZ6zB+sfXslw8AyUZechR9K3/iN
wwIDAQAB
-----END PUBLIC KEY-----
`

	wantIDevIdPubPem := `-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEWDmrgBAuDqR/uB/9EYiw0aiLKgwv2C+z
RD2dW1kjNjKFeZ0Hj8A6W0iiEANC75hbTVsovigXf/GQGZKHLtYwfs+bsS7c8AoB
6NDhlkqP90fXTZUphS/0fKDtd1SSZBft
-----END PUBLIC KEY-----
`

	req := &TpmCertVerifierReq{
		iakCertPem:    iakCertPemRsa2048,
		iDevIdCertPem: iDevIdCertPemEcc384,
	}
	resp, err := VerifyAndParseIakAndIDevIdCerts(req)

	if err != nil {
		t.Errorf("Unexpected error response %v", err)
	}

	if diff := cmp.Diff(resp.iakPubPem, wantIakPubPem); diff != "" {
		t.Errorf("IAK pub PEM does not match expectations: diff = %v", diff)
	}
	if diff := cmp.Diff(resp.iDevIdPubPem, wantIDevIdPubPem); diff != "" {
		t.Errorf("IDevID pub PEM does not match expectations: diff = %v", diff)
	}
}
