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
	"context"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	tpm12 "github.com/google/go-tpm/tpm"
	tpm20 "github.com/google/go-tpm/tpm2"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/testing/protocmp"

	cpb "github.com/openconfig/attestz/proto/common_definitions"
	epb "github.com/openconfig/attestz/proto/tpm_enrollz"
)

type stubEnrollzInfraDeps struct {
	SwitchOwnerCaClient
	EnrollzDeviceClient
	TpmCertVerifier

	// Request params captured in function calls.
	issueOwnerIakCertReqs       []*IssueOwnerIakCertReq
	issueOwnerIDevIDCertReqs    []*IssueOwnerIDevIDCertReq
	getIakCertReqs              []*epb.GetIakCertRequest
	rotateOIakCertReqs          []*epb.RotateOIakCertRequest
	verifyIakAndIDevIDCertsReqs []*VerifyIakAndIDevIDCertsReq
	verifyTpmCertReqs           []*VerifyTpmCertReq
	verifyNonceSignatureReqs    []*VerifyNonceSignatureReq

	// Stubbed responses.
	issueOwnerIakCertResps       []*IssueOwnerIakCertResp
	issueOwnerIDevIDCertResps    []*IssueOwnerIDevIDCertResp
	getIakCertResps              []*epb.GetIakCertResponse
	rotateOIakCertResps          []*epb.RotateOIakCertResponse
	verifyIakAndIDevIDCertsResps []*VerifyIakAndIDevIDCertsResp
	verifyTpmCertResps           []*VerifyTpmCertResp
	verifyNonceSignatureResps    []*VerifyNonceSignatureResp

	// Stubbed errors (optional, per call index).
	issueOwnerIakCertErrs       []error
	issueOwnerIDevIDCertErrs    []error
	rotateOIakCertErrs          []error
	getIakCertErrs              []error
	verifyIakAndIDevIDCertsErrs []error
	verifyTpmCertErrs           []error
	verifyNonceSignatureErrs    []error

	// Error response to return when no specific response is available.
	errorResp error
}

func (s *stubEnrollzInfraDeps) VerifyIakAndIDevIDCerts(ctx context.Context, req *VerifyIakAndIDevIDCertsReq) (*VerifyIakAndIDevIDCertsResp, error) {
	s.verifyIakAndIDevIDCertsReqs = append(s.verifyIakAndIDevIDCertsReqs, req)
	idx := len(s.verifyIakAndIDevIDCertsReqs) - 1
	if idx < len(s.verifyIakAndIDevIDCertsErrs) && s.verifyIakAndIDevIDCertsErrs[idx] != nil {
		return nil, s.verifyIakAndIDevIDCertsErrs[idx]
	}
	if idx < len(s.verifyIakAndIDevIDCertsResps) {
		return s.verifyIakAndIDevIDCertsResps[idx], nil
	}
	return nil, s.errorResp
}

func (s *stubEnrollzInfraDeps) VerifyTpmCert(ctx context.Context, req *VerifyTpmCertReq) (*VerifyTpmCertResp, error) {
	s.verifyTpmCertReqs = append(s.verifyTpmCertReqs, req)
	idx := len(s.verifyTpmCertReqs) - 1
	if idx < len(s.verifyTpmCertErrs) && s.verifyTpmCertErrs[idx] != nil {
		return nil, s.verifyTpmCertErrs[idx]
	}
	if idx < len(s.verifyTpmCertResps) {
		return s.verifyTpmCertResps[idx], nil
	}
	return nil, s.errorResp
}

func (s *stubEnrollzInfraDeps) IssueOwnerIakCert(ctx context.Context, req *IssueOwnerIakCertReq) (*IssueOwnerIakCertResp, error) {
	s.issueOwnerIakCertReqs = append(s.issueOwnerIakCertReqs, req)
	idx := len(s.issueOwnerIakCertReqs) - 1

	if idx < len(s.issueOwnerIakCertErrs) && s.issueOwnerIakCertErrs[idx] != nil {
		return nil, s.issueOwnerIakCertErrs[idx]
	}
	if idx < len(s.issueOwnerIakCertResps) {
		return s.issueOwnerIakCertResps[idx], nil
	}
	return nil, s.errorResp
}

func (s *stubEnrollzInfraDeps) IssueOwnerIDevIDCert(ctx context.Context, req *IssueOwnerIDevIDCertReq) (*IssueOwnerIDevIDCertResp, error) {
	s.issueOwnerIDevIDCertReqs = append(s.issueOwnerIDevIDCertReqs, req)
	idx := len(s.issueOwnerIDevIDCertReqs) - 1
	if idx < len(s.issueOwnerIDevIDCertErrs) && s.issueOwnerIDevIDCertErrs[idx] != nil {
		return nil, s.issueOwnerIDevIDCertErrs[idx]
	}
	if idx < len(s.issueOwnerIDevIDCertResps) {
		return s.issueOwnerIDevIDCertResps[idx], nil
	}
	return nil, s.errorResp
}

func (s *stubEnrollzInfraDeps) GetIakCert(ctx context.Context, req *epb.GetIakCertRequest) (*epb.GetIakCertResponse, error) {
	s.getIakCertReqs = append(s.getIakCertReqs, req)
	idx := len(s.getIakCertReqs) - 1
	if idx < len(s.getIakCertErrs) && s.getIakCertErrs[idx] != nil {
		return nil, s.getIakCertErrs[idx]
	}
	if idx < len(s.getIakCertResps) {
		return s.getIakCertResps[idx], nil
	}
	return nil, s.errorResp
}

func (s *stubEnrollzInfraDeps) RotateOIakCert(ctx context.Context, req *epb.RotateOIakCertRequest) (*epb.RotateOIakCertResponse, error) {
	s.rotateOIakCertReqs = append(s.rotateOIakCertReqs, req)
	idx := len(s.rotateOIakCertReqs) - 1
	if idx < len(s.rotateOIakCertErrs) && s.rotateOIakCertErrs[idx] != nil {
		return nil, s.rotateOIakCertErrs[idx]
	}
	if idx < len(s.rotateOIakCertResps) {
		return s.rotateOIakCertResps[idx], nil
	}
	return nil, s.errorResp
}

func (s *stubEnrollzInfraDeps) VerifyNonceSignature(ctx context.Context, req *VerifyNonceSignatureReq) (*VerifyNonceSignatureResp, error) {
	s.verifyNonceSignatureReqs = append(s.verifyNonceSignatureReqs, req)
	idx := len(s.verifyNonceSignatureReqs) - 1
	if idx < len(s.verifyNonceSignatureErrs) && s.verifyNonceSignatureErrs[idx] != nil {
		return nil, s.verifyNonceSignatureErrs[idx]
	}
	if idx >= len(s.verifyNonceSignatureResps) {
		return nil, s.errorResp
	}
	resp := s.verifyNonceSignatureResps[idx]
	if !resp.IsValid {
		return resp, s.errorResp
	}
	return resp, nil
}

func TestEnrollControlCard(t *testing.T) {
	// Constants to be used in request params and stubbing.
	controlCardSelection1 := &cpb.ControlCardSelection{
		ControlCardId: &cpb.ControlCardSelection_Role{
			Role: cpb.ControlCardRole_CONTROL_CARD_ROLE_ACTIVE,
		},
	}
	controlCardSelection2 := &cpb.ControlCardSelection{
		ControlCardId: &cpb.ControlCardSelection_Role{
			Role: cpb.ControlCardRole_CONTROL_CARD_ROLE_STANDBY,
		},
	}
	controlCardSelection3 := &cpb.ControlCardSelection{
		ControlCardId: &cpb.ControlCardSelection_Role{
			Role: cpb.ControlCardRole_CONTROL_CARD_ROLE_STANDBY,
		},
	}
	certVerificationOpts := x509.VerifyOptions{
		DNSName: "Some DNS name",
	}
	vendorID1 := &cpb.ControlCardVendorId{
		ControlCardRole:     controlCardSelection1.GetRole(),
		ControlCardSerial:   "Some card serial 1",
		ControlCardSlot:     "Some card slot 1",
		ChassisManufacturer: "Some manufacturer",
		ChassisPartNumber:   "Some part",
		ChassisSerialNumber: "Some chassis serial",
	}
	vendorID2 := &cpb.ControlCardVendorId{
		ControlCardRole:     controlCardSelection2.GetRole(),
		ControlCardSerial:   "Some card serial 2",
		ControlCardSlot:     "Some card slot 2",
		ChassisManufacturer: "Some manufacturer",
		ChassisPartNumber:   "Some part",
		ChassisSerialNumber: "Some chassis serial",
	}
	sslProfileID := "Some SSL profile ID"
	iakCert1 := "Some IAK cert PEM 1"
	iakPub1 := "Some IAK pub PEM 1"
	iDevIDCert1 := "Some IDevID cert PEM 1"
	iDevIDPub1 := "Some IDevID pub PEM 1"
	oIakCert1 := "Some Owner IAK cert PEM 1"
	oIdevIDCert1 := "Some Owner IDevID cert PEM 1"

	iakCert2 := "Some IAK cert PEM 2"
	iakPub2 := "Some IAK pub PEM 2"
	iDevIDCert2 := "Some IDevID cert PEM 2"
	iDevIDPub2 := "Some IDevID pub PEM 2"
	oIakCert2 := "Some Owner IAK cert PEM 2"
	oIdevIDCert2 := "Some Owner IDevID cert PEM 2"

	tests := []struct {
		// Test description.
		desc string
		// Overall expected EnrollControlCard response.
		wantErrResp           error
		controlCardSelections []*cpb.ControlCardSelection
		// Expected captured params to stubbed deps functions calls.
		wantGetIakCertReqs              []*epb.GetIakCertRequest
		wantIssueOwnerIakCertReqs       []*IssueOwnerIakCertReq
		wantIssueOwnerIDevIDCertReqs    []*IssueOwnerIDevIDCertReq
		wantRotateOIakCertReqs          []*epb.RotateOIakCertRequest
		wantVerifyIakAndIDevIDCertsReqs []*VerifyIakAndIDevIDCertsReq
		// Stubbed responses to EnrollzInfraDeps deps.
		issueOwnerIakCertResps       []*IssueOwnerIakCertResp
		issueOwnerIDevIDCertResps    []*IssueOwnerIDevIDCertResp
		getIakCertResps              []*epb.GetIakCertResponse
		rotateOIakCertResps          []*epb.RotateOIakCertResponse
		verifyIakAndIDevIDCertsResps []*VerifyIakAndIDevIDCertsResp
	}{
		{
			desc:                  "Successful control card enrollment (single)",
			controlCardSelections: []*cpb.ControlCardSelection{controlCardSelection1},
			getIakCertResps: []*epb.GetIakCertResponse{{
				ControlCardId:               vendorID1,
				IakCert:                     iakCert1,
				IdevidCert:                  iDevIDCert1,
				AtomicCertRotationSupported: true,
			}},
			verifyIakAndIDevIDCertsResps: []*VerifyIakAndIDevIDCertsResp{{
				IakPubPem:    iakPub1,
				IDevIDPubPem: iDevIDPub1,
			}},
			issueOwnerIakCertResps:    []*IssueOwnerIakCertResp{{OwnerIakCertPem: oIakCert1}},
			issueOwnerIDevIDCertResps: []*IssueOwnerIDevIDCertResp{{OwnerIDevIDCertPem: oIdevIDCert1}},
			rotateOIakCertResps:       []*epb.RotateOIakCertResponse{{}},

			wantGetIakCertReqs: []*epb.GetIakCertRequest{{ControlCardSelection: controlCardSelection1}},
			wantVerifyIakAndIDevIDCertsReqs: []*VerifyIakAndIDevIDCertsReq{{
				ControlCardID:        vendorID1,
				IakCertPem:           iakCert1,
				IDevIDCertPem:        iDevIDCert1,
				CertVerificationOpts: certVerificationOpts,
			}},
			wantIssueOwnerIakCertReqs: []*IssueOwnerIakCertReq{{
				CardID:    vendorID1,
				IakPubPem: iakPub1,
			}},
			wantIssueOwnerIDevIDCertReqs: []*IssueOwnerIDevIDCertReq{{
				CardID:       vendorID1,
				IDevIDPubPem: iDevIDPub1,
			}},
			wantRotateOIakCertReqs: []*epb.RotateOIakCertRequest{{
				SslProfileId: sslProfileID,
				Updates: []*epb.ControlCardCertUpdate{{
					ControlCardSelection: controlCardSelection1,
					OiakCert:             oIakCert1,
					OidevidCert:          oIdevIDCert1,
				}},
			}},
		},
		{
			desc:                  "Successful control card enrollment (multiple)",
			controlCardSelections: []*cpb.ControlCardSelection{controlCardSelection1, controlCardSelection2},
			getIakCertResps: []*epb.GetIakCertResponse{
				{
					ControlCardId:               vendorID1,
					IakCert:                     iakCert1,
					IdevidCert:                  iDevIDCert1,
					AtomicCertRotationSupported: true,
				},
				{
					ControlCardId:               vendorID2,
					IakCert:                     iakCert2,
					IdevidCert:                  iDevIDCert2,
					AtomicCertRotationSupported: true,
				},
			},
			verifyIakAndIDevIDCertsResps: []*VerifyIakAndIDevIDCertsResp{
				{
					IakPubPem:    iakPub1,
					IDevIDPubPem: iDevIDPub1,
				},
				{
					IakPubPem:    iakPub2,
					IDevIDPubPem: iDevIDPub2,
				},
			},
			issueOwnerIakCertResps:    []*IssueOwnerIakCertResp{{OwnerIakCertPem: oIakCert1}, {OwnerIakCertPem: oIakCert2}},
			issueOwnerIDevIDCertResps: []*IssueOwnerIDevIDCertResp{{OwnerIDevIDCertPem: oIdevIDCert1}, {OwnerIDevIDCertPem: oIdevIDCert2}},
			rotateOIakCertResps:       []*epb.RotateOIakCertResponse{{}},

			wantGetIakCertReqs: []*epb.GetIakCertRequest{
				{ControlCardSelection: controlCardSelection1},
				{ControlCardSelection: controlCardSelection2},
			},
			wantVerifyIakAndIDevIDCertsReqs: []*VerifyIakAndIDevIDCertsReq{
				{
					ControlCardID:        vendorID1,
					IakCertPem:           iakCert1,
					IDevIDCertPem:        iDevIDCert1,
					CertVerificationOpts: certVerificationOpts,
				},
				{
					ControlCardID:        vendorID2,
					IakCertPem:           iakCert2,
					IDevIDCertPem:        iDevIDCert2,
					CertVerificationOpts: certVerificationOpts,
				},
			},
			wantIssueOwnerIakCertReqs: []*IssueOwnerIakCertReq{
				{CardID: vendorID1, IakPubPem: iakPub1},
				{CardID: vendorID2, IakPubPem: iakPub2},
			},
			wantIssueOwnerIDevIDCertReqs: []*IssueOwnerIDevIDCertReq{
				{CardID: vendorID1, IDevIDPubPem: iDevIDPub1},
				{CardID: vendorID2, IDevIDPubPem: iDevIDPub2},
			},
			wantRotateOIakCertReqs: []*epb.RotateOIakCertRequest{{
				SslProfileId: sslProfileID,
				Updates: []*epb.ControlCardCertUpdate{
					{
						ControlCardSelection: controlCardSelection1,
						OiakCert:             oIakCert1,
						OidevidCert:          oIdevIDCert1,
					},
					{
						ControlCardSelection: controlCardSelection2,
						OiakCert:             oIakCert2,
						OidevidCert:          oIdevIDCert2,
					},
				},
			}},
		},
		{
			desc:                  "EnrollControlCard failure (too few cards)",
			controlCardSelections: []*cpb.ControlCardSelection{},
			wantErrResp:           ErrInvalidRequest,
		},
		{
			desc:                  "EnrollControlCard failure (too many cards)",
			controlCardSelections: []*cpb.ControlCardSelection{controlCardSelection1, controlCardSelection2, controlCardSelection3},
			wantErrResp:           ErrInvalidRequest,
		},
		{
			desc:                  "EnrollzDeviceClient.GetIakCert() failure causes overall EnrollControlCard failure",
			wantErrResp:           ErrVerifyIdentity,
			controlCardSelections: []*cpb.ControlCardSelection{controlCardSelection1},
			wantGetIakCertReqs:    []*epb.GetIakCertRequest{{ControlCardSelection: controlCardSelection1}},
		},
		{
			desc:                  "TpmCertVerifier.VerifyIakAndIDevIDCerts() failure causes overall EnrollControlCard failure",
			wantErrResp:           ErrVerifyIdentity,
			controlCardSelections: []*cpb.ControlCardSelection{controlCardSelection1},
			getIakCertResps: []*epb.GetIakCertResponse{{
				ControlCardId: vendorID1,
				IakCert:       iakCert1,
				IdevidCert:    iDevIDCert1,
			}},
			wantGetIakCertReqs: []*epb.GetIakCertRequest{{ControlCardSelection: controlCardSelection1}},
			wantVerifyIakAndIDevIDCertsReqs: []*VerifyIakAndIDevIDCertsReq{{
				ControlCardID:        vendorID1,
				IakCertPem:           iakCert1,
				IDevIDCertPem:        iDevIDCert1,
				CertVerificationOpts: certVerificationOpts,
			}},
		},
		{
			desc:                  "SwitchOwnerCaClient.IssueOwnerIakCert() failure causes overall EnrollControlCard failure",
			wantErrResp:           ErrIssueAndRotateOwnerCerts,
			controlCardSelections: []*cpb.ControlCardSelection{controlCardSelection1},
			getIakCertResps: []*epb.GetIakCertResponse{{
				ControlCardId:               vendorID1,
				IakCert:                     iakCert1,
				IdevidCert:                  iDevIDCert1,
				AtomicCertRotationSupported: true,
			}},
			verifyIakAndIDevIDCertsResps: []*VerifyIakAndIDevIDCertsResp{{
				IakPubPem:    iakPub1,
				IDevIDPubPem: iDevIDPub1,
			}},
			issueOwnerIDevIDCertResps: []*IssueOwnerIDevIDCertResp{{OwnerIDevIDCertPem: oIdevIDCert1}},
			wantGetIakCertReqs:        []*epb.GetIakCertRequest{{ControlCardSelection: controlCardSelection1}},
			wantVerifyIakAndIDevIDCertsReqs: []*VerifyIakAndIDevIDCertsReq{{
				ControlCardID:        vendorID1,
				IakCertPem:           iakCert1,
				IDevIDCertPem:        iDevIDCert1,
				CertVerificationOpts: certVerificationOpts,
			}},
			wantIssueOwnerIakCertReqs: []*IssueOwnerIakCertReq{{
				CardID:    vendorID1,
				IakPubPem: iakPub1,
			}},
			wantIssueOwnerIDevIDCertReqs: []*IssueOwnerIDevIDCertReq{{
				CardID:       vendorID1,
				IDevIDPubPem: iDevIDPub1,
			}},
		},
		{
			desc:                  "SwitchOwnerCaClient.IssueOwnerIDevIDCert() failure causes overall EnrollControlCard failure",
			wantErrResp:           ErrIssueAndRotateOwnerCerts,
			controlCardSelections: []*cpb.ControlCardSelection{controlCardSelection1},
			getIakCertResps: []*epb.GetIakCertResponse{{
				ControlCardId:               vendorID1,
				IakCert:                     iakCert1,
				IdevidCert:                  iDevIDCert1,
				AtomicCertRotationSupported: true,
			}},
			verifyIakAndIDevIDCertsResps: []*VerifyIakAndIDevIDCertsResp{{
				IakPubPem:    iakPub1,
				IDevIDPubPem: iDevIDPub1,
			}},
			wantGetIakCertReqs: []*epb.GetIakCertRequest{{ControlCardSelection: controlCardSelection1}},
			wantVerifyIakAndIDevIDCertsReqs: []*VerifyIakAndIDevIDCertsReq{{
				ControlCardID:        vendorID1,
				IakCertPem:           iakCert1,
				IDevIDCertPem:        iDevIDCert1,
				CertVerificationOpts: certVerificationOpts,
			}},
			wantIssueOwnerIDevIDCertReqs: []*IssueOwnerIDevIDCertReq{{
				CardID:       vendorID1,
				IDevIDPubPem: iDevIDPub1,
			}},
		},
		{
			desc:                  "EnrollzDeviceClient.RotateOIakCert() failure causes overall EnrollControlCard failure",
			wantErrResp:           ErrIssueAndRotateOwnerCerts,
			controlCardSelections: []*cpb.ControlCardSelection{controlCardSelection1},
			getIakCertResps: []*epb.GetIakCertResponse{{
				ControlCardId:               vendorID1,
				IakCert:                     iakCert1,
				IdevidCert:                  iDevIDCert1,
				AtomicCertRotationSupported: true,
			}},
			verifyIakAndIDevIDCertsResps: []*VerifyIakAndIDevIDCertsResp{{
				IakPubPem:    iakPub1,
				IDevIDPubPem: iDevIDPub1,
			}},
			issueOwnerIakCertResps:    []*IssueOwnerIakCertResp{{OwnerIakCertPem: oIakCert1}},
			issueOwnerIDevIDCertResps: []*IssueOwnerIDevIDCertResp{{OwnerIDevIDCertPem: oIdevIDCert1}},
			wantGetIakCertReqs:        []*epb.GetIakCertRequest{{ControlCardSelection: controlCardSelection1}},
			wantVerifyIakAndIDevIDCertsReqs: []*VerifyIakAndIDevIDCertsReq{{
				ControlCardID:        vendorID1,
				IakCertPem:           iakCert1,
				IDevIDCertPem:        iDevIDCert1,
				CertVerificationOpts: certVerificationOpts,
			}},
			wantIssueOwnerIakCertReqs: []*IssueOwnerIakCertReq{{
				CardID:    vendorID1,
				IakPubPem: iakPub1,
			}},
			wantIssueOwnerIDevIDCertReqs: []*IssueOwnerIDevIDCertReq{{
				CardID:       vendorID1,
				IDevIDPubPem: iDevIDPub1,
			}},
			wantRotateOIakCertReqs: []*epb.RotateOIakCertRequest{{
				SslProfileId: sslProfileID,
				Updates: []*epb.ControlCardCertUpdate{{
					ControlCardSelection: controlCardSelection1,
					OiakCert:             oIakCert1,
					OidevidCert:          oIdevIDCert1,
				}},
			}},
		},
		{
			desc:                  "EnrollzDeviceClient.GetIakCert() failure on second card (multiple)",
			controlCardSelections: []*cpb.ControlCardSelection{controlCardSelection1, controlCardSelection2},
			wantErrResp:           ErrVerifyIdentity,
			getIakCertResps: []*epb.GetIakCertResponse{
				{
					ControlCardId:               vendorID1,
					IakCert:                     iakCert1,
					IdevidCert:                  iDevIDCert1,
					AtomicCertRotationSupported: true,
				},
			},
			verifyIakAndIDevIDCertsResps: []*VerifyIakAndIDevIDCertsResp{
				{
					IakPubPem:    iakPub1,
					IDevIDPubPem: iDevIDPub1,
				},
			},
			wantGetIakCertReqs: []*epb.GetIakCertRequest{
				{ControlCardSelection: controlCardSelection1},
				{ControlCardSelection: controlCardSelection2},
			},
			wantVerifyIakAndIDevIDCertsReqs: []*VerifyIakAndIDevIDCertsReq{
				{
					ControlCardID:        vendorID1,
					IakCertPem:           iakCert1,
					IDevIDCertPem:        iDevIDCert1,
					CertVerificationOpts: certVerificationOpts,
				},
			},
		},
		{
			desc:                  "TpmCertVerifier.VerifyIakAndIDevIDCerts() failure on second card (multiple)",
			controlCardSelections: []*cpb.ControlCardSelection{controlCardSelection1, controlCardSelection2},
			wantErrResp:           ErrVerifyIdentity,
			getIakCertResps: []*epb.GetIakCertResponse{
				{
					ControlCardId:               vendorID1,
					IakCert:                     iakCert1,
					IdevidCert:                  iDevIDCert1,
					AtomicCertRotationSupported: true,
				},
				{
					ControlCardId:               vendorID2,
					IakCert:                     iakCert2,
					IdevidCert:                  iDevIDCert2,
					AtomicCertRotationSupported: true,
				},
			},
			verifyIakAndIDevIDCertsResps: []*VerifyIakAndIDevIDCertsResp{
				{
					IakPubPem:    iakPub1,
					IDevIDPubPem: iDevIDPub1,
				},
			},
			wantGetIakCertReqs: []*epb.GetIakCertRequest{
				{ControlCardSelection: controlCardSelection1},
				{ControlCardSelection: controlCardSelection2},
			},
			wantVerifyIakAndIDevIDCertsReqs: []*VerifyIakAndIDevIDCertsReq{
				{
					ControlCardID:        vendorID1,
					IakCertPem:           iakCert1,
					IDevIDCertPem:        iDevIDCert1,
					CertVerificationOpts: certVerificationOpts,
				},
				{
					ControlCardID:        vendorID2,
					IakCertPem:           iakCert2,
					IDevIDCertPem:        iDevIDCert2,
					CertVerificationOpts: certVerificationOpts,
				},
			},
		},
		{
			desc:                  "SwitchOwnerCaClient.IssueOwnerIakCert() failure on second card (multiple)",
			controlCardSelections: []*cpb.ControlCardSelection{controlCardSelection1, controlCardSelection2},
			wantErrResp:           ErrIssueAndRotateOwnerCerts,
			getIakCertResps: []*epb.GetIakCertResponse{
				{
					ControlCardId:               vendorID1,
					IakCert:                     iakCert1,
					IdevidCert:                  iDevIDCert1,
					AtomicCertRotationSupported: true,
				},
				{
					ControlCardId:               vendorID2,
					IakCert:                     iakCert2,
					IdevidCert:                  iDevIDCert2,
					AtomicCertRotationSupported: true,
				},
			},
			verifyIakAndIDevIDCertsResps: []*VerifyIakAndIDevIDCertsResp{
				{
					IakPubPem:    iakPub1,
					IDevIDPubPem: iDevIDPub1,
				},
				{
					IakPubPem:    iakPub2,
					IDevIDPubPem: iDevIDPub2,
				},
			},
			issueOwnerIakCertResps:    []*IssueOwnerIakCertResp{{OwnerIakCertPem: oIakCert1}},
			issueOwnerIDevIDCertResps: []*IssueOwnerIDevIDCertResp{{OwnerIDevIDCertPem: oIdevIDCert1}, {OwnerIDevIDCertPem: oIdevIDCert2}},
			wantGetIakCertReqs: []*epb.GetIakCertRequest{
				{ControlCardSelection: controlCardSelection1},
				{ControlCardSelection: controlCardSelection2},
			},
			wantVerifyIakAndIDevIDCertsReqs: []*VerifyIakAndIDevIDCertsReq{
				{
					ControlCardID:        vendorID1,
					IakCertPem:           iakCert1,
					IDevIDCertPem:        iDevIDCert1,
					CertVerificationOpts: certVerificationOpts,
				},
				{
					ControlCardID:        vendorID2,
					IakCertPem:           iakCert2,
					IDevIDCertPem:        iDevIDCert2,
					CertVerificationOpts: certVerificationOpts,
				},
			},
			wantIssueOwnerIakCertReqs: []*IssueOwnerIakCertReq{
				{CardID: vendorID1, IakPubPem: iakPub1},
				{CardID: vendorID2, IakPubPem: iakPub2},
			},
			wantIssueOwnerIDevIDCertReqs: []*IssueOwnerIDevIDCertReq{
				{CardID: vendorID1, IDevIDPubPem: iDevIDPub1},
				{CardID: vendorID2, IDevIDPubPem: iDevIDPub2},
			},
		},
		{
			desc:                  "SwitchOwnerCaClient.IssueOwnerIDevIDCert() failure on second card (multiple)",
			controlCardSelections: []*cpb.ControlCardSelection{controlCardSelection1, controlCardSelection2},
			wantErrResp:           ErrIssueAndRotateOwnerCerts,
			getIakCertResps: []*epb.GetIakCertResponse{
				{
					ControlCardId:               vendorID1,
					IakCert:                     iakCert1,
					IdevidCert:                  iDevIDCert1,
					AtomicCertRotationSupported: true,
				},
				{
					ControlCardId:               vendorID2,
					IakCert:                     iakCert2,
					IdevidCert:                  iDevIDCert2,
					AtomicCertRotationSupported: true,
				},
			},
			verifyIakAndIDevIDCertsResps: []*VerifyIakAndIDevIDCertsResp{
				{
					IakPubPem:    iakPub1,
					IDevIDPubPem: iDevIDPub1,
				},
				{
					IakPubPem:    iakPub2,
					IDevIDPubPem: iDevIDPub2,
				},
			},
			issueOwnerIakCertResps:    []*IssueOwnerIakCertResp{{OwnerIakCertPem: oIakCert1}, {OwnerIakCertPem: oIakCert2}},
			issueOwnerIDevIDCertResps: []*IssueOwnerIDevIDCertResp{{OwnerIDevIDCertPem: oIdevIDCert1}},
			wantGetIakCertReqs: []*epb.GetIakCertRequest{
				{ControlCardSelection: controlCardSelection1},
				{ControlCardSelection: controlCardSelection2},
			},
			wantVerifyIakAndIDevIDCertsReqs: []*VerifyIakAndIDevIDCertsReq{
				{
					ControlCardID:        vendorID1,
					IakCertPem:           iakCert1,
					IDevIDCertPem:        iDevIDCert1,
					CertVerificationOpts: certVerificationOpts,
				},
				{
					ControlCardID:        vendorID2,
					IakCertPem:           iakCert2,
					IDevIDCertPem:        iDevIDCert2,
					CertVerificationOpts: certVerificationOpts,
				},
			},
			wantIssueOwnerIakCertReqs: []*IssueOwnerIakCertReq{
				{CardID: vendorID1, IakPubPem: iakPub1},
			},
			wantIssueOwnerIDevIDCertReqs: []*IssueOwnerIDevIDCertReq{
				{CardID: vendorID1, IDevIDPubPem: iDevIDPub1},
				{CardID: vendorID2, IDevIDPubPem: iDevIDPub2},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			stub := &stubEnrollzInfraDeps{
				getIakCertResps:              test.getIakCertResps,
				verifyIakAndIDevIDCertsResps: test.verifyIakAndIDevIDCertsResps,
				issueOwnerIakCertResps:       test.issueOwnerIakCertResps,
				issueOwnerIDevIDCertResps:    test.issueOwnerIDevIDCertResps,
				rotateOIakCertResps:          test.rotateOIakCertResps,
				errorResp:                    test.wantErrResp,
			}
			req := &EnrollControlCardReq{
				ControlCardSelections: test.controlCardSelections,
				CertVerificationOpts:  certVerificationOpts,
				Deps:                  stub,
				SSLProfileID:          sslProfileID,
			}
			ctx := context.Background()
			got := EnrollControlCard(ctx, req)

			// Verify that EnrollControlCard returned expected error/no-error response.
			if !errors.Is(got, test.wantErrResp) {
				t.Errorf("Expected error response %v, but got error response %v", test.wantErrResp, got)
			}

			// Verify that all stubbed dependencies were called with the right params.
			if diff := cmp.Diff(stub.getIakCertReqs, test.wantGetIakCertReqs, protocmp.Transform()); diff != "" {
				t.Errorf("GetIakCertRequest request param to stubbed GetIakCert dep does not match expectations: diff = %v", diff)
			}
			if diff := cmp.Diff(stub.verifyIakAndIDevIDCertsReqs, test.wantVerifyIakAndIDevIDCertsReqs, protocmp.Transform(), cmpopts.IgnoreUnexported(x509.VerifyOptions{})); diff != "" {
				t.Errorf("VerifyIakAndIDevIDCertsReq request param to stubbed VerifyIakAndIDevIDCerts dep does not match expectations: diff = %v", diff)
			}
			if diff := cmp.Diff(stub.issueOwnerIakCertReqs, test.wantIssueOwnerIakCertReqs, protocmp.Transform()); diff != "" {
				t.Errorf("IssueOwnerIakCertReq request param to stubbed IssueOwnerIakCert dep does not match expectations: diff = %v", diff)
			}
			if diff := cmp.Diff(stub.issueOwnerIDevIDCertReqs, test.wantIssueOwnerIDevIDCertReqs, protocmp.Transform()); diff != "" {
				t.Errorf("IssueOwnerIDevIDCertReq request param to stubbed IssueOwnerIDevIDCert dep does not match expectations: diff = %v", diff)
			}
			if diff := cmp.Diff(stub.rotateOIakCertReqs, test.wantRotateOIakCertReqs, protocmp.Transform()); diff != "" {
				t.Errorf("RotateOIakCertRequest request param to stubbed RotateOIakCert dep does not match expectations: diff = %v", diff)
			}
		})
	}
}

func TestRotateOwnerIakCert(t *testing.T) {
	// Constants to be used in request params and stubbing.
	controlCardSelection1 := &cpb.ControlCardSelection{
		ControlCardId: &cpb.ControlCardSelection_Role{
			Role: cpb.ControlCardRole_CONTROL_CARD_ROLE_ACTIVE,
		},
	}
	controlCardSelection2 := &cpb.ControlCardSelection{
		ControlCardId: &cpb.ControlCardSelection_Role{
			Role: cpb.ControlCardRole_CONTROL_CARD_ROLE_STANDBY,
		},
	}
	controlCardSelection3 := &cpb.ControlCardSelection{
		ControlCardId: &cpb.ControlCardSelection_Role{
			Role: cpb.ControlCardRole_CONTROL_CARD_ROLE_STANDBY,
		},
	}
	certVerificationOpts := x509.VerifyOptions{
		DNSName: "Some DNS name",
	}
	vendorID1 := &cpb.ControlCardVendorId{
		ControlCardRole:     controlCardSelection1.GetRole(),
		ControlCardSerial:   "Some card serial 1",
		ControlCardSlot:     "Some card slot 1",
		ChassisManufacturer: "Some manufacturer",
		ChassisPartNumber:   "Some part",
		ChassisSerialNumber: "Some chassis serial",
	}
	vendorID2 := &cpb.ControlCardVendorId{
		ControlCardRole:     controlCardSelection2.GetRole(),
		ControlCardSerial:   "Some card serial 2",
		ControlCardSlot:     "Some card slot 2",
		ChassisManufacturer: "Some manufacturer",
		ChassisPartNumber:   "Some part",
		ChassisSerialNumber: "Some chassis serial",
	}
	iakCert1 := "Some IAK cert PEM 1"
	iakPub1 := "Some IAK pub PEM 1"
	oIakCert1 := "Some Owner IAK cert PEM 1"

	iakCert2 := "Some IAK cert PEM 2"
	iakPub2 := "Some IAK pub PEM 2"
	oIakCert2 := "Some Owner IAK cert PEM 2"

	tests := []struct {
		// Test description.
		desc string
		// Overall expected RotateOwnerIakCert response.
		wantErrResp           error
		controlCardSelections []*cpb.ControlCardSelection
		// Expected captured params to stubbed deps functions calls.
		wantGetIakCertReqs        []*epb.GetIakCertRequest
		wantIssueOwnerIakCertReqs []*IssueOwnerIakCertReq
		wantRotateOIakCertReqs    []*epb.RotateOIakCertRequest
		wantVerifyTpmCertReqs     []*VerifyTpmCertReq
		// Stubbed responses to EnrollzInfraDeps deps.
		issueOwnerIakCertResps []*IssueOwnerIakCertResp
		getIakCertResps        []*epb.GetIakCertResponse
		rotateOIakCertResps    []*epb.RotateOIakCertResponse
		verifyTpmCertResps     []*VerifyTpmCertResp
	}{
		{
			desc:                  "Successful rotation of Owner IAK cert (single)",
			controlCardSelections: []*cpb.ControlCardSelection{controlCardSelection1},
			getIakCertResps: []*epb.GetIakCertResponse{{
				ControlCardId:               vendorID1,
				IakCert:                     iakCert1,
				AtomicCertRotationSupported: true,
			}},
			verifyTpmCertResps: []*VerifyTpmCertResp{{
				PubPem: iakPub1,
			}},
			issueOwnerIakCertResps: []*IssueOwnerIakCertResp{{OwnerIakCertPem: oIakCert1}},
			rotateOIakCertResps:    []*epb.RotateOIakCertResponse{{}},

			wantGetIakCertReqs: []*epb.GetIakCertRequest{{ControlCardSelection: controlCardSelection1}},
			wantVerifyTpmCertReqs: []*VerifyTpmCertReq{{
				ControlCardID:        vendorID1,
				CertPem:              iakCert1,
				CertVerificationOpts: certVerificationOpts,
			}},
			wantIssueOwnerIakCertReqs: []*IssueOwnerIakCertReq{{
				CardID:    vendorID1,
				IakPubPem: iakPub1,
			}},
			wantRotateOIakCertReqs: []*epb.RotateOIakCertRequest{{
				SslProfileId: "",
				Updates: []*epb.ControlCardCertUpdate{{
					ControlCardSelection: controlCardSelection1,
					OiakCert:             oIakCert1,
				}},
			}},
		},
		{
			desc:                  "Successful rotation of Owner IAK cert (multiple)",
			controlCardSelections: []*cpb.ControlCardSelection{controlCardSelection1, controlCardSelection2},
			getIakCertResps: []*epb.GetIakCertResponse{
				{
					ControlCardId:               vendorID1,
					IakCert:                     iakCert1,
					AtomicCertRotationSupported: true,
				},
				{
					ControlCardId:               vendorID2,
					IakCert:                     iakCert2,
					AtomicCertRotationSupported: true,
				},
			},
			verifyTpmCertResps: []*VerifyTpmCertResp{
				{PubPem: iakPub1},
				{PubPem: iakPub2},
			},
			issueOwnerIakCertResps: []*IssueOwnerIakCertResp{{OwnerIakCertPem: oIakCert1}, {OwnerIakCertPem: oIakCert2}},
			rotateOIakCertResps:    []*epb.RotateOIakCertResponse{{}},

			wantGetIakCertReqs: []*epb.GetIakCertRequest{
				{ControlCardSelection: controlCardSelection1},
				{ControlCardSelection: controlCardSelection2},
			},
			wantVerifyTpmCertReqs: []*VerifyTpmCertReq{
				{
					ControlCardID:        vendorID1,
					CertPem:              iakCert1,
					CertVerificationOpts: certVerificationOpts,
				},
				{
					ControlCardID:        vendorID2,
					CertPem:              iakCert2,
					CertVerificationOpts: certVerificationOpts,
				},
			},
			wantIssueOwnerIakCertReqs: []*IssueOwnerIakCertReq{
				{CardID: vendorID1, IakPubPem: iakPub1},
				{CardID: vendorID2, IakPubPem: iakPub2},
			},
			wantRotateOIakCertReqs: []*epb.RotateOIakCertRequest{{
				SslProfileId: "",
				Updates: []*epb.ControlCardCertUpdate{
					{
						ControlCardSelection: controlCardSelection1,
						OiakCert:             oIakCert1,
					},
					{
						ControlCardSelection: controlCardSelection2,
						OiakCert:             oIakCert2,
					},
				},
			}},
		},
		{
			desc:                  "RotateOwnerIakCert failure (too few cards)",
			controlCardSelections: []*cpb.ControlCardSelection{},
			wantErrResp:           ErrInvalidRequest,
		},
		{
			desc:                  "RotateOwnerIakCert failure (too many cards)",
			controlCardSelections: []*cpb.ControlCardSelection{controlCardSelection1, controlCardSelection2, controlCardSelection3},
			wantErrResp:           ErrInvalidRequest,
		},
		{
			desc:                  "EnrollzDeviceClient.GetIakCert() failure causes overall RotateOwnerIakCert failure",
			wantErrResp:           ErrVerifyIdentity,
			controlCardSelections: []*cpb.ControlCardSelection{controlCardSelection1},
			wantGetIakCertReqs:    []*epb.GetIakCertRequest{{ControlCardSelection: controlCardSelection1}},
		},
		{
			desc:                  "TpmCertVerifier.VerifyTpmCert() failure causes overall RotateOwnerIakCert failure",
			wantErrResp:           ErrVerifyIdentity,
			controlCardSelections: []*cpb.ControlCardSelection{controlCardSelection1},
			getIakCertResps: []*epb.GetIakCertResponse{{
				ControlCardId: vendorID1,
				IakCert:       iakCert1,
			}},
			wantGetIakCertReqs: []*epb.GetIakCertRequest{{ControlCardSelection: controlCardSelection1}},
			wantVerifyTpmCertReqs: []*VerifyTpmCertReq{{
				ControlCardID:        vendorID1,
				CertPem:              iakCert1,
				CertVerificationOpts: certVerificationOpts,
			}},
		},
		{
			desc:                  "SwitchOwnerCaClient.IssueOwnerIakCert() failure causes overall RotateOwnerIakCert failure",
			wantErrResp:           ErrIssueAndRotateOwnerCerts,
			controlCardSelections: []*cpb.ControlCardSelection{controlCardSelection1},
			getIakCertResps: []*epb.GetIakCertResponse{{
				ControlCardId:               vendorID1,
				IakCert:                     iakCert1,
				AtomicCertRotationSupported: true,
			}},
			verifyTpmCertResps: []*VerifyTpmCertResp{{
				PubPem: iakPub1,
			}},
			wantGetIakCertReqs: []*epb.GetIakCertRequest{{ControlCardSelection: controlCardSelection1}},
			wantVerifyTpmCertReqs: []*VerifyTpmCertReq{{
				ControlCardID:        vendorID1,
				CertPem:              iakCert1,
				CertVerificationOpts: certVerificationOpts,
			}},
			wantIssueOwnerIakCertReqs: []*IssueOwnerIakCertReq{{
				CardID:    vendorID1,
				IakPubPem: iakPub1,
			}},
		},
		{
			desc:                  "EnrollzDeviceClient.RotateOIakCert() failure causes overall RotateOwnerIakCert failure",
			wantErrResp:           ErrIssueAndRotateOwnerCerts,
			controlCardSelections: []*cpb.ControlCardSelection{controlCardSelection1},
			getIakCertResps: []*epb.GetIakCertResponse{{
				ControlCardId:               vendorID1,
				IakCert:                     iakCert1,
				AtomicCertRotationSupported: true,
			}},
			verifyTpmCertResps: []*VerifyTpmCertResp{{
				PubPem: iakPub1,
			}},
			issueOwnerIakCertResps: []*IssueOwnerIakCertResp{{OwnerIakCertPem: oIakCert1}},
			wantGetIakCertReqs:     []*epb.GetIakCertRequest{{ControlCardSelection: controlCardSelection1}},
			wantVerifyTpmCertReqs: []*VerifyTpmCertReq{{
				ControlCardID:        vendorID1,
				CertPem:              iakCert1,
				CertVerificationOpts: certVerificationOpts,
			}},
			wantIssueOwnerIakCertReqs: []*IssueOwnerIakCertReq{{
				CardID:    vendorID1,
				IakPubPem: iakPub1,
			}},
			wantRotateOIakCertReqs: []*epb.RotateOIakCertRequest{{
				SslProfileId: "",
				Updates: []*epb.ControlCardCertUpdate{{
					ControlCardSelection: controlCardSelection1,
					OiakCert:             oIakCert1,
				}},
			}},
		},
		{
			desc:                  "EnrollzDeviceClient.GetIakCert() failure on second card (multiple)",
			controlCardSelections: []*cpb.ControlCardSelection{controlCardSelection1, controlCardSelection2},
			wantErrResp:           ErrVerifyIdentity,
			getIakCertResps: []*epb.GetIakCertResponse{
				{
					ControlCardId:               vendorID1,
					IakCert:                     iakCert1,
					AtomicCertRotationSupported: true,
				},
			},
			verifyTpmCertResps: []*VerifyTpmCertResp{
				{
					PubPem: iakPub1,
				},
			},
			wantGetIakCertReqs: []*epb.GetIakCertRequest{
				{ControlCardSelection: controlCardSelection1},
				{ControlCardSelection: controlCardSelection2},
			},
			wantVerifyTpmCertReqs: []*VerifyTpmCertReq{
				{
					ControlCardID:        vendorID1,
					CertPem:              iakCert1,
					CertVerificationOpts: certVerificationOpts,
				},
			},
		},
		{
			desc:                  "TpmCertVerifier.VerifyTpmCert() failure on second card (multiple)",
			controlCardSelections: []*cpb.ControlCardSelection{controlCardSelection1, controlCardSelection2},
			wantErrResp:           ErrVerifyIdentity,
			getIakCertResps: []*epb.GetIakCertResponse{
				{
					ControlCardId:               vendorID1,
					IakCert:                     iakCert1,
					AtomicCertRotationSupported: true,
				},
				{
					ControlCardId:               vendorID2,
					IakCert:                     iakCert2,
					AtomicCertRotationSupported: true,
				},
			},
			verifyTpmCertResps: []*VerifyTpmCertResp{
				{
					PubPem: iakPub1,
				},
			},
			wantGetIakCertReqs: []*epb.GetIakCertRequest{
				{ControlCardSelection: controlCardSelection1},
				{ControlCardSelection: controlCardSelection2},
			},
			wantVerifyTpmCertReqs: []*VerifyTpmCertReq{
				{
					ControlCardID:        vendorID1,
					CertPem:              iakCert1,
					CertVerificationOpts: certVerificationOpts,
				},
				{
					ControlCardID:        vendorID2,
					CertPem:              iakCert2,
					CertVerificationOpts: certVerificationOpts,
				},
			},
		},
		{
			desc:                  "SwitchOwnerCaClient.IssueOwnerIakCert() failure on second card (multiple)",
			controlCardSelections: []*cpb.ControlCardSelection{controlCardSelection1, controlCardSelection2},
			wantErrResp:           ErrIssueAndRotateOwnerCerts,
			getIakCertResps: []*epb.GetIakCertResponse{
				{
					ControlCardId:               vendorID1,
					IakCert:                     iakCert1,
					AtomicCertRotationSupported: true,
				},
				{
					ControlCardId:               vendorID2,
					IakCert:                     iakCert2,
					AtomicCertRotationSupported: true,
				},
			},
			verifyTpmCertResps: []*VerifyTpmCertResp{
				{
					PubPem: iakPub1,
				},
				{
					PubPem: iakPub2,
				},
			},
			issueOwnerIakCertResps: []*IssueOwnerIakCertResp{{OwnerIakCertPem: oIakCert1}},
			wantGetIakCertReqs: []*epb.GetIakCertRequest{
				{ControlCardSelection: controlCardSelection1},
				{ControlCardSelection: controlCardSelection2},
			},
			wantVerifyTpmCertReqs: []*VerifyTpmCertReq{
				{
					ControlCardID:        vendorID1,
					CertPem:              iakCert1,
					CertVerificationOpts: certVerificationOpts,
				},
				{
					ControlCardID:        vendorID2,
					CertPem:              iakCert2,
					CertVerificationOpts: certVerificationOpts,
				},
			},
			wantIssueOwnerIakCertReqs: []*IssueOwnerIakCertReq{
				{CardID: vendorID1, IakPubPem: iakPub1},
				{CardID: vendorID2, IakPubPem: iakPub2},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			stub := &stubEnrollzInfraDeps{
				getIakCertResps:        test.getIakCertResps,
				verifyTpmCertResps:     test.verifyTpmCertResps,
				issueOwnerIakCertResps: test.issueOwnerIakCertResps,
				rotateOIakCertResps:    test.rotateOIakCertResps,
				errorResp:              test.wantErrResp,
			}
			req := &RotateOwnerIakCertReq{
				ControlCardSelections: test.controlCardSelections,
				CertVerificationOpts:  certVerificationOpts,
				Deps:                  stub,
			}
			ctx := context.Background()
			got := RotateOwnerIakCert(ctx, req)

			// Verify that RotateOwnerIakCertReq returned expected error/no-error response.
			if !errors.Is(got, test.wantErrResp) {
				t.Errorf("Expected error response %v, but got error response %v", test.wantErrResp, got)
			}

			// Verify that all stubbed dependencies were called with the right params.
			if diff := cmp.Diff(stub.getIakCertReqs, test.wantGetIakCertReqs, protocmp.Transform()); diff != "" {
				t.Errorf("GetIakCertRequest request param to stubbed GetIakCert dep does not match expectations: diff = %v", diff)
			}
			if diff := cmp.Diff(stub.verifyTpmCertReqs, test.wantVerifyTpmCertReqs, protocmp.Transform(), cmpopts.IgnoreUnexported(x509.VerifyOptions{})); diff != "" {
				t.Errorf("VerifyTpmCertReq request param to stubbed VerifyTpmCert dep does not match expectations: diff = %v", diff)
			}
			if diff := cmp.Diff(stub.issueOwnerIakCertReqs, test.wantIssueOwnerIakCertReqs, protocmp.Transform()); diff != "" {
				t.Errorf("IssueOwnerIakCertReq request param to stubbed IssueOwnerIakCert dep does not match expectations: diff = %v", diff)
			}
			if diff := cmp.Diff(stub.rotateOIakCertReqs, test.wantRotateOIakCertReqs, protocmp.Transform()); diff != "" {
				t.Errorf("RotateOIakCertRequest request param to stubbed RotateOIakCert dep does not match expectations: diff = %v", diff)
			}
		})
	}
}

func boolPtr(b bool) *bool {
	return &b
}

func TestNonceVerification(t *testing.T) {
	// Constants to be used in request params and stubbing.
	controlCardSelection := &cpb.ControlCardSelection{
		ControlCardId: &cpb.ControlCardSelection_Role{
			Role: cpb.ControlCardRole_CONTROL_CARD_ROLE_ACTIVE,
		},
	}
	certVerificationOpts := x509.VerifyOptions{
		DNSName: "Some DNS name",
	}
	vendorID := &cpb.ControlCardVendorId{
		ControlCardRole:     controlCardSelection.GetRole(),
		ControlCardSerial:   "Some card serial",
		ControlCardSlot:     "Some card slot",
		ChassisManufacturer: "Some manufacturer",
		ChassisPartNumber:   "Some part",
		ChassisSerialNumber: "Some chassis serial",
	}
	sslProfileID := "some-ssl-profile-id"
	iakCert := "Some IAK cert PEM"
	iDevIDCert := "Some IDevID cert PEM"
	iakPub := "Some IAK pub PEM"
	iDevIDPub := "Some IDevID pub PEM"
	oIakCert := "Some Owner IAK cert PEM"
	oIdevIDCert := "Some Owner IDevID cert PEM"
	validNonceSignature := []byte("some-nonce-signature")

	tests := []struct {
		// Test description.
		desc string
		// Indicates if the test is for EnrollControlCard or RotateOwnerIakCert
		isEnrollmentTest bool
		// Overall expected EnrollControlCard response.
		wantErrResp error
		// Stubbed responses to EnrollzInfraDeps deps.
		getIakCertResp           *epb.GetIakCertResponse
		verifyNonceSignatureResp *VerifyNonceSignatureResp
		skipNonceExchange        *bool
		// Expected verifyNonceSignatureReq to be called.
		wantVerifyNonceSignatureReq bool
	}{
		{
			desc:             "Successful nonce verification",
			isEnrollmentTest: true,
			getIakCertResp: &epb.GetIakCertResponse{
				ControlCardId:  vendorID,
				IakCert:        iakCert,
				IdevidCert:     iDevIDCert,
				NonceSignature: validNonceSignature,
			},
			verifyNonceSignatureResp: &VerifyNonceSignatureResp{
				IsValid: true,
			},
			wantVerifyNonceSignatureReq: true,
			skipNonceExchange:           boolPtr(false),
			wantErrResp:                 nil,
		},
		{
			desc:             "Failed nonce verification",
			isEnrollmentTest: true,
			wantErrResp:      ErrVerifyIdentity,
			getIakCertResp: &epb.GetIakCertResponse{
				ControlCardId:  vendorID,
				IakCert:        iakCert,
				IdevidCert:     iDevIDCert,
				NonceSignature: validNonceSignature,
			},
			verifyNonceSignatureResp: &VerifyNonceSignatureResp{
				IsValid: false,
			},
			wantVerifyNonceSignatureReq: true,
			skipNonceExchange:           boolPtr(false),
		},
		{
			desc:             "Missing nonce signature, verification skipped",
			isEnrollmentTest: true,
			getIakCertResp: &epb.GetIakCertResponse{
				ControlCardId: vendorID,
				IakCert:       iakCert,
				IdevidCert:    iDevIDCert,
			},
			skipNonceExchange: boolPtr(false),
		},
		{
			desc:             "Skip Nonce Exchange",
			isEnrollmentTest: true,
			getIakCertResp: &epb.GetIakCertResponse{
				ControlCardId: vendorID,
				IakCert:       iakCert,
				IdevidCert:    iDevIDCert,
			},
			skipNonceExchange: boolPtr(true),
		},
		{
			desc:             "Successful nonce verification for RotateOwnerIakCert",
			isEnrollmentTest: false,
			getIakCertResp: &epb.GetIakCertResponse{
				ControlCardId:  vendorID,
				IakCert:        iakCert,
				NonceSignature: validNonceSignature,
			},
			verifyNonceSignatureResp: &VerifyNonceSignatureResp{
				IsValid: true,
			},
			wantVerifyNonceSignatureReq: true,
			skipNonceExchange:           boolPtr(false),
			wantErrResp:                 nil,
		},
		{
			desc:             "Failed nonce verification for RotateOwnerIakCert",
			isEnrollmentTest: false,
			wantErrResp:      ErrVerifyIdentity,
			getIakCertResp: &epb.GetIakCertResponse{
				ControlCardId:  vendorID,
				IakCert:        iakCert,
				NonceSignature: validNonceSignature,
			},
			verifyNonceSignatureResp: &VerifyNonceSignatureResp{
				IsValid: false,
			},
			wantVerifyNonceSignatureReq: true,
			skipNonceExchange:           boolPtr(false),
		},
		{
			desc:             "Missing nonce signature for RotateOwnerIakCert, verification skipped",
			isEnrollmentTest: false,
			getIakCertResp: &epb.GetIakCertResponse{
				ControlCardId: vendorID,
				IakCert:       iakCert,
			},
			skipNonceExchange: boolPtr(false),
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			stub := &stubEnrollzInfraDeps{
				getIakCertResps:              []*epb.GetIakCertResponse{test.getIakCertResp},
				verifyIakAndIDevIDCertsResps: []*VerifyIakAndIDevIDCertsResp{{IakPubPem: iakPub, IDevIDPubPem: iDevIDPub}},
				issueOwnerIakCertResps:       []*IssueOwnerIakCertResp{{OwnerIakCertPem: oIakCert}},
				issueOwnerIDevIDCertResps:    []*IssueOwnerIDevIDCertResp{{OwnerIDevIDCertPem: oIdevIDCert}},
				rotateOIakCertResps:          []*epb.RotateOIakCertResponse{{}},
				errorResp:                    test.wantErrResp,
				verifyNonceSignatureResps:    []*VerifyNonceSignatureResp{test.verifyNonceSignatureResp},
				verifyTpmCertResps:           []*VerifyTpmCertResp{{PubPem: iakPub}},
			}
			ctx := context.Background()
			var got error
			if test.isEnrollmentTest {
				req := &EnrollControlCardReq{
					ControlCardSelections: []*cpb.ControlCardSelection{controlCardSelection},
					CertVerificationOpts:  certVerificationOpts,
					Deps:                  stub,
					SSLProfileID:          sslProfileID,
					SkipNonceExchange:     test.skipNonceExchange,
				}
				got = EnrollControlCard(ctx, req)
			} else {
				req := &RotateOwnerIakCertReq{
					ControlCardSelections: []*cpb.ControlCardSelection{controlCardSelection},
					CertVerificationOpts:  certVerificationOpts,
					Deps:                  stub,
					SkipNonceExchange:     test.skipNonceExchange,
				}
				got = RotateOwnerIakCert(ctx, req)
			}

			// Verify that EnrollControlCard returned expected error/no-error response.
			if !errors.Is(got, test.wantErrResp) {
				t.Errorf("Expected error response %v, but got error response %v", test.wantErrResp, got)
			}

			// Verify that GetIakCertReq was called with a nonce if SkipNonceExchange is false.
			if test.skipNonceExchange == nil || !*test.skipNonceExchange {
				if len(stub.getIakCertReqs) == 0 || len(stub.getIakCertReqs[0].Nonce) == 0 {
					t.Errorf("GetIakCertRequest was called without a nonce, but it was expected")
				}
			} else if len(stub.getIakCertReqs) > 0 && len(stub.getIakCertReqs[0].Nonce) > 0 {
				t.Errorf("GetIakCertRequest was called with a nonce, but it was not expected")
			}

			// Verify that VerifyNonceSignature was called if expected.
			if test.wantVerifyNonceSignatureReq && len(stub.verifyNonceSignatureReqs) == 0 {
				t.Errorf("VerifyNonceSignature was expected to be called but was not")
			} else if !test.wantVerifyNonceSignatureReq && len(stub.verifyNonceSignatureReqs) > 0 {
				t.Errorf("VerifyNonceSignature was not expected to be called but was")
			}
			if test.wantVerifyNonceSignatureReq {
				if len(stub.verifyNonceSignatureReqs) == 0 {
					t.Errorf("VerifyNonceSignature was expected to be called but was not")
				} else {
					req := stub.verifyNonceSignatureReqs[0]
					if len(req.Nonce) == 0 || len(req.Signature) == 0 || len(req.IAKPubPem) == 0 || req.HashAlgo == 0 {
						t.Errorf("VerifyNonceSignature was expected to be called with all parameters, but one or more parameters was missing")
					}
				}
			}
		})
	}
}

type stubRotateAIKCertInfraDeps struct {
	SwitchOwnerCaClient
	EnrollzDeviceClient
	TpmCertVerifier
	ROTDBClient
	TPM12Utils

	fetchEkReq      *FetchEKReq
	issueAikCertReq *IssueAikCertReq

	// Specific errors for each stubbed method. If nil, a default success value is returned.
	fetchEkErr                   error
	parseIdentityReqErr          error
	parseSymmetricKeyErr         error
	parseIdentityProofErr        error
	verifySignatureWithRSAKeyErr error
	issueAikCertErr              error
	newAESCBCKeyErr              error
	encryptWithAesErr            error
	serializeSymCAAttestationErr error
	constructAsymCAContentsErr   error
	serializeAsymCAContentsErr   error
	encryptWithPublicKeyErr      error
	decryptWithPrivateKeyErr     error
	decryptWithSymmetricKeyErr   error
	constructIdentityContentsErr error
	serializeIdentityContentsErr error
	tpmPubKeyToRSAPubKeyErr      error
	rotateAikCertClient          epb.TpmEnrollzService_RotateAIKCertClient
	rotateAikCertStreamError     error

	// Optional: Custom return values for specific success scenarios.
	customIssueAikCertResp    *IssueAikCertResp
	customVerifySignatureResp bool
}

func (s *stubRotateAIKCertInfraDeps) FetchEK(ctx context.Context, req *FetchEKReq) (*FetchEKResp, error) {
	if s.fetchEkReq != nil {
		return nil, fmt.Errorf("FetchEK unexpected req %+v", req)
	}
	s.fetchEkReq = req
	if s.fetchEkErr != nil {
		return nil, s.fetchEkErr
	}
	return &FetchEKResp{EkPublicKey: &rsa.PublicKey{}}, nil // Default success
}

func (s *stubRotateAIKCertInfraDeps) ParseIdentityRequest(data []byte) (*TPMIdentityReq, error) {
	if s.parseIdentityReqErr != nil {
		return nil, s.parseIdentityReqErr
	}
	return &TPMIdentityReq{}, nil // Default success
}

func (s *stubRotateAIKCertInfraDeps) ParseSymmetricKey(data []byte) (*TPMSymmetricKey, error) {
	if s.parseSymmetricKeyErr != nil {
		return nil, s.parseSymmetricKeyErr
	}
	return &TPMSymmetricKey{}, nil // Default success
}

func (s *stubRotateAIKCertInfraDeps) ParseIdentityProof(data []byte) (*TPMIdentityProof, error) {
	if s.parseIdentityProofErr != nil {
		return nil, s.parseIdentityProofErr
	}
	return &TPMIdentityProof{}, nil // Default success
}

func (s *stubRotateAIKCertInfraDeps) VerifySignatureWithRSAKey(ctx context.Context, pubKey *TPMPubKey, signature []byte, digest []byte) (bool, error) {
	if s.verifySignatureWithRSAKeyErr != nil {
		return false, s.verifySignatureWithRSAKeyErr
	}
	if s.customVerifySignatureResp != false {
		return s.customVerifySignatureResp, nil
	}
	return true, nil // Default success
}

func (s *stubRotateAIKCertInfraDeps) NewAESCBCKey(algo tpm12.Algorithm) (*TPMSymmetricKey, error) {
	if s.newAESCBCKeyErr != nil {
		return nil, s.newAESCBCKeyErr
	}
	return &TPMSymmetricKey{}, nil // Default success
}

func (s *stubRotateAIKCertInfraDeps) EncryptWithAES(symKey *TPMSymmetricKey, data []byte) ([]byte, *TPMKeyParms, error) {
	if s.encryptWithAesErr != nil {
		return nil, nil, s.encryptWithAesErr
	}
	return []byte("encrypted"), &TPMKeyParms{}, nil // Default success
}

func (s *stubRotateAIKCertInfraDeps) SerializeSymCAAttestation(symCAAttestation *TPMSymCAAttestation) ([]byte, error) {
	if s.serializeAsymCAContentsErr != nil {
		return nil, s.serializeAsymCAContentsErr
	}
	return []byte("serialized"), nil
}

func (s *stubRotateAIKCertInfraDeps) ConstructAsymCAContents(symKey *TPMSymmetricKey, identityKey *TPMPubKey) (*TPMAsymCAContents, error) {
	if s.constructAsymCAContentsErr != nil {
		return nil, s.constructAsymCAContentsErr
	}
	return &TPMAsymCAContents{}, nil
}

func (s *stubRotateAIKCertInfraDeps) SerializeAsymCAContents(asymCAContents *TPMAsymCAContents) ([]byte, error) {
	if s.serializeAsymCAContentsErr != nil {
		return nil, s.serializeAsymCAContentsErr
	}
	return []byte("serialized"), nil
}

func (s *stubRotateAIKCertInfraDeps) EncryptWithPublicKey(ctx context.Context, publicKey *rsa.PublicKey, data []byte, algo tpm12.Algorithm, encScheme TPMEncodingScheme) ([]byte, error) {
	if s.encryptWithPublicKeyErr != nil {
		return nil, s.encryptWithPublicKeyErr
	}
	return []byte("encrypted key"), nil // Default success
}

func (s *stubRotateAIKCertInfraDeps) DecryptWithPrivateKey(ctx context.Context, privateKey *rsa.PrivateKey, data []byte, algo tpm12.Algorithm, encScheme TPMEncodingScheme) ([]byte, error) {
	if s.decryptWithPrivateKeyErr != nil {
		return nil, s.decryptWithPrivateKeyErr
	}
	return []byte("decrypted sym key"), nil // Default success
}

func (s *stubRotateAIKCertInfraDeps) DecryptWithSymmetricKey(ctx context.Context, symKey *TPMSymmetricKey, keyParams *TPMKeyParms, ciphertext []byte) ([]byte, error) {
	if s.decryptWithSymmetricKeyErr != nil {
		return nil, s.decryptWithSymmetricKeyErr
	}
	return []byte("decrypted identity proof"), nil // Default success
}

func (s *stubRotateAIKCertInfraDeps) ConstructIdentityContents(*rsa.PublicKey, *TPMPubKey) (*TPMIdentityContents, error) {
	if s.constructIdentityContentsErr != nil {
		return nil, s.constructIdentityContentsErr
	}
	return &TPMIdentityContents{}, nil // Default success
}

func (s *stubRotateAIKCertInfraDeps) SerializeIdentityContents(*TPMIdentityContents) ([]byte, error) {
	if s.serializeIdentityContentsErr != nil {
		return nil, s.serializeIdentityContentsErr
	}
	return []byte("serialized identity contents"), nil // Default success
}

func (s *stubRotateAIKCertInfraDeps) RotateAIKCert(ctx context.Context, opts ...grpc.CallOption) (epb.TpmEnrollzService_RotateAIKCertClient, error) {
	if s.rotateAikCertStreamError != nil {
		return nil, s.rotateAikCertStreamError
	}
	return s.rotateAikCertClient, nil
}

func (s *stubRotateAIKCertInfraDeps) TpmPubKeyToRSAPubKey(pubKey *TPMPubKey) (*rsa.PublicKey, error) {
	if s.tpmPubKeyToRSAPubKeyErr != nil {
		return nil, s.tpmPubKeyToRSAPubKeyErr
	}
	// Return a default non-nil rsa.PublicKey to avoid issues in subsequent code.
	return &rsa.PublicKey{N: big.NewInt(1), E: 65537}, nil
}

func (s *stubRotateAIKCertInfraDeps) IssueAikCert(ctx context.Context, req *IssueAikCertReq) (*IssueAikCertResp, error) {
	// Validate that no stub (captured) request params were set prior to execution.
	if s.issueAikCertReq != nil {
		return nil, fmt.Errorf("IssueAikCert unexpected req %+v", s.issueAikCertReq)
	}
	s.issueAikCertReq = req
	if s.issueAikCertErr != nil {
		return nil, s.issueAikCertErr
	}
	if s.customIssueAikCertResp != nil {
		return s.customIssueAikCertResp, nil
	}
	return &IssueAikCertResp{AikCertPem: "Some AIK cert PEM"}, nil // Default success
}

type stubRotateAIKCertClient struct {
	epb.TpmEnrollzService_RotateAIKCertClient
	recvResponses   []*epb.RotateAIKCertResponse
	sendError       error
	recvError       error
	closeSendError  error
	recvResponseIdx int
}

func (c *stubRotateAIKCertClient) Send(req *epb.RotateAIKCertRequest) error {
	return c.sendError
}

func (c *stubRotateAIKCertClient) Recv() (*epb.RotateAIKCertResponse, error) {
	if c.recvError != nil {
		return nil, c.recvError
	}
	if c.recvResponseIdx >= len(c.recvResponses) {
		return nil, io.EOF
	}
	resp := c.recvResponses[c.recvResponseIdx]
	c.recvResponseIdx++
	return resp, nil
}

func (c *stubRotateAIKCertClient) CloseSend() error {
	return c.closeSendError
}

func TestRotateAIKCert(t *testing.T) {
	// Constants to be used in request params and stubbing.
	controlCardSelection := &cpb.ControlCardSelection{
		ControlCardId: &cpb.ControlCardSelection_Role{
			Role: cpb.ControlCardRole_CONTROL_CARD_ROLE_ACTIVE,
		},
	}
	vendorID := &cpb.ControlCardVendorId{
		ControlCardRole:     controlCardSelection.GetRole(),
		ControlCardSerial:   "Some card serial",
		ChassisManufacturer: "Some manufacturer",
		ChassisSerialNumber: "Some chassis serial",
	}
	aikCert := "Some AIK cert PEM"
	errorResp := errors.New("Some error")

	// Define the default responses for a successful stream.
	defaultRecvResponses := []*epb.RotateAIKCertResponse{
		{
			Value: &epb.RotateAIKCertResponse_ApplicationIdentityRequest{
				ApplicationIdentityRequest: []byte("dummy identity request"),
			},
			ControlCardId: vendorID,
		},
		{
			Value: &epb.RotateAIKCertResponse_AikCert{
				AikCert: aikCert,
			},
		},
	}

	tests := []struct {
		// Test description.
		desc string
		// Overall expected RotateAIKCert response.
		wantErrResp error
		// Specific errors to inject into stubbed dependencies.
		fetchEkErr                   error
		parseIdentityReqErr          error
		parseSymmetricKeyErr         error
		parseIdentityProofErr        error
		verifySignatureWithRSAKeyErr error
		issueAikCertErr              error
		newAESCBCKeyErr              error
		encryptWithAesErr            error
		serializeSymCAAttestationErr error
		constructAsymCAContentsErr   error
		serializeAsymCAContentsErr   error
		encryptWithPublicKeyErr      error
		decryptWithPrivateKeyErr     error
		tpmPubKeyToRSAPubKeyErr      error
		decryptWithSymmetricKeyErr   error
		constructIdentityContentsErr error
		serializeIdentityContentsErr error
		rotateAikCertStreamError     error
		// Optional: Custom receive responses for the stubbed client.
		recvResponses []*epb.RotateAIKCertResponse
		// Optional: Custom return values for specific success scenarios.
		customIssueAikCertResp    *IssueAikCertResp
		customVerifySignatureResp bool
	}{
		{
			desc:          "Successful AIK cert rotation",
			recvResponses: defaultRecvResponses,
		},
		{
			desc:                     "Error initiating stream",
			wantErrResp:              errorResp,
			rotateAikCertStreamError: errorResp,
		},
		{
			desc:        "Error sending issuer public key",
			wantErrResp: errorResp,
			recvResponses: []*epb.RotateAIKCertResponse{
				{
					Value: &epb.RotateAIKCertResponse_ApplicationIdentityRequest{
						ApplicationIdentityRequest: []byte("dummy identity request"),
					},
					ControlCardId: vendorID,
				},
			},
		},
		{
			desc:          "Error receiving application identity request",
			wantErrResp:   errorResp,
			recvResponses: []*epb.RotateAIKCertResponse{
				// No responses, so Recv will error.
			},
		},
		{
			desc:        "Empty application identity request",
			wantErrResp: errors.New("application_identity_request is empty"),
			recvResponses: []*epb.RotateAIKCertResponse{
				{
					Value: &epb.RotateAIKCertResponse_ApplicationIdentityRequest{
						ApplicationIdentityRequest: []byte(""),
					},
					ControlCardId: vendorID,
				},
			},
		},
		{
			desc:                "Error parsing application identity request",
			wantErrResp:         errorResp,
			parseIdentityReqErr: errorResp,
			recvResponses:       defaultRecvResponses,
		},
		{
			desc:                     "Error decrypting AsymBlob",
			wantErrResp:              errorResp,
			decryptWithPrivateKeyErr: errorResp,
			recvResponses:            defaultRecvResponses,
		},
		{
			desc:                 "Error parsing symmetric key",
			wantErrResp:          errorResp,
			parseSymmetricKeyErr: errorResp,
			recvResponses:        defaultRecvResponses,
		},
		{
			desc:                       "Error decrypting SymBlob",
			wantErrResp:                errorResp,
			decryptWithSymmetricKeyErr: errorResp,
			recvResponses:              defaultRecvResponses,
		},
		{
			desc:                  "Error parsing identity proof",
			wantErrResp:           errorResp,
			parseIdentityProofErr: errorResp,
			recvResponses:         defaultRecvResponses,
		},
		{
			desc:                         "Error constructing identity contents",
			wantErrResp:                  errorResp,
			constructIdentityContentsErr: errorResp,
			recvResponses:                defaultRecvResponses,
		},
		{
			desc:                         "Error serializing identity contents",
			wantErrResp:                  errorResp,
			serializeIdentityContentsErr: errorResp,
			recvResponses:                defaultRecvResponses,
		},
		{
			desc:                         "Error verifying signature",
			wantErrResp:                  errorResp,
			verifySignatureWithRSAKeyErr: errorResp,
			recvResponses:                defaultRecvResponses,
		},
		{
			desc:                      "Signature verification failed",
			wantErrResp:               errors.New("identity contents signature is not valid"),
			customVerifySignatureResp: false, // Override default true
			recvResponses:             defaultRecvResponses,
		},
		{
			desc:          "Error fetching EK",
			wantErrResp:   errorResp,
			fetchEkErr:    errorResp,
			recvResponses: defaultRecvResponses,
		},
		{
			desc:            "Error issuing AIK cert",
			wantErrResp:     errorResp,
			issueAikCertErr: errorResp,
			recvResponses:   defaultRecvResponses,
		},
		{
			desc:            "Error creating AES GCM key",
			wantErrResp:     errorResp,
			newAESCBCKeyErr: errorResp,
			recvResponses:   defaultRecvResponses,
		},
		{
			desc:                         "Serialization of TPMSymCAAttestation failed",
			wantErrResp:                  errorResp,
			serializeSymCAAttestationErr: errorResp,
			recvResponses:                defaultRecvResponses,
		},
		{
			desc:                       "Construction of TPMAsymCaContents failed",
			wantErrResp:                errorResp,
			constructAsymCAContentsErr: errorResp,
			recvResponses:              defaultRecvResponses,
		},
		{
			desc:                       "Serialization of TPMAsymCaContents failed",
			wantErrResp:                errorResp,
			serializeAsymCAContentsErr: errorResp,
			recvResponses:              defaultRecvResponses,
		},
		{
			desc:              "Error encrypting AIK cert",
			wantErrResp:       errorResp,
			encryptWithAesErr: errorResp,
			recvResponses:     defaultRecvResponses,
		},
		{
			desc:                    "Error encrypting AES key",
			wantErrResp:             errorResp,
			encryptWithPublicKeyErr: errorResp,
			recvResponses:           defaultRecvResponses,
		},
		{
			desc:                   "Empty device AIK cert",
			wantErrResp:            fmt.Errorf("device AIK cert is empty"),
			customIssueAikCertResp: &IssueAikCertResp{AikCertPem: aikCert},
			recvResponses: []*epb.RotateAIKCertResponse{
				{
					Value: &epb.RotateAIKCertResponse_ApplicationIdentityRequest{
						ApplicationIdentityRequest: []byte("dummy identity request"),
					},
					ControlCardId: vendorID,
				},
				{
					Value: &epb.RotateAIKCertResponse_AikCert{
						AikCert: "",
					},
				},
			},
		},
		{
			desc:                   "AIK certs do not match",
			wantErrResp:            fmt.Errorf("AIK certificates do not match"),
			customIssueAikCertResp: &IssueAikCertResp{AikCertPem: aikCert},
			recvResponses: []*epb.RotateAIKCertResponse{
				{
					Value: &epb.RotateAIKCertResponse_ApplicationIdentityRequest{
						ApplicationIdentityRequest: []byte("dummy identity request"),
					},
					ControlCardId: vendorID,
				},
				{
					Value: &epb.RotateAIKCertResponse_AikCert{
						AikCert: "Some other AIK cert",
					},
				},
			},
		},
		{
			desc:        "Error sending finalize message",
			wantErrResp: errorResp,
			recvResponses: []*epb.RotateAIKCertResponse{
				{
					Value: &epb.RotateAIKCertResponse_ApplicationIdentityRequest{
						ApplicationIdentityRequest: []byte("dummy identity request"),
					},
					ControlCardId: vendorID,
				},
				{
					Value: &epb.RotateAIKCertResponse_AikCert{
						AikCert: aikCert,
					},
				},
			},
			// sendError is handled directly in the stub's Send method.
		},
		{
			desc:        "Error closing stream after finalize",
			wantErrResp: errorResp,
			recvResponses: []*epb.RotateAIKCertResponse{
				{
					Value: &epb.RotateAIKCertResponse_ApplicationIdentityRequest{
						ApplicationIdentityRequest: []byte("dummy identity request"),
					},
					ControlCardId: vendorID,
				},
				{
					Value: &epb.RotateAIKCertResponse_AikCert{
						AikCert: aikCert,
					},
				},
				{}, // Simulate a non-EOF response after finalize send
			},
			// closeSendError is handled directly in the stub's CloseSend method.
		},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			// Create a new stubRotateAIKCertClient for each test run.
			stubClient := &stubRotateAIKCertClient{
				recvResponses:   tc.recvResponses,
				sendError:       tc.wantErrResp, // Inject send error if expected
				recvError:       tc.wantErrResp, // Inject recv error if expected
				closeSendError:  tc.wantErrResp, // Inject closeSend error if expected
				recvResponseIdx: 0,
			}
			// Override specific errors if defined in the test case.
			if tc.rotateAikCertStreamError != nil {
				stubClient.recvError = tc.rotateAikCertStreamError
				stubClient.sendError = tc.rotateAikCertStreamError
				stubClient.closeSendError = tc.rotateAikCertStreamError
			}
			if tc.desc == "Error sending issuer public key" {
				stubClient.sendError = errorResp
				stubClient.recvError = nil // Don't error on recv for this case
			}
			if tc.desc == "Error receiving application identity request" {
				stubClient.recvError = errorResp
			}
			if tc.desc == "Error sending finalize message" {
				stubClient.sendError = errorResp
			}
			if tc.desc == "Error closing stream after finalize" {
				stubClient.closeSendError = errorResp
			}

			deps := &stubRotateAIKCertInfraDeps{
				fetchEkErr:                   tc.fetchEkErr,
				parseIdentityReqErr:          tc.parseIdentityReqErr,
				parseSymmetricKeyErr:         tc.parseSymmetricKeyErr,
				parseIdentityProofErr:        tc.parseIdentityProofErr,
				verifySignatureWithRSAKeyErr: tc.verifySignatureWithRSAKeyErr,
				issueAikCertErr:              tc.issueAikCertErr,
				encryptWithAesErr:            tc.encryptWithAesErr,
				serializeSymCAAttestationErr: tc.serializeSymCAAttestationErr,
				constructAsymCAContentsErr:   tc.constructAsymCAContentsErr,
				serializeAsymCAContentsErr:   tc.constructIdentityContentsErr,
				encryptWithPublicKeyErr:      tc.encryptWithPublicKeyErr,
				decryptWithPrivateKeyErr:     tc.decryptWithPrivateKeyErr,
				decryptWithSymmetricKeyErr:   tc.decryptWithSymmetricKeyErr,
				constructIdentityContentsErr: tc.constructIdentityContentsErr,
				serializeIdentityContentsErr: tc.serializeIdentityContentsErr,
				tpmPubKeyToRSAPubKeyErr:      tc.tpmPubKeyToRSAPubKeyErr,
				rotateAikCertStreamError:     tc.rotateAikCertStreamError,
				rotateAikCertClient:          stubClient,
				customIssueAikCertResp:       tc.customIssueAikCertResp,
				customVerifySignatureResp:    tc.customVerifySignatureResp,
			}

			req := &RotateAIKCertReq{
				ControlCardSelection: controlCardSelection,
				Deps:                 deps,
			}
			err := RotateAIKCert(context.Background(), req)
			if tc.wantErrResp != nil {
				if err == nil || !strings.Contains(err.Error(), tc.wantErrResp.Error()) {
					t.Errorf("RotateAIKCert() returned unexpected error: got %v, want %v", err, tc.wantErrResp)
				}
			} else if err != nil {
				t.Errorf("RotateAIKCert() returned unexpected error: %v", err)
			}
		})
	}
}

type stubVerifyIdentityWithHMACChallengeInfraDeps struct {
	EnrollzInfraDeps
	ROTDBClient
	TPM20Utils

	// Specific errors for each stubbed method. If nil, a default success value is returned.
	getControlCardVendorIDErr    error
	fetchEKErr                   error
	wrapHMACKeytoRSAPublicKeyErr error
	challengeErr                 error
	verifyHMACErr                error
	verifyCertifyInfoErr         error
	verifyIAKAttributesErr       error
	getIdevidCsrErr              error
	parseTCGCSRIDevIDContentErr  error
	verifyTPMTSignatureErr       error
	verifyIDevIDAttributesErr    error
}

func (s *stubVerifyIdentityWithHMACChallengeInfraDeps) GetControlCardVendorID(ctx context.Context, req *epb.GetControlCardVendorIDRequest) (*epb.GetControlCardVendorIDResponse, error) {
	if s.getControlCardVendorIDErr != nil {
		return nil, s.getControlCardVendorIDErr
	}
	return &epb.GetControlCardVendorIDResponse{
		ControlCardId: &cpb.ControlCardVendorId{
			ChassisSerialNumber: "test-serial",
			ChassisManufacturer: "test-manufacturer",
		},
	}, nil
}

func (s *stubVerifyIdentityWithHMACChallengeInfraDeps) FetchEK(ctx context.Context, req *FetchEKReq) (*FetchEKResp, error) {
	if s.fetchEKErr != nil {
		return nil, s.fetchEKErr
	}
	return &FetchEKResp{EkPublicKey: &rsa.PublicKey{}, KeyType: epb.Key_KEY_EK}, nil
}

func (s *stubVerifyIdentityWithHMACChallengeInfraDeps) GenerateRestrictedHMACKey() (*tpm20.TPMTPublic, *tpm20.TPMTSensitive, error) {
	pub := validTPMTPublic
	return &pub, &tpm20.TPMTSensitive{}, nil
}

func (s *stubVerifyIdentityWithHMACChallengeInfraDeps) WrapHMACKeytoRSAPublicKey(rsaPub *rsa.PublicKey, hmacPub *tpm20.TPMTPublic, hmacSensitive *tpm20.TPMTSensitive) ([]byte, []byte, error) {
	if s.wrapHMACKeytoRSAPublicKeyErr != nil {
		return nil, nil, s.wrapHMACKeytoRSAPublicKeyErr
	}
	return []byte("duplicate"), []byte("inSymSeed"), nil
}

func (s *stubVerifyIdentityWithHMACChallengeInfraDeps) Challenge(ctx context.Context, req *epb.ChallengeRequest) (*epb.ChallengeResponse, error) {
	if s.challengeErr != nil {
		return nil, s.challengeErr
	}
	iakPub := validTPMTPublic
	iakCertifyInfo := validTPMSAttest
	return &epb.ChallengeResponse{
		ChallengeResp: &epb.HMACChallengeResponse{
			IakPub:                  tpm20.Marshal(&iakPub),
			IakCertifyInfo:          tpm20.Marshal(&iakCertifyInfo),
			IakCertifyInfoSignature: []byte{},
		},
	}, nil
}

func (s *stubVerifyIdentityWithHMACChallengeInfraDeps) VerifyHMAC(message []byte, signature []byte, hmacSensitive *tpm20.TPMTSensitive) error {
	return s.verifyHMACErr
}

func (s *stubVerifyIdentityWithHMACChallengeInfraDeps) VerifyCertifyInfo(certifyInfo *tpm20.TPMSAttest, certifiedKey *tpm20.TPMTPublic) error {
	return s.verifyCertifyInfoErr
}

func (s *stubVerifyIdentityWithHMACChallengeInfraDeps) VerifyIAKAttributes(iakPub []byte) (*tpm20.TPMTPublic, error) {
	return &tpm20.TPMTPublic{}, s.verifyIAKAttributesErr
}

func (s *stubVerifyIdentityWithHMACChallengeInfraDeps) GetIdevidCsr(ctx context.Context, req *epb.GetIdevidCsrRequest) (*epb.GetIdevidCsrResponse, error) {
	if s.getIdevidCsrErr != nil {
		return nil, s.getIdevidCsrErr
	}
	idevidSignatureCsr := validTPMTSignature
	return &epb.GetIdevidCsrResponse{
		CsrResponse: &epb.CsrResponse{
			CsrContents:        []byte("csr-contents"),
			IdevidSignatureCsr: tpm20.Marshal(&idevidSignatureCsr),
		},
	}, nil
}

func (s *stubVerifyIdentityWithHMACChallengeInfraDeps) ParseTCGCSRIDevIDContent(csrBytes []byte) (*TCGCSRIDevIDContents, error) {
	if s.parseTCGCSRIDevIDContentErr != nil {
		return nil, s.parseTCGCSRIDevIDContentErr
	}
	csrContents := TCGCSRIDevIDContents{
		IDevIDPub:                validTPMTPublic,
		SignCertifyInfo:          validTPMSAttest,
		SignCertifyInfoSignature: validTPMTSignature,
	}
	return &csrContents, nil
}
func (s *stubVerifyIdentityWithHMACChallengeInfraDeps) VerifyTPMTSignature(data []byte, signature *tpm20.TPMTSignature, pubKey *tpm20.TPMTPublic) error {
	return s.verifyTPMTSignatureErr
}

func (s *stubVerifyIdentityWithHMACChallengeInfraDeps) VerifyIdevidAttributes(idevidPub *tpm20.TPMTPublic, keyTemplate epb.KeyTemplate) error {
	return s.verifyIDevIDAttributesErr
}

func TestVerifyIdentityWithHMACChallenge(t *testing.T) {
	controlCardSelection := &cpb.ControlCardSelection{
		ControlCardId: &cpb.ControlCardSelection_Role{
			Role: cpb.ControlCardRole_CONTROL_CARD_ROLE_ACTIVE,
		},
	}
	errorResp := errors.New("some error")

	tests := []struct {
		desc                         string
		wantErr                      error
		getControlCardVendorIDErr    error
		fetchEKErr                   error
		wrapHMACKeytoRSAPublicKeyErr error
		challengeErr                 error
		verifyHMACErr                error
		verifyCertifyInfoErr         error
		verifyIAKAttributesErr       error
		getIdevidCsrErr              error
		parseTCGCSRIDevIDContentErr  error
		verifyTPMTSignatureErr       error
		verifyIDevIDAttributesErr    error
	}{
		{
			desc: "Successful verification",
		},
		{
			desc:                      "GetControlCardVendorID error",
			getControlCardVendorIDErr: errorResp,
			wantErr:                   errorResp,
		},
		{
			desc:       "FetchEK error",
			fetchEKErr: errorResp,
			wantErr:    errorResp,
		},
		{
			desc:                         "WrapHMACKeytoRSAPublicKey error",
			wrapHMACKeytoRSAPublicKeyErr: errorResp,
			wantErr:                      errorResp,
		},
		{
			desc:         "Challenge error",
			challengeErr: errorResp,
			wantErr:      errorResp,
		},
		{
			desc:          "VerifyHMAC error",
			verifyHMACErr: errorResp,
			wantErr:       errorResp,
		},
		{
			desc:                 "VerifyCertifyInfo error",
			verifyCertifyInfoErr: errorResp,
			wantErr:              errorResp,
		},
		{
			desc:                   "VerifyIAKAttributes error",
			verifyIAKAttributesErr: errorResp,
			wantErr:                errorResp,
		},
		{
			desc:            "GetIdevidCsr error",
			getIdevidCsrErr: errorResp,
			wantErr:         errorResp,
		},
		{
			desc:                        "ParseTCGCSRIDevIDContent error",
			parseTCGCSRIDevIDContentErr: errorResp,
			wantErr:                     errorResp,
		},
		{
			desc:                   "VerifyTPMTSignature error",
			verifyTPMTSignatureErr: errorResp,
			wantErr:                errorResp,
		},
		{
			desc:                      "VerifyIDevIDAttributes error",
			verifyIDevIDAttributesErr: errorResp,
			wantErr:                   errorResp,
		},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			deps := &stubVerifyIdentityWithHMACChallengeInfraDeps{
				getControlCardVendorIDErr:    tc.getControlCardVendorIDErr,
				fetchEKErr:                   tc.fetchEKErr,
				wrapHMACKeytoRSAPublicKeyErr: tc.wrapHMACKeytoRSAPublicKeyErr,
				challengeErr:                 tc.challengeErr,
				verifyHMACErr:                tc.verifyHMACErr,
				verifyCertifyInfoErr:         tc.verifyCertifyInfoErr,
				verifyIAKAttributesErr:       tc.verifyIAKAttributesErr,
				getIdevidCsrErr:              tc.getIdevidCsrErr,
				parseTCGCSRIDevIDContentErr:  tc.parseTCGCSRIDevIDContentErr,
				verifyTPMTSignatureErr:       tc.verifyTPMTSignatureErr,
				verifyIDevIDAttributesErr:    tc.verifyIDevIDAttributesErr,
			}
			_, _, _, err := verifyIdentityWithHMACChallenge(context.Background(), controlCardSelection, deps)
			if tc.wantErr != nil {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr.Error()) {
					t.Errorf("VerifyIdentityWithHmacChallenge() returned unexpected error: got %v, want %v", err, tc.wantErr)
				}
			} else if err != nil {
				t.Errorf("VerifyIdentityWithHmacChallenge() returned unexpected error: %v", err)
			}
		})
	}
}

func TestIssueOwnerIakCert(t *testing.T) {
	// Constants to be used in request params and stubbing.
	vendorID := &cpb.ControlCardVendorId{
		ControlCardSerial:   "Some card serial",
		ChassisManufacturer: "Some manufacturer",
		ChassisSerialNumber: "Some chassis serial",
	}
	iakPubPem := "Some IAK pub PEM"
	ownerIakCertPem := "Some Owner IAK cert PEM"
	errorResp := errors.New("some error from CA")

	tests := []struct {
		desc                string
		certData            ControlCardCertData
		stubbedResp         *IssueOwnerIakCertResp
		stubbedErr          error
		wantReq             *IssueOwnerIakCertReq
		wantOwnerIakCertPem string
		wantErr             error
	}{
		{
			desc: "Successful certificate issuance",
			certData: ControlCardCertData{
				ControlCardID: vendorID,
				IAKPubPem:     iakPubPem,
			},
			stubbedResp: &IssueOwnerIakCertResp{
				OwnerIakCertPem: ownerIakCertPem,
			},
			wantReq: &IssueOwnerIakCertReq{
				CardID:    vendorID,
				IakPubPem: iakPubPem,
			},
			wantOwnerIakCertPem: ownerIakCertPem,
		},
		{
			desc: "Failure in Switch Owner CA",
			certData: ControlCardCertData{
				ControlCardID: vendorID,
				IAKPubPem:     iakPubPem,
			},
			stubbedErr: errorResp,
			wantReq: &IssueOwnerIakCertReq{
				CardID:    vendorID,
				IakPubPem: iakPubPem,
			},
			wantErr: ErrFailedToIssueOwnerCert,
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			var resps []*IssueOwnerIakCertResp
			if test.stubbedResp != nil {
				resps = []*IssueOwnerIakCertResp{test.stubbedResp}
			}
			stub := &stubEnrollzInfraDeps{
				issueOwnerIakCertResps: resps,
				errorResp:              test.stubbedErr,
			}

			ctx := context.Background()
			gotOwnerIakCertPem, gotErr := issueOwnerIakCert(ctx, stub, test.certData)
			if !errors.Is(gotErr, test.wantErr) {
				t.Errorf("issueOwnerIakCert() got error %v, want error %v", gotErr, test.wantErr)
			}
			if gotOwnerIakCertPem != test.wantOwnerIakCertPem {
				t.Errorf("issueOwnerIakCert() got cert %q, want %q", gotOwnerIakCertPem, test.wantOwnerIakCertPem)
			}
			var wantReqs []*IssueOwnerIakCertReq
			if test.wantReq != nil {
				wantReqs = []*IssueOwnerIakCertReq{test.wantReq}
			}
			if diff := cmp.Diff(wantReqs, stub.issueOwnerIakCertReqs, protocmp.Transform()); diff != "" {
				t.Errorf("issueOwnerIakCert() sent unexpected request to SwitchOwnerCaClient: (-want +got)\n%s", diff)
			}
		})
	}
}

func TestIssueOwnerIDevIDCert(t *testing.T) {
	// Constants to be used in request params and stubbing.
	vendorID := &cpb.ControlCardVendorId{
		ControlCardSerial:   "Some card serial",
		ChassisManufacturer: "Some manufacturer",
		ChassisSerialNumber: "Some chassis serial",
	}
	iDevIDPubPem := "Some IDevID pub PEM"
	ownerIDevIDCertPem := "Some Owner IDevID cert PEM"
	sslProfileID := "Some SSL profile ID"
	errorResp := errors.New("some error from CA")

	tests := []struct {
		desc                   string
		certData               ControlCardCertData
		sslProfileID           string
		skipOidevidRotate      bool
		stubbedResp            *IssueOwnerIDevIDCertResp
		stubbedErr             error
		wantReq                *IssueOwnerIDevIDCertReq
		wantOwnerIDevIDCertPem string
		wantErr                error
	}{
		{
			desc: "Successful certificate issuance",
			certData: ControlCardCertData{
				ControlCardID: vendorID,
				IDevIDPubPem:  iDevIDPubPem,
			},
			sslProfileID:      sslProfileID,
			skipOidevidRotate: false,
			stubbedResp: &IssueOwnerIDevIDCertResp{
				OwnerIDevIDCertPem: ownerIDevIDCertPem,
			},
			wantReq: &IssueOwnerIDevIDCertReq{
				CardID:       vendorID,
				IDevIDPubPem: iDevIDPubPem,
			},
			wantOwnerIDevIDCertPem: ownerIDevIDCertPem,
		},
		{
			desc: "skipOidevidRotate is true",
			certData: ControlCardCertData{
				ControlCardID: vendorID,
				IDevIDPubPem:  iDevIDPubPem,
			},
			sslProfileID:      sslProfileID,
			skipOidevidRotate: true,
		},
		{
			desc: "IDevIDPubPem is empty",
			certData: ControlCardCertData{
				ControlCardID: vendorID,
			},
			sslProfileID:      sslProfileID,
			skipOidevidRotate: false,
		},
		{
			desc: "sslProfileID is empty",
			certData: ControlCardCertData{
				ControlCardID: vendorID,
				IDevIDPubPem:  iDevIDPubPem,
			},
			skipOidevidRotate: false,
			wantErr:           ErrEmptyField,
		},
		{
			desc: "Failure in Switch Owner CA",
			certData: ControlCardCertData{
				ControlCardID: vendorID,
				IDevIDPubPem:  iDevIDPubPem,
			},
			sslProfileID:      sslProfileID,
			skipOidevidRotate: false,
			stubbedErr:        errorResp,
			wantReq: &IssueOwnerIDevIDCertReq{
				CardID:       vendorID,
				IDevIDPubPem: iDevIDPubPem,
			},
			wantErr: ErrFailedToIssueOwnerCert,
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			var resps []*IssueOwnerIDevIDCertResp
			if test.stubbedResp != nil {
				resps = []*IssueOwnerIDevIDCertResp{test.stubbedResp}
			}
			stub := &stubEnrollzInfraDeps{
				issueOwnerIDevIDCertResps: resps,
				errorResp:                 test.stubbedErr,
			}

			ctx := context.Background()
			gotOwnerIDevIDCertPem, gotErr := issueOwnerIDevIDCert(ctx, stub, test.certData, test.sslProfileID, test.skipOidevidRotate)
			if !errors.Is(gotErr, test.wantErr) {
				t.Errorf("issueOwnerIDevIDCert() got error %v, want error %v", gotErr, test.wantErr)
			}
			if gotOwnerIDevIDCertPem != test.wantOwnerIDevIDCertPem {
				t.Errorf("issueOwnerIDevIDCert() got cert %q, want %q", gotOwnerIDevIDCertPem, test.wantOwnerIDevIDCertPem)
			}
			var wantReqs []*IssueOwnerIDevIDCertReq
			if test.wantReq != nil {
				wantReqs = []*IssueOwnerIDevIDCertReq{test.wantReq}
			}
			if diff := cmp.Diff(wantReqs, stub.issueOwnerIDevIDCertReqs, protocmp.Transform()); diff != "" {
				t.Errorf("issueOwnerIDevIDCert() sent unexpected request to SwitchOwnerCaClient: (-want +got)\n%s", diff)
			}
		})
	}
}

func TestRotateOIakCert(t *testing.T) {
	// Constants to be used in request params and stubbing.
	controlCardSelection1 := &cpb.ControlCardSelection{
		ControlCardId: &cpb.ControlCardSelection_Role{
			Role: cpb.ControlCardRole_CONTROL_CARD_ROLE_ACTIVE,
		},
	}
	controlCardSelection2 := &cpb.ControlCardSelection{
		ControlCardId: &cpb.ControlCardSelection_Role{
			Role: cpb.ControlCardRole_CONTROL_CARD_ROLE_STANDBY,
		},
	}
	sslProfileID := "Some SSL profile ID"
	oIakCert1 := "Some Owner IAK cert PEM 1"
	oIdevIDCert1 := "Some Owner IDevID cert PEM 1"
	oIakCert2 := "Some Owner IAK cert PEM 2"
	oIdevIDCert2 := "Some Owner IDevID cert PEM 2"
	errorResp := errors.New("some error")

	tests := []struct {
		desc                        string
		atomicCertRotationSupported bool
		controlCardCerts            []*epb.ControlCardCertUpdate
		wantReqs                    []*epb.RotateOIakCertRequest
		mockErrs                    []error
		wantErr                     error
	}{
		{
			desc:                        "Successful atomic rotation (multiple cards)",
			atomicCertRotationSupported: true,
			controlCardCerts: []*epb.ControlCardCertUpdate{
				{
					ControlCardSelection: controlCardSelection1,
					OiakCert:             oIakCert1,
					OidevidCert:          oIdevIDCert1,
				},
				{
					ControlCardSelection: controlCardSelection2,
					OiakCert:             oIakCert2,
					OidevidCert:          oIdevIDCert2,
				},
			},
			wantReqs: []*epb.RotateOIakCertRequest{
				{
					SslProfileId: sslProfileID,
					Updates: []*epb.ControlCardCertUpdate{
						{
							ControlCardSelection: controlCardSelection1,
							OiakCert:             oIakCert1,
							OidevidCert:          oIdevIDCert1,
						},
						{
							ControlCardSelection: controlCardSelection2,
							OiakCert:             oIakCert2,
							OidevidCert:          oIdevIDCert2,
						},
					},
				},
			},
			mockErrs: []error{nil},
		},
		{
			desc:                        "Successful non-atomic rotation (multiple cards)",
			atomicCertRotationSupported: false,
			controlCardCerts: []*epb.ControlCardCertUpdate{
				{
					ControlCardSelection: controlCardSelection1,
					OiakCert:             oIakCert1,
					OidevidCert:          oIdevIDCert1,
				},
				{
					ControlCardSelection: controlCardSelection2,
					OiakCert:             oIakCert2,
					OidevidCert:          oIdevIDCert2,
				},
			},
			wantReqs: []*epb.RotateOIakCertRequest{
				{
					SslProfileId:         sslProfileID,
					ControlCardSelection: controlCardSelection1,
					OiakCert:             oIakCert1,
					OidevidCert:          oIdevIDCert1,
				},
				{
					SslProfileId:         sslProfileID,
					ControlCardSelection: controlCardSelection2,
					OiakCert:             oIakCert2,
					OidevidCert:          oIdevIDCert2,
				},
			},
			mockErrs: []error{nil, nil},
		},
		{
			desc:                        "Successful non-atomic rotation (single card)",
			atomicCertRotationSupported: false,
			controlCardCerts: []*epb.ControlCardCertUpdate{
				{
					ControlCardSelection: controlCardSelection1,
					OiakCert:             oIakCert1,
					OidevidCert:          oIdevIDCert1,
				},
			},
			wantReqs: []*epb.RotateOIakCertRequest{
				{
					SslProfileId:         sslProfileID,
					ControlCardSelection: controlCardSelection1,
					OiakCert:             oIakCert1,
					OidevidCert:          oIdevIDCert1,
				},
			},
			mockErrs: []error{nil},
		},
		{
			desc:                        "Atomic rotation failure (multiple cards)",
			atomicCertRotationSupported: true,
			controlCardCerts: []*epb.ControlCardCertUpdate{
				{
					ControlCardSelection: controlCardSelection1,
					OiakCert:             oIakCert1,
					OidevidCert:          oIdevIDCert1,
				},
				{
					ControlCardSelection: controlCardSelection2,
					OiakCert:             oIakCert2,
					OidevidCert:          oIdevIDCert2,
				},
			},
			wantReqs: []*epb.RotateOIakCertRequest{
				{
					SslProfileId: sslProfileID,
					Updates: []*epb.ControlCardCertUpdate{
						{
							ControlCardSelection: controlCardSelection1,
							OiakCert:             oIakCert1,
							OidevidCert:          oIdevIDCert1,
						},
						{
							ControlCardSelection: controlCardSelection2,
							OiakCert:             oIakCert2,
							OidevidCert:          oIdevIDCert2,
						},
					},
				},
			},
			mockErrs: []error{errorResp},
			wantErr:  ErrRotateOIakCert,
		},
		{
			desc:                        "Non-atomic rotation failure on first card (multiple cards)",
			atomicCertRotationSupported: false,
			controlCardCerts: []*epb.ControlCardCertUpdate{
				{
					ControlCardSelection: controlCardSelection1,
					OiakCert:             oIakCert1,
					OidevidCert:          oIdevIDCert1,
				},
				{
					ControlCardSelection: controlCardSelection2,
					OiakCert:             oIakCert2,
					OidevidCert:          oIdevIDCert2,
				},
			},
			wantReqs: []*epb.RotateOIakCertRequest{
				{
					SslProfileId:         sslProfileID,
					ControlCardSelection: controlCardSelection1,
					OiakCert:             oIakCert1,
					OidevidCert:          oIdevIDCert1,
				},
			},
			mockErrs: []error{errorResp},
			wantErr:  ErrRotateOIakCert,
		},
		{
			desc:                        "Non-atomic rotation failure on second card (multiple cards)",
			atomicCertRotationSupported: false,
			controlCardCerts: []*epb.ControlCardCertUpdate{
				{
					ControlCardSelection: controlCardSelection1,
					OiakCert:             oIakCert1,
					OidevidCert:          oIdevIDCert1,
				},
				{
					ControlCardSelection: controlCardSelection2,
					OiakCert:             oIakCert2,
					OidevidCert:          oIdevIDCert2,
				},
			},
			wantReqs: []*epb.RotateOIakCertRequest{
				{
					SslProfileId:         sslProfileID,
					ControlCardSelection: controlCardSelection1,
					OiakCert:             oIakCert1,
					OidevidCert:          oIdevIDCert1,
				},
				{
					SslProfileId:         sslProfileID,
					ControlCardSelection: controlCardSelection2,
					OiakCert:             oIakCert2,
					OidevidCert:          oIdevIDCert2,
				},
			},
			mockErrs: []error{nil, errorResp},
			wantErr:  ErrRotateOIakCert,
		},
		{
			desc:                        "Non-atomic rotation failure (single card)",
			atomicCertRotationSupported: false,
			controlCardCerts: []*epb.ControlCardCertUpdate{
				{
					ControlCardSelection: controlCardSelection1,
					OiakCert:             oIakCert1,
					OidevidCert:          oIdevIDCert1,
				},
			},
			wantReqs: []*epb.RotateOIakCertRequest{
				{
					SslProfileId:         sslProfileID,
					ControlCardSelection: controlCardSelection1,
					OiakCert:             oIakCert1,
					OidevidCert:          oIdevIDCert1,
				},
			},
			mockErrs: []error{errorResp},
			wantErr:  ErrRotateOIakCert,
		},
		{
			desc:                        "Empty control card cert data list",
			atomicCertRotationSupported: true,
			controlCardCerts:            []*epb.ControlCardCertUpdate{},
			wantErr:                     ErrEmptyField,
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			stub := &stubEnrollzInfraDeps{}
			stub.rotateOIakCertErrs = test.mockErrs
			// Populate responses.
			for i := 0; i < len(test.wantReqs)+len(test.mockErrs); i++ {
				stub.rotateOIakCertResps = append(stub.rotateOIakCertResps, &epb.RotateOIakCertResponse{})
			}

			ctx := context.Background()
			gotErr := rotateOIakCert(ctx, stub, sslProfileID, test.controlCardCerts, test.atomicCertRotationSupported)

			if !errors.Is(gotErr, test.wantErr) {
				t.Errorf("rotateOIakCert() got error %v, want error %v", gotErr, test.wantErr)
			}

			if diff := cmp.Diff(test.wantReqs, stub.rotateOIakCertReqs, protocmp.Transform()); diff != "" {
				t.Errorf("rotateOIakCert() sent unexpected requests: (-want +got)\n%s", diff)
			}
		})
	}
}

func TestIssueAndRotateOwnerCerts(t *testing.T) {
	controlCardSelection1 := &cpb.ControlCardSelection{
		ControlCardId: &cpb.ControlCardSelection_Role{
			Role: cpb.ControlCardRole_CONTROL_CARD_ROLE_ACTIVE,
		},
	}
	controlCardSelection2 := &cpb.ControlCardSelection{
		ControlCardId: &cpb.ControlCardSelection_Role{
			Role: cpb.ControlCardRole_CONTROL_CARD_ROLE_STANDBY,
		},
	}
	vendorID1 := &cpb.ControlCardVendorId{
		ControlCardRole:   controlCardSelection1.GetRole(),
		ControlCardSerial: "Serial1",
	}
	vendorID2 := &cpb.ControlCardVendorId{
		ControlCardRole:   controlCardSelection2.GetRole(),
		ControlCardSerial: "Serial2",
	}
	iakPubPem1 := "IAK Pub PEM 1"
	iDevIDPubPem1 := "IDevID Pub PEM 1"
	iakPubPem2 := "IAK Pub PEM 2"
	iDevIDPubPem2 := "IDevID Pub PEM 2"
	oIakCert1 := "Owner IAK cert PEM 1"
	oIdevIDCert1 := "Owner IDevID cert PEM 1"
	oIakCert2 := "Owner IAK cert PEM 2"
	oIdevIDCert2 := "Owner IDevID cert PEM 2"
	sslProfileID := "Some SSL profile ID"
	errorResp := errors.New("some error")

	tests := []struct {
		desc                        string
		cardDataList                []ControlCardCertData
		sslProfileID                string
		skipOidevidRotate           bool
		atomicCertRotationSupported bool
		deps                        EnrollzInfraDeps
		mockIssueOwnerIakCertErrs   []error
		mockIssueOwnerIDevIDErrs    []error
		mockRotateOIakCertErrs      []error
		wantErr                     error
		wantNumIssueOwnerIakCert    int
		wantNumIssueOwnerIDevIDCert int
		wantRotateOIakCertReqs      []*epb.RotateOIakCertRequest
	}{
		{
			desc: "Successful atomic rotation (multiple cards)",
			cardDataList: []ControlCardCertData{
				{
					ControlCardSelections: controlCardSelection1,
					ControlCardID:         vendorID1,
					IAKPubPem:             iakPubPem1,
					IDevIDPubPem:          iDevIDPubPem1,
				},
				{
					ControlCardSelections: controlCardSelection2,
					ControlCardID:         vendorID2,
					IAKPubPem:             iakPubPem2,
					IDevIDPubPem:          iDevIDPubPem2,
				},
			},
			sslProfileID:                sslProfileID,
			atomicCertRotationSupported: true,
			deps:                        &stubEnrollzInfraDeps{},
			wantNumIssueOwnerIakCert:    2,
			wantNumIssueOwnerIDevIDCert: 2,
			wantRotateOIakCertReqs: []*epb.RotateOIakCertRequest{
				{
					SslProfileId: sslProfileID,
					Updates: []*epb.ControlCardCertUpdate{
						{
							ControlCardSelection: controlCardSelection1,
							OiakCert:             oIakCert1,
							OidevidCert:          oIdevIDCert1,
						},
						{
							ControlCardSelection: controlCardSelection2,
							OiakCert:             oIakCert2,
							OidevidCert:          oIdevIDCert2,
						},
					},
				},
			},
		},
		{
			desc: "Successful non-atomic rotation (multiple cards)",
			cardDataList: []ControlCardCertData{
				{
					ControlCardSelections: controlCardSelection1,
					ControlCardID:         vendorID1,
					IAKPubPem:             iakPubPem1,
					IDevIDPubPem:          iDevIDPubPem1,
				},
				{
					ControlCardSelections: controlCardSelection2,
					ControlCardID:         vendorID2,
					IAKPubPem:             iakPubPem2,
					IDevIDPubPem:          iDevIDPubPem2,
				},
			},
			sslProfileID:                sslProfileID,
			atomicCertRotationSupported: false,
			deps:                        &stubEnrollzInfraDeps{},
			wantNumIssueOwnerIakCert:    2,
			wantNumIssueOwnerIDevIDCert: 2,
			wantRotateOIakCertReqs: []*epb.RotateOIakCertRequest{
				{
					SslProfileId:         sslProfileID,
					ControlCardSelection: controlCardSelection1,
					OiakCert:             oIakCert1,
					OidevidCert:          oIdevIDCert1,
				},
				{
					SslProfileId:         sslProfileID,
					ControlCardSelection: controlCardSelection2,
					OiakCert:             oIakCert2,
					OidevidCert:          oIdevIDCert2,
				},
			},
		},
		{
			desc:         "Empty card data list",
			cardDataList: []ControlCardCertData{},
			deps:         &stubEnrollzInfraDeps{},
			wantErr:      ErrEmptyField,
		},
		{
			desc:         "Nil deps",
			cardDataList: []ControlCardCertData{{}},
			deps:         nil,
			wantErr:      ErrEmptyField,
		},
		{
			desc: "Missing ControlCardID",
			cardDataList: []ControlCardCertData{
				{
					ControlCardSelections: controlCardSelection1,
					IAKPubPem:             iakPubPem1,
				},
			},
			deps:    &stubEnrollzInfraDeps{},
			wantErr: ErrEmptyField,
		},
		{
			desc: "Missing ControlCardSelections",
			cardDataList: []ControlCardCertData{
				{
					ControlCardID: vendorID1,
					IAKPubPem:     iakPubPem1,
				},
			},
			deps:    &stubEnrollzInfraDeps{},
			wantErr: ErrEmptyField,
		},
		{
			desc: "Missing IAKPubPem",
			cardDataList: []ControlCardCertData{
				{
					ControlCardSelections: controlCardSelection1,
					ControlCardID:         vendorID1,
				},
			},
			deps:    &stubEnrollzInfraDeps{},
			wantErr: ErrEmptyField,
		},
		{
			desc: "Issue oIDevID cert fails",
			cardDataList: []ControlCardCertData{
				{
					ControlCardSelections: controlCardSelection1,
					ControlCardID:         vendorID1,
					IAKPubPem:             iakPubPem1,
					IDevIDPubPem:          iDevIDPubPem1,
				},
			},
			sslProfileID:                sslProfileID,
			deps:                        &stubEnrollzInfraDeps{},
			mockIssueOwnerIDevIDErrs:    []error{errorResp},
			wantErr:                     ErrFailedToIssueOwnerCert,
			wantNumIssueOwnerIDevIDCert: 1,
		},
		{
			desc: "Issue oIAK cert fails",
			cardDataList: []ControlCardCertData{
				{
					ControlCardSelections: controlCardSelection1,
					ControlCardID:         vendorID1,
					IAKPubPem:             iakPubPem1,
					IDevIDPubPem:          iDevIDPubPem1,
				},
			},
			sslProfileID:                sslProfileID,
			deps:                        &stubEnrollzInfraDeps{},
			mockIssueOwnerIakCertErrs:   []error{errorResp},
			wantErr:                     ErrFailedToIssueOwnerCert,
			wantNumIssueOwnerIakCert:    1,
			wantNumIssueOwnerIDevIDCert: 1,
		},
		{
			desc: "Rotate cert fails",
			cardDataList: []ControlCardCertData{
				{
					ControlCardSelections: controlCardSelection1,
					ControlCardID:         vendorID1,
					IAKPubPem:             iakPubPem1,
					IDevIDPubPem:          iDevIDPubPem1,
				},
			},
			sslProfileID:                sslProfileID,
			atomicCertRotationSupported: true,
			deps:                        &stubEnrollzInfraDeps{},
			mockRotateOIakCertErrs:      []error{errorResp},
			wantErr:                     ErrRotateOIakCert,
			wantNumIssueOwnerIakCert:    1,
			wantNumIssueOwnerIDevIDCert: 1,
			wantRotateOIakCertReqs: []*epb.RotateOIakCertRequest{
				{
					SslProfileId: sslProfileID,
					Updates: []*epb.ControlCardCertUpdate{
						{
							ControlCardSelection: controlCardSelection1,
							OiakCert:             oIakCert1,
							OidevidCert:          oIdevIDCert1,
						},
					},
				},
			},
		},
		{
			desc: "Issue oIAK cert fails on second card (multiple cards)",
			cardDataList: []ControlCardCertData{
				{
					ControlCardSelections: controlCardSelection1,
					ControlCardID:         vendorID1,
					IAKPubPem:             iakPubPem1,
					IDevIDPubPem:          iDevIDPubPem1,
				},
				{
					ControlCardSelections: controlCardSelection2,
					ControlCardID:         vendorID2,
					IAKPubPem:             iakPubPem2,
					IDevIDPubPem:          iDevIDPubPem2,
				},
			},
			sslProfileID:                sslProfileID,
			deps:                        &stubEnrollzInfraDeps{},
			mockIssueOwnerIakCertErrs:   []error{nil, errorResp},
			wantErr:                     ErrFailedToIssueOwnerCert,
			wantNumIssueOwnerIakCert:    2,
			wantNumIssueOwnerIDevIDCert: 2,
		},
		{
			desc: "Issue oIDevID cert fails on second card (multiple cards)",
			cardDataList: []ControlCardCertData{
				{
					ControlCardSelections: controlCardSelection1,
					ControlCardID:         vendorID1,
					IAKPubPem:             iakPubPem1,
					IDevIDPubPem:          iDevIDPubPem1,
				},
				{
					ControlCardSelections: controlCardSelection2,
					ControlCardID:         vendorID2,
					IAKPubPem:             iakPubPem2,
					IDevIDPubPem:          iDevIDPubPem2,
				},
			},
			sslProfileID:                sslProfileID,
			deps:                        &stubEnrollzInfraDeps{},
			mockIssueOwnerIDevIDErrs:    []error{nil, errorResp},
			wantErr:                     ErrFailedToIssueOwnerCert,
			wantNumIssueOwnerIakCert:    1,
			wantNumIssueOwnerIDevIDCert: 2,
		},
		{
			desc: "Non-atomic rotate cert fails on second card (multiple cards)",
			cardDataList: []ControlCardCertData{
				{
					ControlCardSelections: controlCardSelection1,
					ControlCardID:         vendorID1,
					IAKPubPem:             iakPubPem1,
					IDevIDPubPem:          iDevIDPubPem1,
				},
				{
					ControlCardSelections: controlCardSelection2,
					ControlCardID:         vendorID2,
					IAKPubPem:             iakPubPem2,
					IDevIDPubPem:          iDevIDPubPem2,
				},
			},
			sslProfileID:                sslProfileID,
			atomicCertRotationSupported: false,
			deps:                        &stubEnrollzInfraDeps{},
			mockRotateOIakCertErrs:      []error{nil, errorResp},
			wantErr:                     ErrRotateOIakCert,
			wantNumIssueOwnerIakCert:    2,
			wantNumIssueOwnerIDevIDCert: 2,
			wantRotateOIakCertReqs: []*epb.RotateOIakCertRequest{
				{
					SslProfileId:         sslProfileID,
					ControlCardSelection: controlCardSelection1,
					OiakCert:             oIakCert1,
					OidevidCert:          oIdevIDCert1,
				},
				{
					SslProfileId:         sslProfileID,
					ControlCardSelection: controlCardSelection2,
					OiakCert:             oIakCert2,
					OidevidCert:          oIdevIDCert2,
				},
			},
		},
		{
			desc: "Skip oidevid rotate",
			cardDataList: []ControlCardCertData{
				{
					ControlCardSelections: controlCardSelection1,
					ControlCardID:         vendorID1,
					IAKPubPem:             iakPubPem1,
					IDevIDPubPem:          iDevIDPubPem1,
				},
			},
			sslProfileID:                sslProfileID,
			skipOidevidRotate:           true,
			atomicCertRotationSupported: true,
			deps:                        &stubEnrollzInfraDeps{},
			wantNumIssueOwnerIakCert:    1,
			wantNumIssueOwnerIDevIDCert: 0,
			wantRotateOIakCertReqs: []*epb.RotateOIakCertRequest{
				{
					SslProfileId: sslProfileID,
					Updates: []*epb.ControlCardCertUpdate{
						{
							ControlCardSelection: controlCardSelection1,
							OiakCert:             oIakCert1,
							OidevidCert:          "",
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			stub, ok := test.deps.(*stubEnrollzInfraDeps)
			if !ok && test.deps != nil {
				t.Fatalf("test.deps is not a *stubEnrollzInfraDeps")
			}

			if stub != nil {
				stub.issueOwnerIakCertErrs = test.mockIssueOwnerIakCertErrs
				stub.issueOwnerIDevIDCertErrs = test.mockIssueOwnerIDevIDErrs
				stub.rotateOIakCertErrs = test.mockRotateOIakCertErrs

				for _, cd := range test.cardDataList {
					iak := oIakCert2
					if cd.IAKPubPem == iakPubPem1 {
						iak = oIakCert1
					}
					stub.issueOwnerIakCertResps = append(stub.issueOwnerIakCertResps, &IssueOwnerIakCertResp{OwnerIakCertPem: iak})

					idev := oIdevIDCert2
					if cd.IDevIDPubPem == iDevIDPubPem1 {
						idev = oIdevIDCert1
					}
					stub.issueOwnerIDevIDCertResps = append(stub.issueOwnerIDevIDCertResps, &IssueOwnerIDevIDCertResp{OwnerIDevIDCertPem: idev})
				}

				// Populate RotateOIakCert responses.
				count := len(test.wantRotateOIakCertReqs) + len(test.mockRotateOIakCertErrs)
				for i := 0; i < count; i++ {
					stub.rotateOIakCertResps = append(stub.rotateOIakCertResps, &epb.RotateOIakCertResponse{})
				}
			}

			ctx := context.Background()
			gotErr := issueAndRotateOwnerCerts(ctx, test.deps, test.cardDataList, test.sslProfileID, test.skipOidevidRotate, test.atomicCertRotationSupported)

			if !errors.Is(gotErr, test.wantErr) {
				t.Errorf("IssueAndRotateOwnerCerts() got error %v, want error %v", gotErr, test.wantErr)
			}

			if stub != nil {
				if got, want := len(stub.issueOwnerIakCertReqs), test.wantNumIssueOwnerIakCert; got != want {
					t.Errorf("IssueAndRotateOwnerCerts() called IssueOwnerIakCert %d times, want %d", got, want)
				}
				if got, want := len(stub.issueOwnerIDevIDCertReqs), test.wantNumIssueOwnerIDevIDCert; got != want {
					t.Errorf("IssueAndRotateOwnerCerts() called IssueOwnerIDevIDCert %d times, want %d", got, want)
				}
				if diff := cmp.Diff(test.wantRotateOIakCertReqs, stub.rotateOIakCertReqs, protocmp.Transform()); diff != "" {
					t.Errorf("IssueAndRotateOwnerCerts() sent unexpected requests to RotateOIakCert: (-want +got)\n%s", diff)
				}
			}
		})
	}
}

// TODO: Add tests for  EnrollWithHMACChallenge, verifyIdentityWithVendorCerts, VerifyIdentityWithHMACChallenge, VerifyIAKKey and VerifyIdevidKey with test vectors
