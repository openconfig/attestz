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
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	tpm12 "github.com/google/go-tpm/tpm"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/testing/protocmp"

	cpb "github.com/openconfig/attestz/proto/common_definitions"
	epb "github.com/openconfig/attestz/proto/tpm_enrollz"
)

type stubEnrollzInfraDeps struct {
	SwitchOwnerCaClient
	EnrollzDeviceClient
	TpmCertVerifier

	// Request params that would be captured in stubbed deps' function calls.
	issueOwnerIakCertReq       *IssueOwnerIakCertReq
	issueOwnerIDevIDCertReq    *IssueOwnerIDevIDCertReq
	getIakCertReq              *epb.GetIakCertRequest
	rotateOIakCertReq          *epb.RotateOIakCertRequest
	verifyIakAndIDevIDCertsReq *VerifyIakAndIDevIDCertsReq
	verifyTpmCertReq           *VerifyTpmCertReq
	verifyNonceSignatureReq    *VerifyNonceSignatureReq

	// Stubbed responses to simulate behavior of deps without implementing them.
	issueOwnerIakCertResp       *IssueOwnerIakCertResp
	issueOwnerIDevIDCertResp    *IssueOwnerIDevIDCertResp
	getIakCertResp              *epb.GetIakCertResponse
	rotateOIakCertResp          *epb.RotateOIakCertResponse
	verifyIakAndIDevIDCertsResp *VerifyIakAndIDevIDCertsResp
	verifyTpmCertResp           *VerifyTpmCertResp
	verifyNonceSignatureResp    *VerifyNonceSignatureResp

	// If we need to simulate an error response from any of the deps, then set
	// the dep's response to nil and populate this error field.
	errorResp error
}

func (s *stubEnrollzInfraDeps) VerifyIakAndIDevIDCerts(ctx context.Context, req *VerifyIakAndIDevIDCertsReq) (*VerifyIakAndIDevIDCertsResp, error) {
	// Validate that no stub (captured) request params were set prior to execution.
	if s.verifyIakAndIDevIDCertsReq != nil {
		return nil, fmt.Errorf("VerifyIakAndIDevIDCerts unexpected req %+v", req)
	}
	s.verifyIakAndIDevIDCertsReq = req

	// If a stubbed response is not set, then return error, otherwise return the response.
	if s.verifyIakAndIDevIDCertsResp == nil {
		return nil, s.errorResp
	}
	return s.verifyIakAndIDevIDCertsResp, nil
}

func (s *stubEnrollzInfraDeps) VerifyTpmCert(ctx context.Context, req *VerifyTpmCertReq) (*VerifyTpmCertResp, error) {
	// Validate that no stub (captured) request params were set prior to execution.
	if s.verifyTpmCertReq != nil {
		return nil, fmt.Errorf("VerifyTpmCert unexpected req %+v", req)
	}
	s.verifyTpmCertReq = req

	// If a stubbed response is not set, then return error, otherwise return the response.
	if s.verifyTpmCertResp == nil {
		return nil, s.errorResp
	}
	return s.verifyTpmCertResp, nil
}

func (s *stubEnrollzInfraDeps) IssueOwnerIakCert(ctx context.Context, req *IssueOwnerIakCertReq) (*IssueOwnerIakCertResp, error) {
	// Validate that no stub (captured) request params were set prior to execution.
	if s.issueOwnerIakCertReq != nil {
		return nil, fmt.Errorf("IssueOwnerIakCert unexpected req %+v", s.issueOwnerIakCertReq)
	}
	s.issueOwnerIakCertReq = req

	// If a stubbed response is not set, then return error, otherwise return the response.
	if s.issueOwnerIakCertResp == nil {
		return nil, s.errorResp
	}
	return s.issueOwnerIakCertResp, nil
}

func (s *stubEnrollzInfraDeps) IssueOwnerIDevIDCert(ctx context.Context, req *IssueOwnerIDevIDCertReq) (*IssueOwnerIDevIDCertResp, error) {
	// Validate that no stub (captured) request params were set prior to execution.
	if s.issueOwnerIDevIDCertReq != nil {
		return nil, fmt.Errorf("IssueOwnerIDevIDCert unexpected req %+v", s.issueOwnerIDevIDCertReq)
	}
	s.issueOwnerIDevIDCertReq = req

	// If a stubbed response is not set, then return error, otherwise return the response.
	if s.issueOwnerIDevIDCertResp == nil {
		return nil, s.errorResp
	}
	return s.issueOwnerIDevIDCertResp, nil
}

func (s *stubEnrollzInfraDeps) GetIakCert(ctx context.Context, req *epb.GetIakCertRequest) (*epb.GetIakCertResponse, error) {
	// Validate that no stub (captured) request params were set prior to execution.
	if s.getIakCertReq != nil {
		return nil, fmt.Errorf("GetIakCert unexpected req %s", prototext.Format(s.getIakCertReq))
	}
	s.getIakCertReq = req

	// If a stubbed response is not set, then return error, otherwise return the response.
	if s.getIakCertResp == nil {
		return nil, s.errorResp
	}
	return s.getIakCertResp, nil
}

func (s *stubEnrollzInfraDeps) RotateOIakCert(ctx context.Context, req *epb.RotateOIakCertRequest) (*epb.RotateOIakCertResponse, error) {
	// Validate that no stub (captured) request params were set prior to execution.
	if s.rotateOIakCertReq != nil {
		return nil, fmt.Errorf("RotateOIakCert unexpected req %s", prototext.Format(s.rotateOIakCertReq))
	}
	s.rotateOIakCertReq = req

	// If a stubbed response is not set, then return error, otherwise return the response.
	if s.rotateOIakCertResp == nil {
		return nil, s.errorResp
	}
	return s.rotateOIakCertResp, nil
}

func (s *stubEnrollzInfraDeps) VerifyNonceSignature(ctx context.Context, req *VerifyNonceSignatureReq) (*VerifyNonceSignatureResp, error) {
	// Validate that no stub (captured) request params were set prior to execution.
	if s.verifyNonceSignatureReq != nil {
		return nil, fmt.Errorf("VerifyNonceSignature unexpected req %+v", req)
	}
	s.verifyNonceSignatureReq = req

	// If a stubbed response is not set, then return error, otherwise return the response.
	if s.verifyNonceSignatureResp == nil {
		return nil, s.errorResp
	}
	if !s.verifyNonceSignatureResp.IsValid {
		return s.verifyNonceSignatureResp, s.errorResp
	}
	return s.verifyNonceSignatureResp, nil
}

func TestEnrollControlCard(t *testing.T) {
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
	sslProfileID := "Some SSL profile ID"
	iakCert := "Some IAK cert PEM"
	iakPub := "Some IAK pub PEM"
	iDevIDCert := "Some IDevID cert PEM"
	iDevIDPub := "Some IDevID pub PEM"
	oIakCert := "Some Owner IAK cert PEM"
	oIdevIDCert := "Some Owner IDevID cert PEM"
	errorResp := errors.New("Some error")

	tests := []struct {
		// Test description.
		desc string
		// Overall expected EnrollControlCard response.
		wantErrResp error
		// Expected captured params to stubbed deps functions calls.
		wantGetIakCertReq              *epb.GetIakCertRequest
		wantIssueOwnerIakCertReq       *IssueOwnerIakCertReq
		wantIssueOwnerIDevIDCertReq    *IssueOwnerIDevIDCertReq
		wantRotateOIakCertReq          *epb.RotateOIakCertRequest
		wantVerifyIakAndIDevIDCertsReq *VerifyIakAndIDevIDCertsReq
		// Stubbed responses to EnrollzInfraDeps deps.
		issueOwnerIakCertResp       *IssueOwnerIakCertResp
		issueOwnerIDevIDCertResp    *IssueOwnerIDevIDCertResp
		getIakCertResp              *epb.GetIakCertResponse
		rotateOIakCertResp          *epb.RotateOIakCertResponse
		verifyIakAndIDevIDCertsResp *VerifyIakAndIDevIDCertsResp
	}{
		{
			desc: "Successful control card enrollment",
			// Stubbed deps called:
			// * GetIakCert => Success
			// * VerifyIakAndIDevIDCerts => Success
			// * IssueOwnerIakCert => Success
			// * IssueOwnerIDevIDCert => Success
			// * RotateOIakCert => Success
			getIakCertResp: &epb.GetIakCertResponse{
				ControlCardId: vendorID,
				IakCert:       iakCert,
				IdevidCert:    iDevIDCert,
			},
			verifyIakAndIDevIDCertsResp: &VerifyIakAndIDevIDCertsResp{
				IakPubPem:    iakPub,
				IDevIDPubPem: iDevIDPub,
			},
			issueOwnerIakCertResp:    &IssueOwnerIakCertResp{OwnerIakCertPem: oIakCert},
			issueOwnerIDevIDCertResp: &IssueOwnerIDevIDCertResp{OwnerIDevIDCertPem: oIdevIDCert},
			rotateOIakCertResp:       &epb.RotateOIakCertResponse{},
			// Expected params to all deps functions calls.
			wantGetIakCertReq: &epb.GetIakCertRequest{ControlCardSelection: controlCardSelection},
			wantVerifyIakAndIDevIDCertsReq: &VerifyIakAndIDevIDCertsReq{
				ControlCardID:        vendorID,
				IakCertPem:           iakCert,
				IDevIDCertPem:        iDevIDCert,
				CertVerificationOpts: certVerificationOpts,
			},
			wantIssueOwnerIakCertReq: &IssueOwnerIakCertReq{
				CardID:    vendorID,
				IakPubPem: iakPub,
			},
			wantIssueOwnerIDevIDCertReq: &IssueOwnerIDevIDCertReq{
				CardID:       vendorID,
				IDevIDPubPem: iDevIDPub,
			},
			wantRotateOIakCertReq: &epb.RotateOIakCertRequest{
				ControlCardSelection: controlCardSelection,
				OiakCert:             oIakCert,
				OidevidCert:          oIdevIDCert,
				SslProfileId:         sslProfileID,
			},
		},
		{
			desc:        "EnrollzDeviceClient.GetIakCert() failure causes overall EnrollControlCard failure",
			wantErrResp: errorResp,
			// Stubbed deps called:
			// * GetIakCert => Fail
			wantGetIakCertReq: &epb.GetIakCertRequest{ControlCardSelection: controlCardSelection},
		},
		{
			desc:        "TpmCertVerifier.VerifyIakAndIDevIDCerts() failure causes overall EnrollControlCard failure",
			wantErrResp: errorResp,
			// Stubbed deps called:
			// * GetIakCert => Success
			// * VerifyIakAndIDevIDCerts => Fail
			getIakCertResp: &epb.GetIakCertResponse{
				ControlCardId: vendorID,
				IakCert:       iakCert,
				IdevidCert:    iDevIDCert,
			},
			wantGetIakCertReq: &epb.GetIakCertRequest{ControlCardSelection: controlCardSelection},
			wantVerifyIakAndIDevIDCertsReq: &VerifyIakAndIDevIDCertsReq{
				ControlCardID:        vendorID,
				IakCertPem:           iakCert,
				IDevIDCertPem:        iDevIDCert,
				CertVerificationOpts: certVerificationOpts,
			},
		},
		{
			desc:        "SwitchOwnerCaClient.IssueOwnerIakCert() failure causes overall EnrollControlCard failure",
			wantErrResp: errorResp,
			// Stubbed deps called:
			// * GetIakCert => Success
			// * VerifyIakAndIDevIDCerts => Success
			// * IssueOwnerIakCert => Fail
			getIakCertResp: &epb.GetIakCertResponse{
				ControlCardId: vendorID,
				IakCert:       iakCert,
				IdevidCert:    iDevIDCert,
			},
			verifyIakAndIDevIDCertsResp: &VerifyIakAndIDevIDCertsResp{
				IakPubPem:    iakPub,
				IDevIDPubPem: iDevIDPub,
			},
			wantGetIakCertReq: &epb.GetIakCertRequest{ControlCardSelection: controlCardSelection},
			wantVerifyIakAndIDevIDCertsReq: &VerifyIakAndIDevIDCertsReq{
				ControlCardID:        vendorID,
				IakCertPem:           iakCert,
				IDevIDCertPem:        iDevIDCert,
				CertVerificationOpts: certVerificationOpts,
			},
			wantIssueOwnerIakCertReq: &IssueOwnerIakCertReq{
				CardID:    vendorID,
				IakPubPem: iakPub,
			},
		},
		{
			desc:        "SwitchOwnerCaClient.IssueOwnerIDevIDCert() failure causes overall EnrollControlCard failure",
			wantErrResp: errorResp,
			// Stubbed deps called:
			// * GetIakCert => Success
			// * VerifyIakAndIDevIDCerts => Success
			// * IssueOwnerIakCert => Success
			// * IssueOwnerIDevIDCert => Fail
			getIakCertResp: &epb.GetIakCertResponse{
				ControlCardId: vendorID,
				IakCert:       iakCert,
				IdevidCert:    iDevIDCert,
			},
			verifyIakAndIDevIDCertsResp: &VerifyIakAndIDevIDCertsResp{
				IakPubPem:    iakPub,
				IDevIDPubPem: iDevIDPub,
			},
			issueOwnerIakCertResp: &IssueOwnerIakCertResp{OwnerIakCertPem: oIakCert},
			wantGetIakCertReq:     &epb.GetIakCertRequest{ControlCardSelection: controlCardSelection},
			wantVerifyIakAndIDevIDCertsReq: &VerifyIakAndIDevIDCertsReq{
				ControlCardID:        vendorID,
				IakCertPem:           iakCert,
				IDevIDCertPem:        iDevIDCert,
				CertVerificationOpts: certVerificationOpts,
			},
			wantIssueOwnerIakCertReq: &IssueOwnerIakCertReq{
				CardID:    vendorID,
				IakPubPem: iakPub,
			},
			wantIssueOwnerIDevIDCertReq: &IssueOwnerIDevIDCertReq{
				CardID:       vendorID,
				IDevIDPubPem: iDevIDPub,
			},
		},
		{
			desc:        "EnrollzDeviceClient.RotateOIakCert() failure causes overall EnrollControlCard failure",
			wantErrResp: errorResp,
			// Stubbed deps called:
			// * GetIakCert => Success
			// * VerifyIakAndIDevIDCerts => Success
			// * IssueOwnerIakCert => Success
			// * IssueOwnerIDevIDCert => Success
			// * RotateOIakCert => Fail
			getIakCertResp: &epb.GetIakCertResponse{
				ControlCardId: vendorID,
				IakCert:       iakCert,
				IdevidCert:    iDevIDCert,
			},
			verifyIakAndIDevIDCertsResp: &VerifyIakAndIDevIDCertsResp{
				IakPubPem:    iakPub,
				IDevIDPubPem: iDevIDPub,
			},
			issueOwnerIakCertResp:    &IssueOwnerIakCertResp{OwnerIakCertPem: oIakCert},
			issueOwnerIDevIDCertResp: &IssueOwnerIDevIDCertResp{OwnerIDevIDCertPem: oIdevIDCert},
			wantGetIakCertReq:        &epb.GetIakCertRequest{ControlCardSelection: controlCardSelection},
			wantVerifyIakAndIDevIDCertsReq: &VerifyIakAndIDevIDCertsReq{
				ControlCardID:        vendorID,
				IakCertPem:           iakCert,
				IDevIDCertPem:        iDevIDCert,
				CertVerificationOpts: certVerificationOpts,
			},
			wantIssueOwnerIakCertReq: &IssueOwnerIakCertReq{
				CardID:    vendorID,
				IakPubPem: iakPub,
			},
			wantIssueOwnerIDevIDCertReq: &IssueOwnerIDevIDCertReq{
				CardID:       vendorID,
				IDevIDPubPem: iDevIDPub,
			},
			wantRotateOIakCertReq: &epb.RotateOIakCertRequest{
				ControlCardSelection: controlCardSelection,
				OiakCert:             oIakCert,
				OidevidCert:          oIdevIDCert,
				SslProfileId:         sslProfileID,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			stub := &stubEnrollzInfraDeps{
				getIakCertResp:              test.getIakCertResp,
				verifyIakAndIDevIDCertsResp: test.verifyIakAndIDevIDCertsResp,
				issueOwnerIakCertResp:       test.issueOwnerIakCertResp,
				issueOwnerIDevIDCertResp:    test.issueOwnerIDevIDCertResp,
				rotateOIakCertResp:          test.rotateOIakCertResp,
				errorResp:                   test.wantErrResp,
			}
			req := &EnrollControlCardReq{
				ControlCardSelection: controlCardSelection,
				CertVerificationOpts: certVerificationOpts,
				Deps:                 stub,
				SSLProfileID:         sslProfileID,
			}
			ctx := context.Background()
			got := EnrollControlCard(ctx, req)

			// Verify that EnrollControlCard returned expected error/no-error response.
			if test.wantErrResp != nil && test.wantErrResp != errors.Unwrap(got) {
				t.Errorf("Expected error response %v, but got error response %v", test.wantErrResp, errors.Unwrap(got))
			} else if test.wantErrResp == nil && got != nil {
				t.Errorf("Expected no-error response %v, but got error response %v", test.wantErrResp, got)
			}

			// Verify that all stubbed dependencies were called with the right params.
			if diff := cmp.Diff(stub.getIakCertReq, test.wantGetIakCertReq, protocmp.Transform()); diff != "" {
				t.Errorf("GetIakCertRequest request param to stubbed GetIakCert dep does not match expectations: diff = %v", diff)
			}
			if diff := cmp.Diff(stub.verifyIakAndIDevIDCertsReq, test.wantVerifyIakAndIDevIDCertsReq, protocmp.Transform(), cmpopts.IgnoreUnexported(x509.VerifyOptions{})); diff != "" {
				t.Errorf("VerifyIakAndIDevIDCertsReq request param to stubbed VerifyIakAndIDevIDCerts dep does not match expectations: diff = %v", diff)
			}
			if diff := cmp.Diff(stub.issueOwnerIakCertReq, test.wantIssueOwnerIakCertReq, protocmp.Transform()); diff != "" {
				t.Errorf("IssueOwnerIakCertReq request param to stubbed IssueOwnerIakCert dep does not match expectations: diff = %v", diff)
			}
			if diff := cmp.Diff(stub.issueOwnerIDevIDCertReq, test.wantIssueOwnerIDevIDCertReq, protocmp.Transform()); diff != "" {
				t.Errorf("IssueOwnerIDevIDCertReq request param to stubbed IssueOwnerIDevIDCert dep does not match expectations: diff = %v", diff)
			}
			if diff := cmp.Diff(stub.rotateOIakCertReq, test.wantRotateOIakCertReq, protocmp.Transform()); diff != "" {
				t.Errorf("RotateOIakCertRequest request param to stubbed RotateOIakCert dep does not match expectations: diff = %v", diff)
			}
		})
	}
}

func TestRotateOwnerIakCert(t *testing.T) {
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
	iakCert := "Some IAK cert PEM"
	iakPub := "Some IAK pub PEM"
	oIakCert := "Some Owner IAK cert PEM"
	errorResp := errors.New("Some error")

	tests := []struct {
		// Test description.
		desc string
		// Overall expected RotateOwnerIakCert response.
		wantErrResp error
		// Expected captured params to stubbed deps functions calls.
		wantGetIakCertReq        *epb.GetIakCertRequest
		wantIssueOwnerIakCertReq *IssueOwnerIakCertReq
		wantRotateOIakCertReq    *epb.RotateOIakCertRequest
		wantVerifyTpmCertReq     *VerifyTpmCertReq
		// Stubbed responses to EnrollzInfraDeps deps.
		issueOwnerIakCertResp *IssueOwnerIakCertResp
		getIakCertResp        *epb.GetIakCertResponse
		rotateOIakCertResp    *epb.RotateOIakCertResponse
		verifyTpmCertResp     *VerifyTpmCertResp
	}{
		{
			desc: "Successful rotation of Owner IAK cert",
			// Stubbed deps called:
			// * GetIakCert => Success
			// * VerifyTpmCert => Success
			// * IssueOwnerIakCert => Success
			// * RotateOIakCert => Success
			getIakCertResp: &epb.GetIakCertResponse{
				ControlCardId: vendorID,
				IakCert:       iakCert,
			},
			verifyTpmCertResp: &VerifyTpmCertResp{
				PubPem: iakPub,
			},
			issueOwnerIakCertResp: &IssueOwnerIakCertResp{OwnerIakCertPem: oIakCert},
			rotateOIakCertResp:    &epb.RotateOIakCertResponse{},
			// Expected params to all deps functions calls.
			wantGetIakCertReq: &epb.GetIakCertRequest{ControlCardSelection: controlCardSelection},
			wantVerifyTpmCertReq: &VerifyTpmCertReq{
				ControlCardID:        vendorID,
				CertPem:              iakCert,
				CertVerificationOpts: certVerificationOpts,
			},
			wantIssueOwnerIakCertReq: &IssueOwnerIakCertReq{
				CardID:    vendorID,
				IakPubPem: iakPub,
			},
			wantRotateOIakCertReq: &epb.RotateOIakCertRequest{
				ControlCardSelection: controlCardSelection,
				OiakCert:             oIakCert,
			},
		},
		{
			desc:        "EnrollzDeviceClient.GetIakCert() failure causes overall RotateOwnerIakCert failure",
			wantErrResp: errorResp,
			// Stubbed deps called:
			// * GetIakCert => Fail
			wantGetIakCertReq: &epb.GetIakCertRequest{ControlCardSelection: controlCardSelection},
		},
		{
			desc:        "TpmCertVerifier.VerifyTpmCert() failure causes overall RotateOwnerIakCert failure",
			wantErrResp: errorResp,
			// Stubbed deps called:
			// * GetIakCert => Success
			// * VerifyTpmCert => Fail
			getIakCertResp: &epb.GetIakCertResponse{
				ControlCardId: vendorID,
				IakCert:       iakCert,
			},
			wantGetIakCertReq: &epb.GetIakCertRequest{ControlCardSelection: controlCardSelection},
			wantVerifyTpmCertReq: &VerifyTpmCertReq{
				ControlCardID:        vendorID,
				CertPem:              iakCert,
				CertVerificationOpts: certVerificationOpts,
			},
		},
		{
			desc:        "SwitchOwnerCaClient.IssueOwnerIakCert() failure causes overall RotateOwnerIakCert failure",
			wantErrResp: errorResp,
			// Stubbed deps called:
			// * GetIakCert => Success
			// * VerifyTpmCert => Success
			// * IssueOwnerIakCert => Fail
			getIakCertResp: &epb.GetIakCertResponse{
				ControlCardId: vendorID,
				IakCert:       iakCert,
			},
			verifyTpmCertResp: &VerifyTpmCertResp{
				PubPem: iakPub,
			},
			wantGetIakCertReq: &epb.GetIakCertRequest{ControlCardSelection: controlCardSelection},
			wantVerifyTpmCertReq: &VerifyTpmCertReq{
				ControlCardID:        vendorID,
				CertPem:              iakCert,
				CertVerificationOpts: certVerificationOpts,
			},
			wantIssueOwnerIakCertReq: &IssueOwnerIakCertReq{
				CardID:    vendorID,
				IakPubPem: iakPub,
			},
		},
		{
			desc:        "EnrollzDeviceClient.RotateOIakCert() failure causes overall RotateOwnerIakCert failure",
			wantErrResp: errorResp,
			// Stubbed deps called:
			// * GetIakCert => Success
			// * VerifyTpmCert => Success
			// * IssueOwnerIakCert => Success
			// * RotateOIakCert => Fail
			getIakCertResp: &epb.GetIakCertResponse{
				ControlCardId: vendorID,
				IakCert:       iakCert,
			},
			verifyTpmCertResp: &VerifyTpmCertResp{
				PubPem: iakPub,
			},
			issueOwnerIakCertResp: &IssueOwnerIakCertResp{OwnerIakCertPem: oIakCert},
			wantGetIakCertReq:     &epb.GetIakCertRequest{ControlCardSelection: controlCardSelection},
			wantVerifyTpmCertReq: &VerifyTpmCertReq{
				ControlCardID:        vendorID,
				CertPem:              iakCert,
				CertVerificationOpts: certVerificationOpts,
			},
			wantIssueOwnerIakCertReq: &IssueOwnerIakCertReq{
				CardID:    vendorID,
				IakPubPem: iakPub,
			},
			wantRotateOIakCertReq: &epb.RotateOIakCertRequest{
				ControlCardSelection: controlCardSelection,
				OiakCert:             oIakCert,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			stub := &stubEnrollzInfraDeps{
				getIakCertResp:        test.getIakCertResp,
				verifyTpmCertResp:     test.verifyTpmCertResp,
				issueOwnerIakCertResp: test.issueOwnerIakCertResp,
				rotateOIakCertResp:    test.rotateOIakCertResp,
				errorResp:             test.wantErrResp,
			}
			req := &RotateOwnerIakCertReq{
				ControlCardSelection: controlCardSelection,
				CertVerificationOpts: certVerificationOpts,
				Deps:                 stub,
			}
			ctx := context.Background()
			got := RotateOwnerIakCert(ctx, req)

			// Verify that RotateOwnerIakCertReq returned expected error/no-error response.
			if test.wantErrResp != nil && test.wantErrResp != errors.Unwrap(got) {
				t.Errorf("Expected error response %v, but got error response %v", test.wantErrResp, errors.Unwrap(got))
			} else if test.wantErrResp == nil && got != nil {
				t.Errorf("Expected no-error response %v, but got error response %v", test.wantErrResp, got)
			}

			// Verify that all stubbed dependencies were called with the right params.
			if diff := cmp.Diff(stub.getIakCertReq, test.wantGetIakCertReq, protocmp.Transform()); diff != "" {
				t.Errorf("GetIakCertRequest request param to stubbed GetIakCert dep does not match expectations: diff = %v", diff)
			}
			if diff := cmp.Diff(stub.verifyTpmCertReq, test.wantVerifyTpmCertReq, protocmp.Transform(), cmpopts.IgnoreUnexported(x509.VerifyOptions{})); diff != "" {
				t.Errorf("VerifyTpmCertReq request param to stubbed VerifyTpmCert dep does not match expectations: diff = %v", diff)
			}
			if diff := cmp.Diff(stub.issueOwnerIakCertReq, test.wantIssueOwnerIakCertReq, protocmp.Transform()); diff != "" {
				t.Errorf("IssueOwnerIakCertReq request param to stubbed IssueOwnerIakCert dep does not match expectations: diff = %v", diff)
			}
			if diff := cmp.Diff(stub.rotateOIakCertReq, test.wantRotateOIakCertReq, protocmp.Transform()); diff != "" {
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
	errorResp := errors.New("Some error")
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
			wantErrResp:      errorResp,
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
			wantErrResp:      errorResp,
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
				getIakCertResp:              test.getIakCertResp,
				verifyIakAndIDevIDCertsResp: &VerifyIakAndIDevIDCertsResp{IakPubPem: iakPub, IDevIDPubPem: iDevIDPub},
				issueOwnerIakCertResp:       &IssueOwnerIakCertResp{OwnerIakCertPem: oIakCert},
				issueOwnerIDevIDCertResp:    &IssueOwnerIDevIDCertResp{OwnerIDevIDCertPem: oIdevIDCert},
				rotateOIakCertResp:          &epb.RotateOIakCertResponse{},
				errorResp:                   test.wantErrResp,
				verifyNonceSignatureResp:    test.verifyNonceSignatureResp,
				verifyTpmCertResp:           &VerifyTpmCertResp{PubPem: iakPub},
			}
			ctx := context.Background()
			var got error
			if test.isEnrollmentTest {
				req := &EnrollControlCardReq{
					ControlCardSelection: controlCardSelection,
					CertVerificationOpts: certVerificationOpts,
					Deps:                 stub,
					SSLProfileID:         sslProfileID,
					SkipNonceExchange:    test.skipNonceExchange,
				}
				got = EnrollControlCard(ctx, req)
			} else {
				req := &RotateOwnerIakCertReq{
					ControlCardSelection: controlCardSelection,
					CertVerificationOpts: certVerificationOpts,
					Deps:                 stub,
					SkipNonceExchange:    test.skipNonceExchange,
				}
				got = RotateOwnerIakCert(ctx, req)
			}

			// Verify that EnrollControlCard returned expected error/no-error response.
			if test.wantErrResp != nil && test.wantErrResp != errors.Unwrap(got) {
				t.Errorf("Expected error response %v, but got error response %v", test.wantErrResp, errors.Unwrap(got))
			} else if test.wantErrResp == nil && got != nil {
				t.Errorf("Expected no-error response, but got error response %v", got)
			}

			// Verify that GetIakCertReq was called with a nonce if SkipNonceExchange is false.
			if test.skipNonceExchange == nil || !*test.skipNonceExchange {
				if stub.getIakCertReq == nil || len(stub.getIakCertReq.Nonce) == 0 {
					t.Errorf("GetIakCertRequest was called without a nonce, but it was expected")
				}
			} else if stub.getIakCertReq != nil && len(stub.getIakCertReq.Nonce) > 0 {
				t.Errorf("GetIakCertRequest was called with a nonce, but it was not expected")
			}

			// Verify that VerifyNonceSignature was called if expected.
			if test.wantVerifyNonceSignatureReq && stub.verifyNonceSignatureReq == nil {
				t.Errorf("VerifyNonceSignature was expected to be called but was not")
			} else if !test.wantVerifyNonceSignatureReq && stub.verifyNonceSignatureReq != nil {
				t.Errorf("VerifyNonceSignature was not expected to be called but was")
			}
			if test.wantVerifyNonceSignatureReq && (len(stub.verifyNonceSignatureReq.Nonce) == 0 || len(stub.verifyNonceSignatureReq.Signature) == 0 || len(stub.verifyNonceSignatureReq.IAKPubPem) == 0 || stub.verifyNonceSignatureReq.HashAlgo == 0) {
				t.Errorf("VerifyNonceSignature was expected to be called with all parameters, but one or more parameters was missing")
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
	verifySignatureErr           error
	issueAikCertErr              error
	encryptWithAesErr            error
	encryptWithPublicKeyErr      error
	decryptWithPrivateKeyErr     error
	decryptWithSymmetricKeyErr   error
	constructIdentityContentsErr error
	serializeIdentityContentsErr error
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

func (s *stubRotateAIKCertInfraDeps) VerifySignature(ctx context.Context, pubKey []byte, signature []byte, data []byte, hash crypto.Hash) (bool, error) {
	if s.verifySignatureErr != nil {
		return false, s.verifySignatureErr
	}
	if s.customVerifySignatureResp != false {
		return s.customVerifySignatureResp, nil
	}
	return true, nil // Default success
}

func (s *stubRotateAIKCertInfraDeps) EncryptWithAes(key []byte, data []byte) ([]byte, error) {
	if s.encryptWithAesErr != nil {
		return nil, s.encryptWithAesErr
	}
	return []byte("encrypted"), nil // Default success
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

func (s *stubRotateAIKCertInfraDeps) DecryptWithSymmetricKey(ctx context.Context, symKey []byte, data []byte, algo tpm12.Algorithm, encScheme TPMEncodingScheme) ([]byte, error) {
	if s.decryptWithSymmetricKeyErr != nil {
		return nil, s.decryptWithSymmetricKeyErr
	}
	return []byte("decrypted identity proof"), nil // Default success
}

func (s *stubRotateAIKCertInfraDeps) ConstructIdentityContents(*rsa.PublicKey) (*TPMIdentityContents, error) {
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
		verifySignatureErr           error
		issueAikCertErr              error
		encryptWithAesErr            error
		encryptWithPublicKeyErr      error
		decryptWithPrivateKeyErr     error
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
			desc:               "Error verifying signature",
			wantErrResp:        errorResp,
			verifySignatureErr: errorResp,
			recvResponses:      defaultRecvResponses,
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
				verifySignatureErr:           tc.verifySignatureErr,
				issueAikCertErr:              tc.issueAikCertErr,
				encryptWithAesErr:            tc.encryptWithAesErr,
				encryptWithPublicKeyErr:      tc.encryptWithPublicKeyErr,
				decryptWithPrivateKeyErr:     tc.decryptWithPrivateKeyErr,
				decryptWithSymmetricKeyErr:   tc.decryptWithSymmetricKeyErr,
				constructIdentityContentsErr: tc.constructIdentityContentsErr,
				serializeIdentityContentsErr: tc.serializeIdentityContentsErr,
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
