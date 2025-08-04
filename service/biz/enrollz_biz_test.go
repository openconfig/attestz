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
	"crypto/rand"
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
	ROTdbClient
	TPM12Utils

	fetchEkReq      *FetchEKReq
	issueAikCertReq *IssueAikCertReq

	// Stubbed responses to simulate behavior of deps without implementing them.
	fetchEkResp                 *FetchEKResp
	parseIdentityReqResp        *TPMIdentityReq
	parseSymmetricKeyResp       *TPMSymmetricKey
	parseIdentityProofResp      *TPMIdentityProof
	verifySignatureResp         bool
	issueAikCertResp            *IssueAikCertResp
	encryptWithAesResp          []byte
	encryptWithPublicKeyResp    []byte
	decryptWithPrivateKeyResp   []byte
	decryptWithSymmetricKeyResp []byte
	rotateAikCertClient         epb.TpmEnrollzService_RotateAIKCertClient
	rotateAikCertStreamError    error

	// If we need to simulate an error response from any of the deps, then set
	// the dep's response to nil and populate this error field.
	errorResp error
}

func (s *stubRotateAIKCertInfraDeps) FetchEK(ctx context.Context, req *FetchEKReq) (*FetchEKResp, error) {
	// Validate that no stub (captured) request params were set prior to execution.
	if s.fetchEkReq != nil {
		return nil, fmt.Errorf("FetchEK unexpected req %+v", req)
	}
	s.fetchEkReq = req

	// If a stubbed response is not set, then return error, otherwise return the response.
	if s.fetchEkResp == nil {
		return nil, s.errorResp
	}
	return s.fetchEkResp, nil
}

func (s *stubRotateAIKCertInfraDeps) ParseIdentityRequest(data []byte) (*TPMIdentityReq, error) {
	if s.parseIdentityReqResp == nil {
		return nil, s.errorResp
	}
	return s.parseIdentityReqResp, nil
}

func (s *stubRotateAIKCertInfraDeps) ParseSymmetricKey(data []byte) (*TPMSymmetricKey, error) {
	if s.parseSymmetricKeyResp == nil {
		return nil, s.errorResp
	}
	return s.parseSymmetricKeyResp, nil
}

func (s *stubRotateAIKCertInfraDeps) ParseIdentityProof(data []byte) (*TPMIdentityProof, error) {
	if s.parseIdentityProofResp == nil {
		return nil, s.errorResp
	}
	return s.parseIdentityProofResp, nil
}

func (s *stubRotateAIKCertInfraDeps) VerifySignature(ctx context.Context, pubKey []byte, signature []byte, data []byte, hash crypto.Hash) (bool, error) {
	if s.verifySignatureResp == false {
		return false, s.errorResp
	}
	return s.verifySignatureResp, nil
}

func (s *stubRotateAIKCertInfraDeps) EncryptWithAes(key []byte, data []byte) ([]byte, error) {
	if s.encryptWithAesResp == nil {
		return nil, s.errorResp
	}
	return s.encryptWithAesResp, nil
}

func (s *stubRotateAIKCertInfraDeps) EncryptWithPublicKey(ctx context.Context, publicKey *rsa.PublicKey, data []byte, algo tpm12.Algorithm, encScheme TPMEncodingScheme) ([]byte, error) {
	if s.encryptWithPublicKeyResp == nil {
		return nil, s.errorResp
	}
	return s.encryptWithPublicKeyResp, nil
}

func (s *stubRotateAIKCertInfraDeps) DecryptWithPrivateKey(ctx context.Context, privateKey *rsa.PrivateKey, data []byte, algo tpm12.Algorithm, encScheme TPMEncodingScheme) ([]byte, error) {
	if s.decryptWithPrivateKeyResp == nil {
		return nil, s.errorResp
	}
	return s.decryptWithPrivateKeyResp, nil
}

func (s *stubRotateAIKCertInfraDeps) DecryptWithSymmetricKey(ctx context.Context, symKey []byte, data []byte, algo tpm12.Algorithm, encScheme TPMEncodingScheme) ([]byte, error) {
	if s.decryptWithSymmetricKeyResp == nil {
		return nil, s.errorResp
	}
	return s.decryptWithSymmetricKeyResp, nil
}

func (s *stubRotateAIKCertInfraDeps) RotateAIKCert(ctx context.Context, opts ...grpc.CallOption) (epb.TpmEnrollzService_RotateAIKCertClient, error) {
	if s.rotateAikCertClient == nil {
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

	// If a stubbed response is not set, then return error, otherwise return the response.
	if s.issueAikCertResp == nil {
		return nil, s.errorResp
	}
	return s.issueAikCertResp, nil
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

func generateDummyTPMKeyParms(algID tpm12.Algorithm, encScheme TPMEncodingScheme) *TPMKeyParms {
	return &TPMKeyParms{
		AlgID:     algID,
		EncScheme: encScheme,
		SigScheme: SsNone,
	}
}

func generateDummyRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, RSAkeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate dummy RSA key: %v", err)
	}
	return privateKey
}

func generateDummyTPMIdentityReq(t *testing.T, asymAlgID tpm12.Algorithm, asymEncScheme TPMEncodingScheme, symAlgID tpm12.Algorithm, symEncScheme TPMEncodingScheme, asymBlob []byte, symBlob []byte) *TPMIdentityReq {
	t.Helper()
	return &TPMIdentityReq{
		AsymAlgorithm: *generateDummyTPMKeyParms(asymAlgID, asymEncScheme),
		SymAlgorithm:  *generateDummyTPMKeyParms(symAlgID, symEncScheme),
		AsymBlob:      asymBlob,
		SymBlob:       symBlob,
	}
}

func generateDummyTPMSymmetricKey(t *testing.T, algID tpm12.Algorithm, encScheme TPMEncodingScheme, key []byte) *TPMSymmetricKey {
	t.Helper()
	return &TPMSymmetricKey{
		AlgID:     algID,
		EncScheme: encScheme,
		Key:       key,
	}
}

func generateDummyTPMIdentityProof(t *testing.T, pubKey *rsa.PublicKey, identityBinding []byte) (*TPMIdentityProof, error) {
	t.Helper()
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal dummy public key: %v", err)
	}
	return &TPMIdentityProof{
		AttestationIdentityKey: TPMPubKey{
			Pubkey: TPMStorePubkey{
				Key: publicKeyBytes,
			},
		},
		IdentityBinding: identityBinding,
	}, nil
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
	encryptedAikCert := []byte("encrypted AIK cert")
	encryptedAesKey := []byte("encrypted AES key")
	dummyEkKey := generateDummyRSAKey(t)
	dummyIdentityReq := generateDummyTPMIdentityReq(t, tpm12.AlgRSA, EsRSAEsOAEPSHA1MGF1, tpm12.AlgAES256, EsSymCBCPKCS5, []byte("dummy asym blob"), []byte("dummy sym blob"))
	dummySymKey := generateDummyTPMSymmetricKey(t, tpm12.AlgAES256, EsSymCBCPKCS5, []byte("dummy symmetric key"))
	dummyIdentityProof, err := generateDummyTPMIdentityProof(t, &dummyEkKey.PublicKey, []byte("dummy identity binding"))
	if err != nil {
		t.Fatalf("Failed to generate dummy identity proof: %v", err)
	}

	errorResp := errors.New("Some error")
	tests := []struct {
		// Test description.
		desc string
		// Overall expected RotateAIKCert response.
		wantErrResp error
		// Stubbed responses to RotateAIKCertInfraDeps deps.
		fetchEkResp                 *FetchEKResp
		parseIdentityReqResp        *TPMIdentityReq
		parseSymmetricKeyResp       *TPMSymmetricKey
		parseIdentityProofResp      *TPMIdentityProof
		verifySignatureResp         bool
		issueAikCertResp            *IssueAikCertResp
		encryptWithAesResp          []byte
		encryptWithPublicKeyResp    []byte
		decryptWithPrivateKeyResp   []byte
		decryptWithSymmetricKeyResp []byte
		rotateAikCertClient         epb.TpmEnrollzService_RotateAIKCertClient
		rotateAikCertStreamError    error
		// Stubbed errors
		sendError      error
		recvError      error
		closeSendError error
		errorResp      error
	}{
		{
			desc: "Successful AIK cert rotation",
			fetchEkResp: &FetchEKResp{
				EkPublicKey: &dummyEkKey.PublicKey,
			},
			parseIdentityReqResp:        dummyIdentityReq,
			parseSymmetricKeyResp:       dummySymKey,
			parseIdentityProofResp:      dummyIdentityProof,
			verifySignatureResp:         true,
			issueAikCertResp:            &IssueAikCertResp{AikCertPem: aikCert},
			encryptWithAesResp:          encryptedAikCert,
			encryptWithPublicKeyResp:    encryptedAesKey,
			decryptWithPrivateKeyResp:   []byte("dummy sym key"),
			decryptWithSymmetricKeyResp: []byte("dummy identity proof"),
			rotateAikCertClient: &stubRotateAIKCertClient{
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
			},
		},
		{
			desc:                     "Error initiating stream",
			wantErrResp:              errorResp,
			rotateAikCertStreamError: errorResp,
		},
		{
			desc:        "Error sending issuer public key",
			wantErrResp: errorResp,
			rotateAikCertClient: &stubRotateAIKCertClient{
				sendError: errorResp,
			},
		},
		{
			desc:        "Error receiving application identity request",
			wantErrResp: errorResp,
			rotateAikCertClient: &stubRotateAIKCertClient{
				recvError: errorResp,
			},
		},
		{
			desc:        "Empty application identity request",
			wantErrResp: errors.New("application_identity_request is empty"),
			rotateAikCertClient: &stubRotateAIKCertClient{
				recvResponses: []*epb.RotateAIKCertResponse{
					{
						Value: &epb.RotateAIKCertResponse_ApplicationIdentityRequest{
							ApplicationIdentityRequest: []byte(""),
						},
						ControlCardId: vendorID,
					},
				},
			},
		},
		{
			desc:        "Error parsing application identity request",
			wantErrResp: errorResp,
			rotateAikCertClient: &stubRotateAIKCertClient{
				recvResponses: []*epb.RotateAIKCertResponse{
					{
						Value: &epb.RotateAIKCertResponse_ApplicationIdentityRequest{
							ApplicationIdentityRequest: []byte("dummy identity request"),
						},
						ControlCardId: vendorID,
					},
				},
			},
		},
		{
			desc:        "Error decrypting AsymBlob",
			wantErrResp: errorResp,
			rotateAikCertClient: &stubRotateAIKCertClient{
				recvResponses: []*epb.RotateAIKCertResponse{
					{
						Value: &epb.RotateAIKCertResponse_ApplicationIdentityRequest{
							ApplicationIdentityRequest: []byte("dummy identity request"),
						},
					},
				},
			},
			parseIdentityReqResp:      dummyIdentityReq,
			decryptWithPrivateKeyResp: nil,
		},
		{
			desc:        "Error parsing symmetric key",
			wantErrResp: errorResp,
			rotateAikCertClient: &stubRotateAIKCertClient{
				recvResponses: []*epb.RotateAIKCertResponse{
					{
						Value: &epb.RotateAIKCertResponse_ApplicationIdentityRequest{
							ApplicationIdentityRequest: []byte("dummy identity request"),
						},
					},
				},
			},
			parseIdentityReqResp:      dummyIdentityReq,
			decryptWithPrivateKeyResp: []byte("dummy sym key"),
		},
		{
			desc:        "Error decrypting SymBlob",
			wantErrResp: errorResp,
			rotateAikCertClient: &stubRotateAIKCertClient{
				recvResponses: []*epb.RotateAIKCertResponse{
					{
						Value: &epb.RotateAIKCertResponse_ApplicationIdentityRequest{
							ApplicationIdentityRequest: []byte("dummy identity request"),
						},
					},
				},
			},
			parseIdentityReqResp:      dummyIdentityReq,
			decryptWithPrivateKeyResp: []byte("dummy sym key"),
			parseSymmetricKeyResp:     dummySymKey,
		},
		{
			desc:        "Error parsing identity proof",
			wantErrResp: errorResp,
			rotateAikCertClient: &stubRotateAIKCertClient{
				recvResponses: []*epb.RotateAIKCertResponse{
					{
						Value: &epb.RotateAIKCertResponse_ApplicationIdentityRequest{
							ApplicationIdentityRequest: []byte("dummy identity request"),
						},
					},
				},
			},
			parseIdentityReqResp:        dummyIdentityReq,
			decryptWithPrivateKeyResp:   []byte("dummy sym key"),
			parseSymmetricKeyResp:       dummySymKey,
			decryptWithSymmetricKeyResp: []byte("dummy identity proof"),
		},
		{
			desc:        "Error verifying signature",
			wantErrResp: errorResp,
			rotateAikCertClient: &stubRotateAIKCertClient{
				recvResponses: []*epb.RotateAIKCertResponse{
					{
						Value: &epb.RotateAIKCertResponse_ApplicationIdentityRequest{
							ApplicationIdentityRequest: []byte("dummy identity request"),
						},
					},
				},
			},
			parseIdentityReqResp:        dummyIdentityReq,
			decryptWithPrivateKeyResp:   []byte("dummy sym key"),
			parseSymmetricKeyResp:       dummySymKey,
			decryptWithSymmetricKeyResp: []byte("dummy identity proof"),
			parseIdentityProofResp:      dummyIdentityProof,
			verifySignatureResp:         false,
		},
		{
			desc:        "Error fetching EK",
			wantErrResp: errorResp,
			fetchEkResp: nil,
			rotateAikCertClient: &stubRotateAIKCertClient{
				recvResponses: []*epb.RotateAIKCertResponse{
					{
						Value: &epb.RotateAIKCertResponse_ApplicationIdentityRequest{
							ApplicationIdentityRequest: []byte("dummy identity request"),
						},
					},
				},
			},
			parseIdentityReqResp:        dummyIdentityReq,
			decryptWithPrivateKeyResp:   []byte("dummy sym key"),
			parseSymmetricKeyResp:       dummySymKey,
			decryptWithSymmetricKeyResp: []byte("dummy identity proof"),
			parseIdentityProofResp:      dummyIdentityProof,
			verifySignatureResp:         true,
		},
		{
			desc:        "Empty device AIK cert",
			wantErrResp: fmt.Errorf("device AIK cert is empty"),
			rotateAikCertClient: &stubRotateAIKCertClient{
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
			parseIdentityReqResp:        dummyIdentityReq,
			decryptWithPrivateKeyResp:   []byte("dummy sym key"),
			parseSymmetricKeyResp:       dummySymKey,
			decryptWithSymmetricKeyResp: []byte("dummy identity proof"),
			parseIdentityProofResp:      dummyIdentityProof,
			verifySignatureResp:         true,
			issueAikCertResp:            &IssueAikCertResp{AikCertPem: aikCert},
			encryptWithAesResp:          encryptedAikCert,
			fetchEkResp: &FetchEKResp{
				EkPublicKey: &dummyEkKey.PublicKey,
			},
			encryptWithPublicKeyResp: encryptedAesKey,
		},
		{
			desc:        "AIK certs do not match",
			wantErrResp: fmt.Errorf("AIK certificates do not match"),
			rotateAikCertClient: &stubRotateAIKCertClient{
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
			parseIdentityReqResp:        dummyIdentityReq,
			decryptWithPrivateKeyResp:   []byte("dummy sym key"),
			parseSymmetricKeyResp:       dummySymKey,
			decryptWithSymmetricKeyResp: []byte("dummy identity proof"),
			parseIdentityProofResp:      dummyIdentityProof,
			verifySignatureResp:         true,
			issueAikCertResp:            &IssueAikCertResp{AikCertPem: aikCert},
			encryptWithAesResp:          encryptedAikCert,
			fetchEkResp: &FetchEKResp{
				EkPublicKey: &dummyEkKey.PublicKey,
			},
			encryptWithPublicKeyResp: encryptedAesKey,
		},
		{
			desc:        "Error sending finalize message",
			wantErrResp: errorResp,
			rotateAikCertClient: &stubRotateAIKCertClient{
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
				sendError: errorResp,
			},
			parseIdentityReqResp:        dummyIdentityReq,
			decryptWithPrivateKeyResp:   []byte("dummy sym key"),
			parseSymmetricKeyResp:       dummySymKey,
			decryptWithSymmetricKeyResp: []byte("dummy identity proof"),
			parseIdentityProofResp:      dummyIdentityProof,
			verifySignatureResp:         true,
			issueAikCertResp:            &IssueAikCertResp{AikCertPem: aikCert},
			encryptWithAesResp:          encryptedAikCert,
			fetchEkResp: &FetchEKResp{
				EkPublicKey: &dummyEkKey.PublicKey,
			},
			encryptWithPublicKeyResp: encryptedAesKey,
		},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			deps := &stubRotateAIKCertInfraDeps{
				fetchEkResp:                 tc.fetchEkResp,
				parseIdentityReqResp:        tc.parseIdentityReqResp,
				parseSymmetricKeyResp:       tc.parseSymmetricKeyResp,
				parseIdentityProofResp:      tc.parseIdentityProofResp,
				verifySignatureResp:         tc.verifySignatureResp,
				issueAikCertResp:            tc.issueAikCertResp,
				encryptWithAesResp:          tc.encryptWithAesResp,
				encryptWithPublicKeyResp:    tc.encryptWithPublicKeyResp,
				decryptWithPrivateKeyResp:   tc.decryptWithPrivateKeyResp,
				decryptWithSymmetricKeyResp: tc.decryptWithSymmetricKeyResp,
				rotateAikCertClient:         tc.rotateAikCertClient,
				rotateAikCertStreamError:    tc.rotateAikCertStreamError,
				errorResp:                   tc.wantErrResp,
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
