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
	"errors"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/testing/protocmp"

	cpb "github.com/openconfig/attestz/proto/common_definitions"
	epb "github.com/openconfig/attestz/proto/tpm_enrollz"
)

type stubEnrollzInfraDeps struct {
	SwitchOwnerCaClient
	EnrollzDeviceClient

	// Request params that would be captured in stubbed deps' function calls.
	cardIdIssueIakReq    *cpb.ControlCardVendorId
	cardIdIssueIDevIdReq *cpb.ControlCardVendorId
	iakPubPemReq         string
	iDevIdPubPemReq      string
	getIakCertReq        *epb.GetIakCertRequest
	rotateOIakCertReq    *epb.RotateOIakCertRequest

	// Stubbed responses to simulate behavior of deps without implementing them.
	oIakCertResp       string
	oIDevIdCertPemResp string
	getIakCertResp     *epb.GetIakCertResponse
	rotateOIakCertResp *epb.RotateOIakCertResponse

	// If we need to simulate an error response from any of the deps, then set
	// the dep's response to nil and populate this error field.
	errorResp error
}

func (s *stubEnrollzInfraDeps) IssueOwnerIakCert(cardId *cpb.ControlCardVendorId, iakPubPem string) (string, error) {
	// Validate that no stub (captured) request params were set prior to execution.
	if s.cardIdIssueIakReq != nil {
		return "", fmt.Errorf("IssueOwnerIakCert unexpected req cardId %s", prototext.Format(s.cardIdIssueIakReq))
	}
	s.cardIdIssueIakReq = cardId

	if s.iakPubPemReq != "" {
		return "", fmt.Errorf("IssueOwnerIakCert unexpected req IAK pub key PEM %s", s.iakPubPemReq)
	}
	s.iakPubPemReq = iakPubPem

	// If the response is set, then return it, otherwise return error.
	if s.oIakCertResp == "" {
		return "", s.errorResp
	} else {
		return s.oIakCertResp, nil
	}
}

func (s *stubEnrollzInfraDeps) IssueOwnerIDevIdCert(cardId *cpb.ControlCardVendorId, iDevIdPubPem string) (string, error) {
	// Validate that no stub (captured) request params were set prior to execution.
	if s.cardIdIssueIDevIdReq != nil {
		return "", fmt.Errorf("IssueOwnerIDevIdCert unexpected req cardId %s", prototext.Format(s.cardIdIssueIDevIdReq))
	}
	s.cardIdIssueIDevIdReq = cardId

	if s.iDevIdPubPemReq != "" {
		return "", fmt.Errorf("IssueOwnerIDevIdCert unexpected req IDevId pub key PEM %s", s.iDevIdPubPemReq)
	}
	s.iDevIdPubPemReq = iDevIdPubPem

	// If the response is set, then return it, otherwise return error.
	if s.oIDevIdCertPemResp == "" {
		return "", s.errorResp
	} else {
		return s.oIDevIdCertPemResp, nil
	}
}

func (s *stubEnrollzInfraDeps) GetIakCert(req *epb.GetIakCertRequest) (*epb.GetIakCertResponse, error) {
	// Validate that no stub (captured) request params were set prior to execution.
	if s.getIakCertReq != nil {
		return nil, fmt.Errorf("GetIakCert unexpected req %s", prototext.Format(s.getIakCertReq))
	}
	s.getIakCertReq = req

	// If the response is set, then return it, otherwise return error.
	if s.getIakCertResp == nil {
		return nil, s.errorResp
	} else {
		return s.getIakCertResp, nil
	}
}

func (s *stubEnrollzInfraDeps) RotateOIakCert(req *epb.RotateOIakCertRequest) (*epb.RotateOIakCertResponse, error) {
	// Validate that no stub (captured) request params were set prior to execution.
	if s.rotateOIakCertReq != nil {
		return nil, fmt.Errorf("RotateOIakCert unexpected req %s", prototext.Format(s.rotateOIakCertReq))
	}
	s.rotateOIakCertReq = req

	// If the response is set, then return it, otherwise return error.
	if s.rotateOIakCertResp == nil {
		return nil, s.errorResp
	} else {
		return s.rotateOIakCertResp, nil
	}
}

func TestEnrollControlCard(t *testing.T) {
	// Constants to be used in request params and stubbing.
	controlCardSelection := &cpb.ControlCardSelection{
		ControlCardId: &cpb.ControlCardSelection_Role{
			Role: cpb.ControlCardRole_CONTROL_CARD_ROLE_ACTIVE,
		},
	}
	vendorId := &cpb.ControlCardVendorId{
		ControlCardRole:     controlCardSelection.GetRole(),
		ControlCardSerial:   "Some card serial",
		ControlCardSlot:     "Some card slot",
		ChassisManufacturer: "Some manufacturer",
		ChassisPartNumber:   "Some part",
		ChassisSerialNumber: "Some chassis serial",
	}
	iakCert := "Some IAK cert PEM"
	iDevIdCert := "Some IDevID cert PEM"
	oIakCert := "Some Owner IAK cert PEM"
	oIdevIdCert := "Some Owner IDevID cert PEM"
	errorResp := errors.New("Some error")

	tests := []struct {
		// Test description.
		desc string
		// Overall expected EnrollControlCard response.
		wantErrResp error
		// Expected captured params to stubbed deps functions calls.
		wantGetIakCertReq        *epb.GetIakCertRequest
		wantCardIdIssueIakReq    *cpb.ControlCardVendorId
		wantIakPubPemReq         string
		wantCardIdIssueIDevIdReq *cpb.ControlCardVendorId
		wantIDevIdPubPemReq      string
		wantRotateOIakCertReq    *epb.RotateOIakCertRequest
		// Stubbed responses to EnrollzInfraDeps deps.
		oIakCertResp       string
		oIDevIdCertPemResp string
		getIakCertResp     *epb.GetIakCertResponse
		rotateOIakCertResp *epb.RotateOIakCertResponse
	}{
		{
			desc: "Successful control card enrollment",
			// Stubbed deps called: GetIakCert (Success), IssueOwnerIakCert (Success), IssueOwnerIDevIdCert (Success), RotateOIakCert(Success)
			getIakCertResp: &epb.GetIakCertResponse{
				ControlCardId: vendorId,
				IakCert:       iakCert,
				IdevidCert:    iDevIdCert,
			},
			oIakCertResp:       oIakCert,
			oIDevIdCertPemResp: oIdevIdCert,
			rotateOIakCertResp: &epb.RotateOIakCertResponse{},
			// Expected params to all deps functions calls.
			wantGetIakCertReq:        &epb.GetIakCertRequest{ControlCardSelection: controlCardSelection},
			wantCardIdIssueIakReq:    vendorId,
			wantIakPubPemReq:         iakCert,
			wantCardIdIssueIDevIdReq: vendorId,
			wantIDevIdPubPemReq:      iDevIdCert,
			wantRotateOIakCertReq: &epb.RotateOIakCertRequest{
				ControlCardSelection: controlCardSelection,
				OiakCert:             oIakCert,
				OidevidCert:          oIdevIdCert,
			},
		},
		{
			desc:        "GetIakCert failure causes EnrollControlCard failure",
			wantErrResp: errorResp,
			// Stubbed deps called: GetIakCert (Fail)
			wantGetIakCertReq: &epb.GetIakCertRequest{ControlCardSelection: controlCardSelection},
		},
		{
			desc:        "IssueOwnerIakCert failure causes EnrollControlCard failure",
			wantErrResp: errorResp,
			// Stubbed deps called: GetIakCert (Success), IssueOwnerIakCert (Fail)
			getIakCertResp: &epb.GetIakCertResponse{
				ControlCardId: vendorId,
				IakCert:       iakCert,
				IdevidCert:    iDevIdCert,
			},
			wantGetIakCertReq:     &epb.GetIakCertRequest{ControlCardSelection: controlCardSelection},
			wantCardIdIssueIakReq: vendorId,
			wantIakPubPemReq:      iakCert,
		},
		{
			desc:        "IssueOwnerIDevIdCert failure causes EnrollControlCard failure",
			wantErrResp: errorResp,
			// Stubbed deps called: GetIakCert (Success), IssueOwnerIakCert (Success), IssueOwnerIDevIdCert (Fail)
			getIakCertResp: &epb.GetIakCertResponse{
				ControlCardId: vendorId,
				IakCert:       iakCert,
				IdevidCert:    iDevIdCert,
			},
			oIakCertResp:             oIakCert,
			wantGetIakCertReq:        &epb.GetIakCertRequest{ControlCardSelection: controlCardSelection},
			wantCardIdIssueIakReq:    vendorId,
			wantIakPubPemReq:         iakCert,
			wantCardIdIssueIDevIdReq: vendorId,
			wantIDevIdPubPemReq:      iDevIdCert,
		},
		{
			desc:        "RotateOIakCert failure causes EnrollControlCard failure",
			wantErrResp: errorResp,
			// Stubbed deps called: GetIakCert (Success), IssueOwnerIakCert (Success), IssueOwnerIDevIdCert (Success), RotateOIakCert(Fail)
			getIakCertResp: &epb.GetIakCertResponse{
				ControlCardId: vendorId,
				IakCert:       iakCert,
				IdevidCert:    iDevIdCert,
			},
			oIakCertResp:             oIakCert,
			oIDevIdCertPemResp:       oIdevIdCert,
			wantGetIakCertReq:        &epb.GetIakCertRequest{ControlCardSelection: controlCardSelection},
			wantCardIdIssueIakReq:    vendorId,
			wantIakPubPemReq:         iakCert,
			wantCardIdIssueIDevIdReq: vendorId,
			wantIDevIdPubPemReq:      iDevIdCert,
			wantRotateOIakCertReq: &epb.RotateOIakCertRequest{
				ControlCardSelection: controlCardSelection,
				OiakCert:             oIakCert,
				OidevidCert:          oIdevIdCert,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			stub := &stubEnrollzInfraDeps{
				getIakCertResp:     test.getIakCertResp,
				oIakCertResp:       test.oIakCertResp,
				oIDevIdCertPemResp: test.oIDevIdCertPemResp,
				rotateOIakCertResp: test.rotateOIakCertResp,
				errorResp:          test.wantErrResp,
			}
			got := EnrollControlCard(controlCardSelection, stub)

			// Verify that EnrollControlCard returned expected error/no-error response.
			if test.wantErrResp != got {
				t.Errorf("Expected error response %v, but got error response %v", test.wantErrResp, got)
			}

			// Verify that all stubbed dependencies were called with the right params.
			if diff := cmp.Diff(stub.getIakCertReq, test.wantGetIakCertReq, protocmp.Transform()); diff != "" {
				t.Errorf("GetIakCertRequest request param to stubbed GetIakCert dep does not match expectations: diff = %v", diff)
			}
			if diff := cmp.Diff(stub.cardIdIssueIakReq, test.wantCardIdIssueIakReq, protocmp.Transform()); diff != "" {
				t.Errorf("ControlCardVendorId request param to stubbed IssueOwnerIakCert dep does not match expectations: diff = %v", diff)
			}
			if diff := cmp.Diff(stub.iakPubPemReq, test.wantIakPubPemReq); diff != "" {
				t.Errorf("iakPubPem request param to stubbed IssueOwnerIakCert dep does not match expectations: diff = %v", diff)
			}
			if diff := cmp.Diff(stub.cardIdIssueIDevIdReq, test.wantCardIdIssueIDevIdReq, protocmp.Transform()); diff != "" {
				t.Errorf("ControlCardVendorId request param to stubbed IssueOwnerIDevIdCert dep does not match expectations: diff = %v", diff)
			}
			if diff := cmp.Diff(stub.iDevIdPubPemReq, test.wantIDevIdPubPemReq); diff != "" {
				t.Errorf("iDevIdPubPem request param to stubbed IssueOwnerIDevIdCert dep does not match expectations: diff = %v", diff)
			}
			if diff := cmp.Diff(stub.rotateOIakCertReq, test.wantRotateOIakCertReq, protocmp.Transform()); diff != "" {
				t.Errorf("RotateOIakCertRequest request param to stubbed RotateOIakCert dep does not match expectations: diff = %v", diff)
			}
		})
	}
}
