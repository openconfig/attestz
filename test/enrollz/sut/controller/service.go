//
// Copyright 2026 Google LLC
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
//

// Package main implements the Enrollz SUT Controller service.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"strings"

	"github.com/golang/glog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	cpb "github.com/openconfig/attestz/proto/common_definitions"
	epb "github.com/openconfig/attestz/proto/tpm_enrollz"
	"github.com/openconfig/attestz/test/enrollz/caservice"
	sutpb "github.com/openconfig/attestz/test/enrollz/proto"
	statuspb "google.golang.org/genproto/googleapis/rpc/status"
)

// Service implements the sutpb.ControllerServer interface.
type Service struct {
	sutpb.UnimplementedControllerServer
	pkiProvider caservice.PKIProvider
}

// New creates a new Enrollz Controller service instance.
func New(pki caservice.PKIProvider) *Service {
	return &Service{pkiProvider: pki}
}

// EnrollDevice executes the TPM 2.0 Enrollz handshake with the DUT.
func (s *Service) EnrollDevice(ctx context.Context, req *sutpb.EnrollDeviceRequest) (*sutpb.EnrollDeviceResponse, error) {
	roles := req.GetControlCardRoles()
	if len(roles) == 0 {
		return nil, status.Errorf(codes.InvalidArgument, "no control card roles specified in request")
	}

	glog.Infof("SUT received EnrollDevice request for ControlCardRoles=%v on %s:%s", roles, req.GetIpAddress(), req.GetPort())

	dialTarget := net.JoinHostPort(req.GetIpAddress(), req.GetPort())
	glog.Infof("SUT dialing DUT at %q", dialTarget)

	conn, err := s.dialDUT(ctx, dialTarget)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "failed to dial DUT %q: %v", dialTarget, err)
	}
	defer conn.Close()

	gnsiClient := epb.NewTpmEnrollzServiceClient(conn)

	cardGetCertResps := make(map[cpb.ControlCardRole]*epb.GetIakCertResponse)
	var cardResults []*sutpb.ControlCardEnrollmentResult
	for _, role := range roles {
		resp, err := s.fetchAndValidateControlCardCerts(ctx, gnsiClient, role)
		if err != nil {
			cardResults = append(cardResults, &sutpb.ControlCardEnrollmentResult{
				ControlCardRole: role,
				Status:          status.Convert(err).Proto(),
			})
			continue
		}
		cardGetCertResps[role] = resp
	}

	// If any card failed discovery/validation, return early with per-card failure statuses
	if len(cardResults) > 0 {
		return &sutpb.EnrollDeviceResponse{CardResults: cardResults}, nil
	}

	var updates []*epb.ControlCardCertUpdate
	for _, role := range roles {
		update, err := s.issueOwnerCerts(role, cardGetCertResps[role])
		if err != nil {
			return nil, err
		}
		updates = append(updates, update)
	}

	// Rotate each card individually.
	for _, u := range updates {
		role := u.GetControlCardSelection().GetRole()
		rotateReq := &epb.RotateOIakCertRequest{
			SslProfileId: req.GetSslProfileId(),
			Updates:      []*epb.ControlCardCertUpdate{u},
		}
		if _, err := gnsiClient.RotateOIakCert(ctx, rotateReq); err != nil {
			cardResults = append(cardResults, &sutpb.ControlCardEnrollmentResult{
				ControlCardRole: role,
				Status: &statuspb.Status{
					Code:    int32(codes.Aborted),
					Message: fmt.Sprintf("RotateOIakCert failed: %v", err),
				},
			})
			continue
		}
		cardResults = append(cardResults, &sutpb.ControlCardEnrollmentResult{
			ControlCardRole: role,
			Status:          &statuspb.Status{Code: int32(codes.OK)},
		})
	}

	glog.Infof("Completed EnrollDevice for ControlCardRoles=%v", roles)
	return &sutpb.EnrollDeviceResponse{CardResults: cardResults}, nil
}

func (s *Service) dialDUT(ctx context.Context, target string) (*grpc.ClientConn, error) {
	certPEM, keyPEM, err := s.pkiProvider.GenerateClientCredentials()
	if err != nil {
		return nil, fmt.Errorf("failed to generate client credentials: %w", err)
	}

	clientCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse client certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      s.pkiProvider.DeviceTrustBundle(),
	}

	tlsCreds := credentials.NewTLS(tlsConfig)
	return grpc.NewClient(target, grpc.WithTransportCredentials(tlsCreds))
}

// fetchAndValidateControlCardCerts retrieves and validates certificates for a single control card from the DUT.
func (s *Service) fetchAndValidateControlCardCerts(ctx context.Context, gnsiClient epb.TpmEnrollzServiceClient, role cpb.ControlCardRole) (*epb.GetIakCertResponse, error) {
	iakReq := &epb.GetIakCertRequest{
		ControlCardSelection: &cpb.ControlCardSelection{
			ControlCardId: &cpb.ControlCardSelection_Role{Role: role},
		},
	}
	iakResp, err := gnsiClient.GetIakCert(ctx, iakReq)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "GetIakCert failed: %v", err)
	}
	glog.Infof("Received GetIakCert response for ControlCardRole=%v from DUT", role)

	if err := s.validateCerts(iakResp.GetIdevidCert(), iakResp.GetIakCert(), s.pkiProvider.DeviceTrustBundle()); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "failed to validate certificates: %v", err)
	}
	glog.Infof("Validated certificates for ControlCardRole=%v", role)

	return iakResp, nil
}

func (s *Service) validateCerts(idevidPem, iakPem string, deviceTrustBundle *x509.CertPool) error {
	if idevidPem == "" || iakPem == "" || deviceTrustBundle == nil {
		return fmt.Errorf("missing certificate or trust bundle")
	}

	idevidBlock, _ := pem.Decode([]byte(idevidPem))
	if idevidBlock == nil {
		return fmt.Errorf("failed to decode IDevID PEM")
	}
	iakBlock, _ := pem.Decode([]byte(iakPem))
	if iakBlock == nil {
		return fmt.Errorf("failed to decode IAK PEM")
	}

	idevidCert, err := x509.ParseCertificate(idevidBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse IDevID cert: %w", err)
	}
	iakCert, err := x509.ParseCertificate(iakBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse IAK cert: %w", err)
	}

	opts := x509.VerifyOptions{Roots: deviceTrustBundle}
	if _, err := idevidCert.Verify(opts); err != nil {
		return fmt.Errorf("failed to verify IDevID: %w", err)
	}
	if _, err := iakCert.Verify(opts); err != nil {
		return fmt.Errorf("failed to verify IAK: %w", err)
	}

	// Verify serial numbers match across IDevID and IAK
	iakSN := getSerialNumber(iakCert.Subject.SerialNumber)
	idevidSN := getSerialNumber(idevidCert.Subject.SerialNumber)
	if iakSN == "" || idevidSN == "" {
		return fmt.Errorf("certificate missing subject serial number: IAK=%q, IDevID=%q", iakSN, idevidSN)
	}
	if iakSN != idevidSN {
		return fmt.Errorf("serial number mismatch: IAK=%q, IDevID=%q", iakSN, idevidSN)
	}
	return nil
}

func getSerialNumber(s string) string {
	parts := strings.Split(s, "SN:")
	if len(parts) == 2 {
		return strings.TrimSpace(parts[1])
	}
	return strings.TrimSpace(s)
}

// issueOwnerCerts mints owner certificates (oIAK and oIDevID) via the controller's PKI provider.
func (s *Service) issueOwnerCerts(role cpb.ControlCardRole, iakResp *epb.GetIakCertResponse) (*epb.ControlCardCertUpdate, error) {
	oIAKPem, err := s.pkiProvider.IssueOIAK(iakResp.GetIakCert())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to issue OIAK for role %v: %v", role, err)
	}
	oIDevIDPem, err := s.pkiProvider.IssueOIDevID(iakResp.GetIdevidCert())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to issue OIDevID for role %v: %v", role, err)
	}

	return &epb.ControlCardCertUpdate{
		ControlCardSelection: &cpb.ControlCardSelection{
			ControlCardId: &cpb.ControlCardSelection_Role{Role: role},
		},
		OiakCert:    oIAKPem,
		OidevidCert: oIDevIDPem,
	}, nil
}
