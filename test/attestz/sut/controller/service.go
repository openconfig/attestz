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

// Package main implements the Attestz SUT Controller service.
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"maps"
	"net"
	"slices"
	"sort"

	"github.com/golang/glog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	cpb "github.com/openconfig/attestz/proto/common_definitions"
	apb "github.com/openconfig/attestz/proto/tpm_attestz"
	"github.com/openconfig/attestz/service/biz"
	sutpb "github.com/openconfig/attestz/test/attestz/proto"
	"github.com/openconfig/attestz/test/attestz/tpmutil"
	statuspb "google.golang.org/genproto/googleapis/rpc/status"
)

const defaultGNSIPort = "9339"

// PKIProvider defines the Public Key Infrastructure interface for the Attestz controller.
type PKIProvider interface {
	// OwnerTrustBundle returns the pool of owner CA certificates used to validate the DUT's oIDevID and oIAK.
	OwnerTrustBundle() *x509.CertPool
	// GenerateClientCredentials generates a client cert/key pair for mTLS authentication with the DUT.
	GenerateClientCredentials() (certPEM, keyPEM []byte, err error)
}

// PCRProvider defines the interface for retrieving expected Platform Configuration Registers (PCRs)
// for a target device during attestation verification.
type PCRProvider interface {
	// ExpectedPCRs returns the expected PCR index-to-digests mapping for a target device.
	ExpectedPCRs(ctx context.Context, device string) (map[int32][][]byte, error)
}

// Service implements the sutpb.ControllerServer gRPC interface.
type Service struct {
	sutpb.UnimplementedControllerServer
	pkiProvider  PKIProvider
	pcrProvider  PCRProvider
	tpmCertUtils tpmutil.TPMCertUtils
}

// New creates a new Attestz SUT Service.
func New(pki PKIProvider, pcr PCRProvider, tpmCertUtils tpmutil.TPMCertUtils) *Service {
	return &Service{
		pkiProvider:  pki,
		pcrProvider:  pcr,
		tpmCertUtils: tpmCertUtils,
	}
}

// AttestDevice executes the TPM 2.0 Attestz workflow against the DUT for each requested control card role.
func (s *Service) AttestDevice(ctx context.Context, req *sutpb.AttestDeviceRequest) (*sutpb.AttestDeviceResponse, error) {
	roles := req.GetControlCardRoles()
	if len(roles) == 0 {
		return nil, status.Errorf(codes.InvalidArgument, "no control card roles specified in request")
	}

	port := req.GetPort()
	if port == "" {
		port = defaultGNSIPort
	}
	glog.Infof("SUT received AttestDevice request for ControlCardRoles=%v on %s:%s", roles, req.GetHost(), port)

	if s.pkiProvider == nil || s.pkiProvider.OwnerTrustBundle() == nil {
		return nil, status.Errorf(codes.FailedPrecondition, "owner trust bundle is not configured")
	}

	dialTarget := net.JoinHostPort(req.GetHost(), port)
	conn, err := s.dialDUT(ctx, dialTarget)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "failed to dial DUT %q: %v", dialTarget, err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			glog.Warningf("Failed to close connection to DUT: %v", err)
		}
	}()

	client := apb.NewTpmAttestzServiceClient(conn)

	if s.pcrProvider == nil {
		return nil, status.Errorf(codes.Internal, "PCR provider is not configured")
	}
	expectedPCRs, err := s.pcrProvider.ExpectedPCRs(ctx, req.GetHost())
	if err != nil || len(expectedPCRs) == 0 {
		return nil, status.Errorf(codes.FailedPrecondition, "no expected PCRs found for device %q: %v", req.GetHost(), err)
	}

	sortedIndices := slices.Collect(maps.Keys(expectedPCRs))
	sort.Slice(sortedIndices, func(i, j int) bool { return sortedIndices[i] < sortedIndices[j] })

	var cardResults []*sutpb.ControlCardAttestationResult
	for _, role := range roles {
		cardStatus := s.attestControlCard(ctx, client, req, role, expectedPCRs, sortedIndices)
		cardResults = append(cardResults, &sutpb.ControlCardAttestationResult{
			ControlCardRole: role,
			Status:          cardStatus,
		})
	}

	return &sutpb.AttestDeviceResponse{CardResults: cardResults}, nil
}

func (s *Service) attestControlCard(ctx context.Context, client apb.TpmAttestzServiceClient,
	req *sutpb.AttestDeviceRequest, role cpb.ControlCardRole, expectedPCRs map[int32][][]byte, sortedIndices []int32) *statuspb.Status {
	nonce, err := generateNonce(req.GetHashAlgo())
	if err != nil {
		return &statuspb.Status{
			Code:    int32(codes.InvalidArgument),
			Message: fmt.Sprintf("failed to generate nonce: %v", err),
		}
	}

	attestReq := &apb.AttestRequest{
		ControlCardSelection: &cpb.ControlCardSelection{
			ControlCardId: &cpb.ControlCardSelection_Role{
				Role: role,
			},
		},
		Nonce:      nonce,
		HashAlgo:   req.GetHashAlgo(),
		PcrIndices: sortedIndices,
	}

	glog.Infof("Calling Attest on device %q (role %v) with requested PCRs %v", req.GetHost(), role, sortedIndices)
	attestResp, err := client.Attest(ctx, attestReq)
	if err != nil {
		return &statuspb.Status{
			Code:    int32(codes.Unavailable),
			Message: fmt.Sprintf("DUT Attest RPC failed: %v", err),
		}
	}

	certVerificationOpts := x509.VerifyOptions{
		Roots: s.pkiProvider.OwnerTrustBundle(),
	}
	leafCert, err := biz.VerifyAndParsePemCert(ctx, attestResp.GetAttestationCert().GetOiakCert(), certVerificationOpts)
	if err != nil {
		return &statuspb.Status{
			Code:    int32(codes.FailedPrecondition),
			Message: fmt.Sprintf("oIAK certificate verification failed: %v", err),
		}
	}

	isIAK, err := s.tpmCertUtils.IsIAK(leafCert)
	if err != nil || !isIAK {
		return &statuspb.Status{
			Code:    int32(codes.FailedPrecondition),
			Message: fmt.Sprintf("certificate is not a valid oIAK (isIAK=%v): %v", isIAK, err),
		}
	}

	if err := tpmutil.VerifyPCRQuoteAndQuoteSignature(
		ctx,
		s.tpmCertUtils,
		leafCert,
		attestResp.GetQuoted(),
		attestResp.GetQuoteSignature(),
		attestResp.GetPcrValues(),
		attestReq.GetNonce(),
		attestReq.GetHashAlgo(),
	); err != nil {
		return &statuspb.Status{
			Code:    int32(codes.FailedPrecondition),
			Message: fmt.Sprintf("PCR quote signature verification failed: %v", err),
		}
	}

	if err := tpmutil.ValidatePCRs(expectedPCRs, attestResp.GetPcrValues()); err != nil {
		return &statuspb.Status{
			Code:    int32(codes.FailedPrecondition),
			Message: fmt.Sprintf("PCR validation failed: %v", err),
		}
	}

	return &statuspb.Status{Code: int32(codes.OK)}
}

// dialDUT establishes a gRPC connection to the DUT.
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
		RootCAs:      s.pkiProvider.OwnerTrustBundle(),
	}

	tlsCreds := credentials.NewTLS(tlsConfig)
	return grpc.NewClient(target, grpc.WithTransportCredentials(tlsCreds))
}

// generateNonce generates a cryptographically secure random nonce sized to match
// the digest length of the requested TPM 2.0 hash algorithm.
func generateNonce(hashAlgo cpb.Tpm20HashAlgo) ([]byte, error) {
	var size int
	switch hashAlgo {
	case cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA256:
		size = 32
	case cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA384:
		size = 48
	case cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA512:
		size = 64
	default:
		return nil, fmt.Errorf("unsupported hash algorithm %v for nonce generation", hashAlgo)
	}

	nonce := make([]byte, size)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("rand.Read(%d bytes) failed: %w", size, err)
	}
	return nonce, nil
}
