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

// Package main provides a client binary that calls the TpmAttestzService.Attest gRPC.
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"slices"
	"strings"

	log "github.com/golang/glog"
	cpb "github.com/openconfig/attestz/proto/common_definitions"
	apb "github.com/openconfig/attestz/proto/tpm_attestz"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/encoding/prototext"
)

var (
	addr                = flag.String("addr", "localhost:50051", "Address of the TpmAttestzService gRPC server")
	ownerCACert         = flag.String("owner_ca_cert", "", "Path to the owner CA certificate file")
	ownerCAKey          = flag.String("owner_ca_key", "", "Path to the owner CA private key file")
	expectedPCRsFlag    = flag.String("expected_pcrs", "", `JSON string mapping PCR index to hex digest (e.g. '{"0":"a1b2...","4":"c3d4..."}')`)
	hashAlgoFlag        = flag.String("hash_algo", "SHA384", `TPM 2.0 PCR hash algorithm ("SHA256" or "SHA384")`)
	controlCardRoleFlag = flag.String("control_card_role", "CONTROL_CARD_ROLE_ACTIVE", `Control card role to attest ("CONTROL_CARD_ROLE_ACTIVE", "CONTROL_CARD_ROLE_STANDBY", or "CONTROL_CARD_ROLE_CHASSIS")`)
)

// parseExpectedPCRs parses a JSON string mapping PCR index to hex digest, and PCR indices.
func parseExpectedPCRs(jsonStr string) (map[int][]byte, []int32, error) {
	if jsonStr == "" {
		return nil, nil, errors.New("expected_pcrs flag is required")
	}
	var rawMap map[int]string
	if err := json.Unmarshal([]byte(jsonStr), &rawMap); err != nil {
		return nil, nil, fmt.Errorf("failed to parse expected_pcrs JSON: %w", err)
	}
	if len(rawMap) == 0 {
		return nil, nil, errors.New("expected_pcrs cannot be empty")
	}
	pcrs := make(map[int][]byte, len(rawMap))
	indices := make([]int32, 0, len(rawMap))
	for idx, v := range rawMap {
		indices = append(indices, int32(idx))
		val, err := hex.DecodeString(v)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid hex value for PCR %d: %w", idx, err)
		}
		pcrs[idx] = val
	}
	slices.Sort(indices)
	return pcrs, indices, nil
}

// parseHashAlgo parses a string into a Tpm20HashAlgo (supports SHA256 and SHA384).
func parseHashAlgo(s string) (cpb.Tpm20HashAlgo, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "SHA256", "TPM_2_0_HASH_ALGO_SHA256":
		return cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA256, nil
	case "SHA384", "TPM_2_0_HASH_ALGO_SHA384":
		return cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA384, nil
	default:
		return cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_UNSPECIFIED, fmt.Errorf("unsupported hash algorithm %q: must be SHA256 or SHA384", s)
	}
}

// parseControlCardRole parses a string into a ControlCardRole using generated protobuf maps.
func parseControlCardRole(s string) (cpb.ControlCardRole, error) {
	if v, ok := cpb.ControlCardRole_value[s]; ok {
		return cpb.ControlCardRole(v), nil
	}
	return cpb.ControlCardRole_CONTROL_CARD_ROLE_UNSPECIFIED, fmt.Errorf("unsupported control card role %q", s)
}

func main() {
	flag.Parse()
	ctx := context.Background()

	hashAlgo, err := parseHashAlgo(*hashAlgoFlag)
	if err != nil {
		log.Exitf("Invalid --hash_algo: %v", err)
	}

	controlCardRole, err := parseControlCardRole(*controlCardRoleFlag)
	if err != nil {
		log.Exitf("Invalid --control_card_role: %v", err)
	}

	expectedPCRs, pcrIndices, err := parseExpectedPCRs(*expectedPCRsFlag)
	if err != nil {
		log.Exitf("Invalid --expected_pcrs: %v", err)
	}

	caCert, err := os.ReadFile(*ownerCACert)
	if err != nil {
		log.Exitf("Failed to read owner CA cert from %s: %v", *ownerCACert, err)
	}
	trustedRoots := x509.NewCertPool()
	if !trustedRoots.AppendCertsFromPEM(caCert) {
		log.Exitf("Failed to parse owner CA cert from %s", *ownerCACert)
	}

	clientCert, err := generateClientCert(*ownerCACert, *ownerCAKey)
	if err != nil {
		log.Exitf("Failed to generate client certificate: %v", err)
	}
	conn, err := grpc.NewClient(*addr, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		RootCAs:      trustedRoots,
		Certificates: []tls.Certificate{clientCert},
	})))
	if err != nil {
		log.Exitf("Failed to create gRPC client for %s: %v", *addr, err)
	}
	defer conn.Close()

	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		log.Exitf("failed to generate random nonce: %v", err)
	}

	client := apb.NewTpmAttestzServiceClient(conn)
	resp, err := client.Attest(ctx, &apb.AttestRequest{
		ControlCardSelection: &cpb.ControlCardSelection{
			ControlCardId: &cpb.ControlCardSelection_Role{
				Role: controlCardRole,
			},
		},
		Nonce:      nonce,
		HashAlgo:   hashAlgo,
		PcrIndices: pcrIndices,
	})
	if err != nil {
		log.Exitf("Attest RPC failed: %v", err)
	}

	log.Infof("AttestResponse:\n%s", prototext.Format(resp))

	if err := VerifyRemoteAttestation(resp, expectedPCRs, pcrIndices, nonce, trustedRoots, nil); err != nil {
		log.Exitf("Remote attestation verification failed: %v", err)
	}
	log.Infof("Remote attestation verification succeeded")
}
