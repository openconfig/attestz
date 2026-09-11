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

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	log "github.com/golang/glog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	cpb "github.com/openconfig/attestz/proto/common_definitions"
	epb "github.com/openconfig/attestz/proto/tpm_enrollz"
)

var (
	port            = flag.String("port", "4321", "Port to listen on")
	caCertOut       = flag.String("ca_cert_out", "", "Optional path to write the vendor CA certificate PEM")
	caCertFile      = flag.String("ca_cert", "", "Optional path to existing vendor CA certificate PEM")
	caKeyFile       = flag.String("ca_key", "", "Optional path to existing vendor CA private key PEM")
	ownerCACertFile = flag.String("owner_ca_cert", "", "Optional path to switch owner CA certificate PEM file to verify client certificates")
	insecureConn    = flag.Bool("insecure", false, "Use plaintext (insecure) connection instead of TLS")
)

// CardState holds the certificate and identity state of a control card.
type CardState struct {
	VendorID           *cpb.ControlCardVendorId
	IakCertPem         string
	IdevidCertPem      string
	OwnerIakCertPem    string
	OwnerIdevidCertPem string
}

// DeviceServer implements epb.TpmEnrollzServiceServer for the emulator.
type DeviceServer struct {
	epb.UnimplementedTpmEnrollzServiceServer

	mu           sync.RWMutex
	caCertPem    string
	activeCard   *CardState
	standbyCard  *CardState
	sslProfileID string
	tlsCert      tls.Certificate
}

// CaCertPem returns the vendor CA certificate PEM string.
func (s *DeviceServer) CaCertPem() string {
	return s.caCertPem
}

// TLSCertificate returns the device server's TLS certificate.
func (s *DeviceServer) TLSCertificate() tls.Certificate {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.tlsCert
}

// ActiveCard returns the active card state.
func (s *DeviceServer) ActiveCard() *CardState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.activeCard
}

// StandbyCard returns the standby card state.
func (s *DeviceServer) StandbyCard() *CardState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.standbyCard
}

// SslProfileID returns the configured SSL profile ID.
func (s *DeviceServer) SslProfileID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sslProfileID
}

func generateServerTLSCert(caCert *x509.Certificate, caKey *ecdsa.PrivateKey) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate server TLS key: %w", err)
	}
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate server TLS serial number: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Switch Vendor"},
			CommonName:   "localhost",
		},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	certDer, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to create server TLS cert: %w", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{certDer, caCert.Raw},
		PrivateKey:  key,
	}, nil
}

func generateCert(tmpl, parent *x509.Certificate, pub, priv any) (string, error) {
	certDer, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, priv)
	if err != nil {
		return "", err
	}
	certPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDer,
	})
	return string(certPem), nil
}

func generateCardCert(caCert *x509.Certificate, caKey *ecdsa.PrivateKey, serial string) (string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return "", fmt.Errorf("failed to generate card key: %w", err)
	}
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", fmt.Errorf("failed to generate card serial number: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   serial,
			SerialNumber: serial,
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}
	return generateCert(tmpl, caCert, &key.PublicKey, caKey)
}

func initCard(caCert *x509.Certificate, caKey *ecdsa.PrivateKey, vendorID *cpb.ControlCardVendorId) (*CardState, error) {
	iakCertPem, err := generateCardCert(caCert, caKey, vendorID.GetControlCardSerial())
	if err != nil {
		return nil, fmt.Errorf("failed to generate IAK cert: %w", err)
	}
	idevidCertPem, err := generateCardCert(caCert, caKey, vendorID.GetControlCardSerial())
	if err != nil {
		return nil, fmt.Errorf("failed to generate IDevID cert: %w", err)
	}
	return &CardState{
		VendorID:      vendorID,
		IakCertPem:    iakCertPem,
		IdevidCertPem: idevidCertPem,
	}, nil
}

// NewDeviceServerWithCA creates a new DeviceServer with the provided vendor CA.
func NewDeviceServerWithCA(caCert *x509.Certificate, caKey *ecdsa.PrivateKey, caCertPem string) (*DeviceServer, error) {
	activeVendorID := &cpb.ControlCardVendorId{
		ControlCardRole:     cpb.ControlCardRole_CONTROL_CARD_ROLE_ACTIVE,
		ControlCardSerial:   "card-serial-active-1",
		ControlCardSlot:     "slot-1",
		ChassisManufacturer: "Vendor",
		ChassisPartNumber:   "Part123",
		ChassisSerialNumber: "chassis-serial-1",
	}
	activeCard, err := initCard(caCert, caKey, activeVendorID)
	if err != nil {
		return nil, fmt.Errorf("failed to init active card: %w", err)
	}

	standbyVendorID := &cpb.ControlCardVendorId{
		ControlCardRole:     cpb.ControlCardRole_CONTROL_CARD_ROLE_STANDBY,
		ControlCardSerial:   "card-serial-standby-2",
		ControlCardSlot:     "slot-2",
		ChassisManufacturer: "Vendor",
		ChassisPartNumber:   "Part123",
		ChassisSerialNumber: "chassis-serial-1",
	}
	standbyCard, err := initCard(caCert, caKey, standbyVendorID)
	if err != nil {
		return nil, fmt.Errorf("failed to init standby card: %w", err)
	}

	tlsCert, err := generateServerTLSCert(caCert, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate server TLS cert: %w", err)
	}

	return &DeviceServer{
		caCertPem:   caCertPem,
		activeCard:  activeCard,
		standbyCard: standbyCard,
		tlsCert:     tlsCert,
	}, nil
}

// NewDeviceServer generates a self-signed vendor CA and creates a new DeviceServer.
func NewDeviceServer() (*DeviceServer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate vendor CA key: %w", err)
	}
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate vendor CA serial number: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Switch Vendor CA"},
			CommonName:   "Switch Vendor Root CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	certPem, err := generateCert(tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("failed to generate vendor CA cert: %w", err)
	}
	block, _ := pem.Decode([]byte(certPem))
	if block == nil {
		return nil, errors.New("failed to decode vendor CA PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse vendor CA cert: %w", err)
	}
	return NewDeviceServerWithCA(cert, key, certPem)
}

func (s *DeviceServer) getCard(selection *cpb.ControlCardSelection) *CardState {
	if selection == nil || selection.GetControlCardId() == nil {
		return s.activeCard
	}
	switch id := selection.GetControlCardId().(type) {
	case *cpb.ControlCardSelection_Role:
		if id.Role == cpb.ControlCardRole_CONTROL_CARD_ROLE_STANDBY {
			return s.standbyCard
		}
		return s.activeCard
	case *cpb.ControlCardSelection_Serial:
		if id.Serial == s.standbyCard.VendorID.GetControlCardSerial() {
			return s.standbyCard
		}
		return s.activeCard
	case *cpb.ControlCardSelection_Slot:
		if id.Slot == s.standbyCard.VendorID.GetControlCardSlot() {
			return s.standbyCard
		}
		return s.activeCard
	default:
		return s.activeCard
	}
}

// GetIakCert returns the IAK and IDevID certificates for the selected control card.
func (s *DeviceServer) GetIakCert(_ context.Context, req *epb.GetIakCertRequest) (*epb.GetIakCertResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	card := s.getCard(req.GetControlCardSelection())
	return &epb.GetIakCertResponse{
		ControlCardId:               card.VendorID,
		IakCert:                     card.IakCertPem,
		IdevidCert:                  card.IdevidCertPem,
		AtomicCertRotationSupported: true,
	}, nil
}

// RotateOIakCert updates the owner IAK and IDevID certificates on the device.
func (s *DeviceServer) RotateOIakCert(_ context.Context, req *epb.RotateOIakCertRequest) (*epb.RotateOIakCertResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.sslProfileID = req.GetSslProfileId()
	if len(req.GetUpdates()) > 0 {
		for _, update := range req.GetUpdates() {
			card := s.getCard(update.GetControlCardSelection())
			if card != nil {
				card.OwnerIakCertPem = update.GetOiakCert()
				card.OwnerIdevidCertPem = update.GetOidevidCert()
			}
		}
	} else if req.GetControlCardSelection() != nil {
		card := s.getCard(req.GetControlCardSelection())
		if card != nil {
			card.OwnerIakCertPem = req.GetOiakCert()
			card.OwnerIdevidCertPem = req.GetOidevidCert()
		}
	}
	return &epb.RotateOIakCertResponse{}, nil
}

// GetControlCardVendorID returns vendor identity fields for the selected control card.
func (s *DeviceServer) GetControlCardVendorID(_ context.Context, req *epb.GetControlCardVendorIDRequest) (*epb.GetControlCardVendorIDResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	card := s.getCard(req.GetControlCardSelection())
	return &epb.GetControlCardVendorIDResponse{
		ControlCardId: card.VendorID,
	}, nil
}

func loadCA(certPath, keyPath string) (*x509.Certificate, *ecdsa.PrivateKey, string, error) {
	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to read CA cert file: %w", err)
	}
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to read CA key file: %w", err)
	}
	certBlock, _ := pem.Decode(certBytes)
	if certBlock == nil {
		return nil, nil, "", errors.New("failed to decode CA cert PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to parse CA cert: %w", err)
	}
	keyBlock, _ := pem.Decode(keyBytes)
	if keyBlock == nil {
		return nil, nil, "", errors.New("failed to decode CA key PEM")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to parse CA private key: %w", err)
	}
	return cert, key, string(certBytes), nil
}

func main() {
	flag.Parse()

	var server *DeviceServer
	var err error
	if *caCertFile != "" && *caKeyFile != "" {
		cert, key, certPem, err := loadCA(*caCertFile, *caKeyFile)
		if err != nil {
			log.Exitf("Failed to load CA: %v", err)
		}
		server, err = NewDeviceServerWithCA(cert, key, certPem)
		if err != nil {
			log.Exitf("Failed to initialize Device Server with CA: %v", err)
		}
	} else {
		server, err = NewDeviceServer()
		if err != nil {
			log.Exitf("Failed to initialize Device Server: %v", err)
		}
	}

	if *caCertOut != "" {
		if err := os.WriteFile(*caCertOut, []byte(server.CaCertPem()), 0644); err != nil {
			log.Exitf("Failed to write vendor CA certificate to %s: %v", *caCertOut, err)
		}
		log.Infof("Wrote switch vendor CA certificate to %s", *caCertOut)
	}

	listenAddr := *port
	if !strings.Contains(listenAddr, ":") {
		listenAddr = ":" + listenAddr
	}
	lis, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Exitf("Failed to listen on %s: %v", listenAddr, err)
	}
	defer lis.Close()

	var serverCreds credentials.TransportCredentials
	if *insecureConn {
		log.Warning("Running Device Emulator in insecure (plaintext) mode")
	} else {
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{server.TLSCertificate()},
			ClientAuth:   tls.RequireAnyClientCert,
			MinVersion:   tls.VersionTLS13,
			MaxVersion:   tls.VersionTLS13,
		}
		if *ownerCACertFile != "" {
			ownerCAData, err := os.ReadFile(*ownerCACertFile)
			if err != nil {
				log.Exitf("Failed to read owner CA cert from %s: %v", *ownerCACertFile, err)
			}
			ownerPool := x509.NewCertPool()
			if !ownerPool.AppendCertsFromPEM(ownerCAData) {
				log.Exitf("Failed to parse owner CA cert from %s", *ownerCACertFile)
			}
			tlsConfig.ClientCAs = ownerPool
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		}
		serverCreds = credentials.NewTLS(tlsConfig)
	}

	var grpcServer *grpc.Server
	if serverCreds != nil {
		grpcServer = grpc.NewServer(grpc.Creds(serverCreds))
	} else {
		grpcServer = grpc.NewServer()
	}
	epb.RegisterTpmEnrollzServiceServer(grpcServer, server)

	log.Infof("Device Emulator listening on %s (mTLS: %v)", lis.Addr().String(), !*insecureConn)
	if err := grpcServer.Serve(lis); err != nil {
		log.Exitf("gRPC server failed: %v", err)
	}
}
