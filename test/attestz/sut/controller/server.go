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

// Package main is the executable entrypoint for the Attestz SUT Controller.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/golang/glog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"github.com/openconfig/attestz/test/attestz/pcrprovider"
	sutpb "github.com/openconfig/attestz/test/attestz/proto"
	"github.com/openconfig/attestz/test/attestz/tpmutil"
	"github.com/openconfig/attestz/test/caservice"
)

// Config encapsulates all runtime configuration flags for the SUT controller.
type Config struct {
	Port        int
	OwnerCACert string
	OwnerCAKey  string
}

// loadConfig parses CLI flags and resolves certificate paths from a mounted K8s Secret or the container image.
func loadConfig() *Config {
	cfg := &Config{}
	flag.IntVar(&cfg.Port, "controller_port", 9999, "Port for serving RPC requests")
	flag.StringVar(&cfg.OwnerCACert, "owner_ca_cert_path", "/etc/attestz/certs/ownerca.crt", "Path to Owner CA root certificate")
	flag.StringVar(&cfg.OwnerCAKey, "owner_ca_key_path", "/etc/attestz/certs/ownerca.key", "Path to Owner CA private key")
	flag.Parse()

	// Resolve paths: Check mounted K8s Secret paths first, fall back to baked-in image certs
	cfg.OwnerCACert = resolveCertPath(cfg.OwnerCACert, "/app/certs/ownerca.crt")
	cfg.OwnerCAKey = resolveCertPath(cfg.OwnerCAKey, "/app/certs/ownerca.key")

	return cfg
}

func main() {
	cfg := loadConfig()
	ctx := context.Background()

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.Port))
	if err != nil {
		glog.Exitf("Failed to listen on port %d: %v", cfg.Port, err)
	}
	glog.Infof("Attestz SUT Server listening on %s", lis.Addr())

	grpcServer := grpc.NewServer()

	caEngine, err := caservice.NewEngine(ctx, "", cfg.OwnerCACert, cfg.OwnerCAKey)
	if err != nil {
		glog.Exitf("Failed to initialize CA service engine: %v", err)
	}
	glog.Infof("Successfully initialized in-memory CA Engine")

	pcrProvider := pcrprovider.NewTestPCRProvider()
	tpmCertUtils := tpmutil.NewTPMCertUtils()

	s := New(caEngine, pcrProvider, tpmCertUtils)
	sutpb.RegisterControllerServer(grpcServer, s)
	reflection.Register(grpcServer)

	// Graceful shutdown handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigChan
		glog.Infof("Received signal %v, shutting down...", sig)
		grpcServer.GracefulStop()
	}()

	if err := grpcServer.Serve(lis); err != nil {
		glog.Exitf("Failed to serve: %v", err)
	}
	glog.Infof("Attestz SUT Server shut down cleanly")
}

// resolveCertPath checks if an optional K8s Secret mount path exists; if not, falls back to the default image path.
func resolveCertPath(secretMountPath, defaultFallback string) string {
	if _, err := os.Stat(secretMountPath); err == nil {
		glog.Infof("Using mounted secret certificate path: %s", secretMountPath)
		return secretMountPath
	}
	glog.Infof("Mounted secret certificate %s not found. Falling back to default: %s", secretMountPath, defaultFallback)
	return defaultFallback
}
