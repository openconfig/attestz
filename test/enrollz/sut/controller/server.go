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

// Package main is the executable entrypoint for the Enrollz SUT Controller.
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

	"github.com/openconfig/attestz/test/enrollz/caservice"
	sutpb "github.com/openconfig/attestz/test/enrollz/proto"
)

// Config encapsulates all runtime configuration flags for the SUT controller.
type Config struct {
	Port         int
	VendorCACert string
	OwnerCACert  string
	OwnerCAKey   string
}

// loadConfig parses CLI flags and resolves paths with fallback to built-in default test certificates.
func loadConfig() *Config {
	cfg := &Config{}
	flag.IntVar(&cfg.Port, "controller_port", 9999, "Port for serving RPC requests")
	flag.StringVar(&cfg.VendorCACert, "vendor_ca_cert_path", "/etc/enrollz/certs/vendorca.crt", "Path to Vendor CA root certificate")
	flag.StringVar(&cfg.OwnerCACert, "owner_ca_cert_path", "/etc/enrollz/certs/ownerca.crt", "Path to Owner CA root certificate")
	flag.StringVar(&cfg.OwnerCAKey, "owner_ca_key_path", "/etc/enrollz/certs/ownerca.key", "Path to Owner CA private key")
	flag.Parse()

	// Resolve paths: Check custom/mounted Secret paths first, fall back to baked-in test certs
	cfg.VendorCACert = resolveCertPath(cfg.VendorCACert, "/app/certs/fakevendorca.crt")
	cfg.OwnerCACert = resolveCertPath(cfg.OwnerCACert, "/app/certs/fakeownerca.crt")
	cfg.OwnerCAKey = resolveCertPath(cfg.OwnerCAKey, "/app/certs/fakeownerca.key")

	return cfg
}

func main() {
	cfg := loadConfig()
	ctx := context.Background()

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.Port))
	if err != nil {
		glog.Exitf("Failed to listen on port %d: %v", cfg.Port, err)
	}
	glog.Infof("Enrollz SUT Server listening on %s", lis.Addr())

	grpcServer := grpc.NewServer()

	caEngine, err := caservice.NewEngine(ctx, cfg.VendorCACert, cfg.OwnerCACert, cfg.OwnerCAKey)
	if err != nil {
		glog.Exitf("Failed to initialize CA service engine: %v", err)
	}
	glog.Infof("Successfully initialized in-memory CA Engine")

	s := New(caEngine)
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
	glog.Infof("Enrollz SUT Server shut down cleanly")
}

// resolveCertPath checks if a custom mounted path exists; if not, falls back to the default image path.
func resolveCertPath(customPath, defaultFallback string) string {
	if _, err := os.Stat(customPath); err == nil {
		glog.Infof("Using custom certificate path: %s", customPath)
		return customPath
	}
	glog.Infof("Certificate %s not found. Falling back to default: %s", customPath, defaultFallback)
	return defaultFallback
}
