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

// Package enrollz_test implements integration tests for OpenConfig Enrollz gNSI service.
package enrollz_test

import (
	"context"
	"flag"
	"fmt"
	"testing"

	"github.com/golang/glog"
	"github.com/openconfig/attestz/test/dut"
	sutpb "github.com/openconfig/attestz/test/enrollz/proto"
	"github.com/openconfig/monax"
	"github.com/openconfig/monax/monaxtest"
	"github.com/openconfig/monax/runtime/kubernetesruntime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	config           monax.Config
	sutAddr          string
	dutTarget        *dut.Target
	enrollzSUTClient sutpb.ControllerClient
)

func init() {
	flag.StringVar(&config.AbstractSUTPath, "abstract_sut", "./sut/abstract_sut.txtpb", "Path to the Monax abstract SUT file")
	flag.StringVar(&config.LibraryPath, "library", "./sut/library.txtpb", "Path to the Monax library file")
	flag.StringVar(&config.RuntimeParametersPath, "runtime_parameters", "./sut/kubernetes_runtime_parameters.txtpb", "Path to the Monax runtime parameters file")
	flag.StringVar(&sutAddr, "sut_addr", "", "Address of the Enrollz SUT Controller via Bare Metal (e.g. localhost:9999); if set, bypasses Monax/KIND")
}

// TestMain initializes the SUT and runs the tests.
func TestMain(m *testing.M) {
	flag.Parse()
	defer glog.Flush()

	if err := runTests(m); err != nil {
		glog.Exitf("%v", err)
	}
}

// runTests manages the lifecycle of the SUT (via Monax/KIND or Bare Metal) and executes the test suite.
func runTests(m *testing.M) error {
	ctx := context.Background()

	var (
		conn    *grpc.ClientConn
		cleanup func()
		err     error
	)
	if sutAddr != "" {
		conn, cleanup, err = setupBareMetalSUT(sutAddr)
	} else {
		conn, cleanup, err = setupMonaxSUT(ctx)
	}
	if err != nil {
		return err
	}
	defer cleanup()

	glog.Infof("===========================================================================")
	glog.Infof("The Enrollz Controller SUT is now ready and running.")
	glog.Infof("===========================================================================")

	enrollzSUTClient = sutpb.NewControllerClient(conn)

	if dutTarget, err = dut.PrepareDUT(); err != nil {
		return fmt.Errorf("failed to prepare DUT: %w", err)
	}
	glog.Infof("DUT (%s:%s) is ready; starting test suite.", dutTarget.Host, dutTarget.Port)

	if code := m.Run(); code != 0 {
		return fmt.Errorf("test suite failed with exit code %d", code)
	}
	return nil
}

// setupBareMetalSUT connects directly to a pre-running Enrollz SUT Controller via Bare Metal.
func setupBareMetalSUT(addr string) (*grpc.ClientConn, func(), error) {
	glog.Infof("=========================================================================")
	glog.Infof("Connecting to Enrollz Controller SUT via Bare Metal at %s...", addr)
	glog.Infof("=========================================================================")

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to Enrollz SUT Controller via Bare Metal at %q: %w", addr, err)
	}
	cleanup := func() {
		if closeErr := conn.Close(); closeErr != nil {
			glog.Errorf("Failed to close Bare Metal SUT connection: %v", closeErr)
		}
	}
	return conn, cleanup, nil
}

// setupMonaxSUT builds and deploys the Enrollz SUT Controller container in KIND via Monax.
func setupMonaxSUT(ctx context.Context) (*grpc.ClientConn, func(), error) {
	glog.Infof("=========================================================================")
	glog.Infof("Building Enrollz Controller SUT in KIND via Monax...")
	glog.Infof("=========================================================================")

	sut, err := monaxtest.Start(ctx, &config, kubernetesruntime.New)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize SUT: %w", err)
	}
	stopSUT := func() {
		if stopErr := sut.Stop(ctx); stopErr != nil {
			glog.Errorf("Failed to stop SUT: %v", stopErr)
		}
	}

	if err := sut.Status(ctx); err != nil {
		stopSUT()
		return nil, nil, fmt.Errorf("SUT is unhealthy: %w", err)
	}

	conn, err := sut.Interfaces().GRPC(ctx, "openconfig.attestz.test.enrollz.Controller")
	if err != nil {
		stopSUT()
		return nil, nil, fmt.Errorf("failed to connect to Enrollz SUT Controller: %w", err)
	}

	cleanup := func() {
		if closeErr := conn.Close(); closeErr != nil {
			glog.Errorf("Failed to close Monax SUT connection: %v", closeErr)
		}
		stopSUT()
	}
	return conn, cleanup, nil
}
