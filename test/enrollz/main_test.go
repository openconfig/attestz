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
	"testing"

	"github.com/golang/glog"
	"github.com/openconfig/attestz/test/dut"
	sutpb "github.com/openconfig/attestz/test/enrollz/proto"
	"github.com/openconfig/monax"
	"github.com/openconfig/monax/monaxtest"
	"github.com/openconfig/monax/runtime/kubernetesruntime"
)

var (
	config           monax.Config
	dutTarget        *dut.Target
	enrollzSUTClient sutpb.ControllerClient
)

func init() {
	flag.StringVar(&config.AbstractSUTPath, "abstract_sut", "./sut/abstract_sut.txtpb", "Path to the Monax abstract SUT file")
	flag.StringVar(&config.LibraryPath, "library", "./sut/library.txtpb", "Path to the Monax library file")
	flag.StringVar(&config.RuntimeParametersPath, "runtime_parameters", "./sut/kubernetes_runtime_parameters.txtpb", "Path to the Monax runtime parameters file")
}

// TestMain initializes the SUT and runs the tests.
func TestMain(m *testing.M) {
	flag.Parse()
	defer glog.Flush()

	glog.Infof("=========================================================================")
	glog.Infof("Building Enrollz Controller SUT and preparing DUT for Enrollz testing...")
	glog.Infof("=========================================================================")

	ctx := context.Background()

	sut, err := monaxtest.Start(ctx, &config, kubernetesruntime.New)
	if err != nil {
		glog.Exitf("Failed to initialize SUT: %v", err)
	}
	defer func() {
		if err := sut.Stop(ctx); err != nil {
			glog.Errorf("Failed to stop SUT: %v", err)
		}
	}()
	if err := sut.Status(ctx); err != nil {
		glog.Exitf("SUT is unhealthy: %v", err)
	}

	conn, err := sut.Interfaces().GRPC(ctx, "openconfig.attestz.test.enrollz.Controller")
	if err != nil {
		glog.Exitf("Failed to connect to Enrollz SUT Controller: %v", err)
	}
	defer conn.Close()
	enrollzSUTClient = sutpb.NewControllerClient(conn)

	glog.Infof("===========================================================================")
	glog.Infof("The Enrollz Controller SUT is now ready and running in a Monax container.")
	glog.Infof("===========================================================================")

	if dutTarget, err = dut.PrepareDUT(); err != nil {
		sut.Stop(ctx)
		glog.Exitf("Failed to prepare DUT: %v", err)
	}
	glog.Infof("DUT (%s:%s) is ready; starting test suite.", dutTarget.Host, dutTarget.Port)

	m.Run()
}
