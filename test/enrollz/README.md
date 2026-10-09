# Test Enrollz with Real Switch Chassis

The files located in this directory are intended to test [OpenConfig TPM 2.0 Enrollz](https://github.com/openconfig/attestz#tpm-20-enrollment-for-switch-owners) with a real switch chassis of your choice. We support two methods for executing the test suite:

- **Bare Metal Test Method**: Run the Enrollz Controller SUT (System Under Test) process directly on a test host (either manually in a separate terminal or via an automated test harness), and run `go test` with `-sut_addr=<host>:<port>` (no Docker or KIND required).

- **Monax Auto Test Method**: Use the [Monax](https://github.com/openconfig/monax) test framework to automatically build the Enrollz Controller SUT container image, deploy it into a local KIND (Kubernetes IN Docker) cluster, prepare the switch chassis via `dut.PrepareDUT()`, and execute the integration test suite via `go test`.

Please note that all example commands in this README are shown from the `attestz` repository **root** directory.

## Prerequisite

> [!NOTE]
> If your switch requires initial vendor certificate provisioning, you can run the [Bootz test suite](https://github.com/openconfig/bootz/tree/main/test) first. **Configure the Enrollz SUT (System Under Test) Controller with the exact same Vendor Root CA certificate that you used to provision the switch during Bootz.**

- **A DUT (Device Under Test)**: This is the switch chassis of your choice, which must be running an image that supports the **OpenConfig TPM 2.0 Enrollz** gNSI service (listening on gRPC port `9339` by default).
  - For the **IDevID enrollment flow**, the switch must be provisioned with vendor hardware identity certificates (IDevID and IAK).

- **A Test Host**: A host environment (such as a server or VM; Linux OS is recommended) with IP network reachability to the DUT's management address. This host runs the **Enrollz Controller SUT** (listening on TCP port `9999`) and executes the test suite against the DUT's gNSI service.

---

## Vendor Onboarding & Setup

### 1. Implement `dut.PrepareDUT()` ([`../dut/dut.go`](../dut/dut.go))

Implement the `PrepareDUT()` function in [`../dut/dut.go`](../dut/dut.go) to perform any vendor-specific switch preparation and return your switch's management IP address and gNSI port:

```go
func PrepareDUT() (*Target, error) {
    return &Target{
        Host: "192.168.1.100", // Replace with your switch's management IP or hostname
        Port: "9339",          // Replace with your switch's gNSI port
    }, nil
}
```

> [!NOTE]
> Since `dut.go` is completely vendor-specific, you can keep your implementation private for your own testing only. You do not need to submit or publish your implementation on GitHub.

### 2. Implement `caservice.PKIProvider` ([`../caservice/caservice.go`](../caservice/caservice.go))

Implement the `PKIProvider` interface methods (`DeviceTrustBundle`, `IssueOIAK`, `IssueOIDevID`, and `GenerateClientCredentials`) in [`../caservice/caservice.go`](../caservice/caservice.go) to load your device trust anchors and sign the rotated Owner certificates (`oIAK` and `oIDevID`).

### 3. Configure Vendor & Owner CA Certificates

To verify the switch's hardware identity (IDevID/IAK) and sign the rotated Owner certificate, you must provide your Vendor Root CA certificate (`vendorca.crt`), Owner Root CA certificate (`ownerca.crt`), and Owner CA private key (`ownerca.key`):

- **Option A: Local Certificate Directory (Bare Metal or Monax/KIND)**:
  Place your `vendorca.crt`, `ownerca.crt`, and `ownerca.key` files directly under [`../caservice/certs/`](../caservice/certs/).
  - **In Bare Metal mode**, [`./run_enrollz_sut.sh`](./run_enrollz_sut.sh) passes these `../caservice/certs/` paths via `--vendor_ca_cert_path`, `--owner_ca_cert_path`, and `--owner_ca_key_path` (and you can override them by passing flags to the script).
  - **In Monax (KIND) mode**, these files are copied into `/app/certs/` inside the container image during the Monax Docker build and used automatically if no Kubernetes Secret is mounted at `/etc/enrollz/certs/`.

- **Option B: Kubernetes Secret (Monax/KIND only)**:
  1. Copy [`./sut/controller/deploy/secret.example.yaml`](./sut/controller/deploy/secret.example.yaml) to `./sut/controller/deploy/secret.yaml`.
  2. Paste your PEM-encoded `vendorca.crt` (the Vendor Root CA used in factory or Bootz provisioning), `ownerca.crt`, and `ownerca.key`.
  3. Apply the secret to your KIND cluster before running the test:

     ```bash
     kubectl apply -f ./test/enrollz/sut/controller/deploy/secret.yaml
     ```

     When mounted at `/etc/enrollz/certs/`, the Kubernetes Secret takes precedence over the baked-in `/app/certs/` files.

### 4. Select Applicable Test Cases ([`./enrollz_test.go`](./enrollz_test.go))

Because each test case targets a specific switch hardware topology (e.g., a single-supervisor switch vs. a dual-supervisor modular chassis), not all test cases in this suite apply to a single physical DUT. Depending on your switch hardware configuration, you can either:

1. **Select the applicable test case(s) using the `-run` flag**, which accepts a Go regular expression (e.g., `-run "TestCaseA|TestCaseB"` to run multiple test cases in a single invocation).
2. **Delete or comment out inapplicable test cases** in [`./enrollz_test.go`](./enrollz_test.go) and omit `-run` to run all remaining test cases together.

---

## Bare Metal Test Method

### Bare Metal Setup (a one-time effort)

1. Ensure IP network connectivity between the test host and the management address of your switch chassis.
2. Update `PrepareDUT()` in [`../dut/dut.go`](../dut/dut.go) with your switch's management IP and gNSI port.
3. Place your `vendorca.crt`, `ownerca.crt`, and `ownerca.key` files in [`../caservice/certs/`](../caservice/certs/) (or pass their paths via flags when starting the SUT controller).

### Bare Metal Run

1. **Build and Start the Enrollz Controller SUT**

   From the `attestz` repository **root** directory, run the Bash script below to build and start the SUT controller (either in a dedicated terminal or as a background process in your test harness):

   ```bash
   ./test/enrollz/run_enrollz_sut.sh
   ```

   By default, the SUT controller listens on port `9999` and loads certificates from `./test/caservice/certs/`.

   > [!NOTE]
   > To override these defaults, pass additional flags:
   >
   > ```bash
   > ./test/enrollz/run_enrollz_sut.sh \
   >   --controller_port=9999 \
   >   --vendor_ca_cert_path=./test/caservice/certs/vendorca.crt \
   >   --owner_ca_cert_path=./test/caservice/certs/ownerca.crt \
   >   --owner_ca_key_path=./test/caservice/certs/ownerca.key
   > ```

2. **Run the Test Suite**

   From the `attestz` repository **root** directory (e.g., in a second terminal or from your test runner), run `go test` with `-args -sut_addr=localhost:9999` so `TestMain` connects directly to your running SUT controller instead of starting a KIND cluster:
   - For Single Control Card / Fixed Switch:

     ```bash
     go test -v -count=1 -run TestEnrollz_InitialEnrollment_TPM20_IDevID_SingleControlCard ./test/enrollz -args -sut_addr=localhost:9999 -logtostderr -v=2
     ```

   - For Dual / Multiple Control Cards (Active + Standby):

     ```bash
     go test -v -count=1 -run TestEnrollz_InitialEnrollment_TPM20_IDevID_MultipleControlCards ./test/enrollz -args -sut_addr=localhost:9999 -logtostderr -v=2
     ```

### Bare Metal Cleanup

Stop the running SUT controller process (e.g., press `Ctrl+C` in the terminal running `./test/enrollz/run_enrollz_sut.sh`).

---

## Monax Auto Test Method

### Monax Setup (a one-time effort)

1. Install [Docker](https://www.docker.com/) and [KIND (Kubernetes IN Docker)](https://kind.sigs.k8s.io/) on the test host.
2. Ensure IP network connectivity between the test host and the management address of your switch chassis.
3. Update `PrepareDUT()` in [`../dut/dut.go`](../dut/dut.go) with your switch's management IP and gNSI port.

### Monax Preparation

1. Create a KIND virtual cluster (if not already running):

   ```bash
   kind create cluster
   ```

2. _(Optional)_ If using a Kubernetes Secret (Option B in [Configure Vendor & Owner CA Certificates](#3-configure-vendor--owner-ca-certificates)), apply it to the KIND cluster:

   ```bash
   kubectl apply -f ./test/enrollz/sut/controller/deploy/secret.yaml
   ```

### Monax Run

From the `attestz` repository **root** directory, run the test case corresponding to your switch chassis (without `-sut_addr`):

- For Single Control Card / Fixed Switch:

  ```bash
  go test -v -count=1 -run TestEnrollz_InitialEnrollment_TPM20_IDevID_SingleControlCard ./test/enrollz -args -logtostderr -v=2
  ```

- For Dual / Multiple Control Cards (Active + Standby):

  ```bash
  go test -v -count=1 -run TestEnrollz_InitialEnrollment_TPM20_IDevID_MultipleControlCards ./test/enrollz -args -logtostderr -v=2
  ```

<br>

**What happens during `go test`:**

1. `TestMain` automatically builds the `openconfig/enrollz-sut:latest` Docker image from the repository root, loads it into KIND, deploys the SUT controller pod and service into the `default` namespace, and establishes a gRPC client connection (`enrollzSUTClient`).
2. `TestMain` calls `dut.PrepareDUT()` to prepare the switch and obtain `dutTarget.Host` and `dutTarget.Port`.
3. Each test case invokes `enrollzSUTClient.EnrollDevice()`, instructing the SUT controller to dial the switch over gNSI, verify its hardware identity certificates against the Vendor CA bundle, verify the TPM 2.0 quote, and rotate/install the new Owner certificate.

### Monax Cleanup

1. When the test finishes, Monax automatically stops and deletes the SUT deployment and service from the KIND cluster.
2. If you want to delete the KIND virtual cluster completely when done testing:

   ```bash
   kind delete cluster
   ```

> [!NOTE]
> If you plan to run more tests later, you can skip deleting the KIND cluster so you don't need to recreate it and re-apply the secret before the next test run.

---

## Test Case Summary

| Test Case                                                                           | Description                                                                                                                             | Target Topology                          | Expected Result                                                                                                      |
| :---------------------------------------------------------------------------------- | :-------------------------------------------------------------------------------------------------------------------------------------- | :--------------------------------------- | :------------------------------------------------------------------------------------------------------------------- |
| `TestEnrollz_`<br>`InitialEnrollment_`<br>`TPM20_IDevID_`<br>`SingleControlCard`    | Validates initial TPM 2.0 enrollment of an active control card (`CONTROL_CARD_ROLE_ACTIVE`) on a single-processor DUT.                  | Single Route Processor /<br>Fixed Switch | SUT validates vendor certificates (IDevID & IAK), rotates owner certificates, and returns `OK`.                      |
| `TestEnrollz_`<br>`InitialEnrollment_`<br>`TPM20_IDevID_`<br>`MultipleControlCards` | Validates batch initial TPM 2.0 enrollment across redundant control cards (`CONTROL_CARD_ROLE_ACTIVE` and `CONTROL_CARD_ROLE_STANDBY`). | Modular Chassis /<br>Dual Supervisor     | Both control cards complete certificate validation, rotate owner certificates in a single workflow, and return `OK`. |
