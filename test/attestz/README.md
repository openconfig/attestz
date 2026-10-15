# Test Attestz with a Real Switch Chassis

The files located in this directory are intended to test [OpenConfig TPM 2.0 Attestz](https://github.com/openconfig/attestz) with a real switch chassis of your choice. We support two methods for executing the test suite:

- **Bare Metal Test Method**: Run the Attestz Controller SUT (System Under Test) process directly on a test host (either manually in a separate terminal or via an automated test harness), and run `go test` with `-sut_addr=<host>:<port>` (no Docker or KIND required).

- **Monax Auto Test Method**: Use the [Monax](https://github.com/openconfig/monax) test framework to automatically build the Attestz Controller SUT container image, deploy it into a local KIND (Kubernetes IN Docker) cluster, prepare the switch chassis via `dut.PrepareDUT()`, and execute the integration test suite via `go test`.

Please note that all example commands in this readme are shown from the `attestz` repository **root** directory.

## Prerequisites

> [!NOTE]
> If your switch has not yet been provisioned with Owner certificates, you can run the [Enrollz test suite](../enrollz/README.md) first. Configure the Attestz SUT (System Under Test) Controller with the exact same Owner Root CA certificate (`ownerca.crt`) and private key (`ownerca.key`) that you used to enroll the switch during Enrollz.

- **A DUT (Device Under Test)**: This is the switch chassis of your choice, which must be running an image that supports the **OpenConfig TPM 2.0 Attestz** gNSI service (listening on gRPC port `9339` by default).
  - The switch must already be enrolled with Owner certificates (`oIDevID` for mTLS server authentication and `oIAK` for signing TPM 2.0 quotes).

- **A Test Host**: A host environment (such as a server or VM; Linux OS is recommended) with IP network reachability to the DUT's management address. This host runs the **Attestz Controller SUT** (listening on TCP port `9999`) and executes the test suite against the DUT's gNSI service.

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
> Since `dut.go` is completely vendor-specific, you can keep your implementation private for your own testing. You do not need to submit or publish your implementation on GitHub.

### 2. Implement `caservice.PKIProvider` ([`../caservice/caservice.go`](../caservice/caservice.go))

Implement the `PKIProvider` interface methods (`OwnerTrustBundle` and `GenerateClientCredentials`) in [`../caservice/caservice.go`](../caservice/caservice.go) so the Attestz SUT controller can authenticate the switch's `oIDevID` and `oIAK` certificates against your Owner Root CA and present mTLS client credentials to the DUT.

### 3. Implement `pcrprovider.TestPCRProvider` ([`./pcrprovider/pcrprovider.go`](./pcrprovider/pcrprovider.go))

Implement `ExpectedPCRs(ctx context.Context, device string) (map[int32][][]byte, error)` in [`./pcrprovider/pcrprovider.go`](./pcrprovider/pcrprovider.go) to return the reference ("golden") TPM 2.0 PCR measurements (index-to-digests mapping) expected for your switch's hardware and boot software state. Each PCR index maps to one or more acceptable raw binary digests.

### 4. Implement `tpmutil.TPMCertUtils` ([`./tpmutil/tpm2.go`](./tpmutil/tpm2.go))

Implement the `TPMCertUtils` interfaces in [`./tpmutil/tpm2.go`](./tpmutil/tpm2.go) to validate the switch's `oIAK` X.509 certificate profile and convert its public key into a `tpm2.TPMTPublic` structure per the [TCG specification](https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-Keys-for-Device-Identity-and-Attestation-v1.10r9_pub.pdf) (Section 7.4.4).

### 5. Configure Owner CA Certificates

To verify the switch's Owner certificates (`oIDevID` and `oIAK`) and sign mTLS client credentials, you must provide your Owner Root CA certificate (`ownerca.crt`) and Owner CA private key (`ownerca.key`):

- **Option A: Local Certificate Directory (Bare Metal or Monax/KIND)**:
  Place your `ownerca.crt` and `ownerca.key` files directly under [`../caservice/certs/`](../caservice/certs/).
  - **In Bare Metal mode**, [`./run_attestz_sut.sh`](./run_attestz_sut.sh) passes these `../caservice/certs/` paths via `--owner_ca_cert_path` and `--owner_ca_key_path` (you can override them by passing `--owner_ca_cert_path=<path>` and `--owner_ca_key_path=<path>` to the script; see the note in [Bare Metal Run](#bare-metal-run)).
  - **In Monax (KIND) mode**, these files are copied into `/app/certs/` inside the container image during the Monax Docker build and used automatically if no Kubernetes Secret is mounted at `/etc/attestz/certs/`.

- **Option B: Kubernetes Secret (Monax/KIND only)**:
  1. Copy [`./sut/controller/deploy/secret.example.yaml`](./sut/controller/deploy/secret.example.yaml) to `./sut/controller/deploy/secret.yaml`.
  2. Paste your PEM-encoded `ownerca.crt` (the Owner Root CA used during Enrollz) and `ownerca.key`.
  3. Apply the secret to your KIND cluster before running the test:

     ```bash
     kubectl apply -f ./test/attestz/sut/controller/deploy/secret.yaml
     ```

     When mounted at `/etc/attestz/certs/`, the Kubernetes Secret takes precedence over the baked-in `/app/certs/` files.

### 6. Select Applicable Test Cases ([`./attestz_test.go`](./attestz_test.go))

Because each test case targets a specific switch hardware topology (e.g., a single-supervisor switch vs. a dual-supervisor modular chassis), not all test cases in this suite apply to a single physical DUT. Depending on your switch hardware configuration, you can either:

1. **Select the applicable test case(s) using the `-run` flag**, which accepts a Go regular expression (e.g., `-run "TestCaseA|TestCaseB"` to run multiple test cases in a single invocation).
2. **Delete or comment out inapplicable test cases** in [`./attestz_test.go`](./attestz_test.go) and omit `-run` to run all remaining test cases together.

---

## Bare Metal Test Method

### Bare Metal Setup (a one-time effort)

1. Ensure IP network connectivity between the test host and the management address of your switch chassis.
2. Update `PrepareDUT()` in [`../dut/dut.go`](../dut/dut.go), `PKIProvider` in [`../caservice/caservice.go`](../caservice/caservice.go), `ExpectedPCRs()` in [`./pcrprovider/pcrprovider.go`](./pcrprovider/pcrprovider.go), and `TPMCertUtils` in [`./tpmutil/tpm2.go`](./tpmutil/tpm2.go).
3. Place your `ownerca.crt` and `ownerca.key` files in [`../caservice/certs/`](../caservice/certs/) (or pass their paths via flags when starting the SUT controller).

### Bare Metal Run

1. **Build and Start the Attestz Controller SUT**

   From the `attestz` repository **root** directory, run the Bash script below to build and start the SUT controller (either in a dedicated terminal or as a background process in your test harness):

   ```bash
   ./test/attestz/run_attestz_sut.sh
   ```

   By default, the SUT controller listens on port `9999` and loads certificates from `./test/caservice/certs/`.

   > [!NOTE]
   > To override these defaults, pass additional flags:
   >
   > ```bash
   > ./test/attestz/run_attestz_sut.sh \
   >   --controller_port=9999 \
   >   --owner_ca_cert_path=./test/caservice/certs/ownerca.crt \
   >   --owner_ca_key_path=./test/caservice/certs/ownerca.key
   > ```

2. **Run the Test Suite**

   From the `attestz` repository **root** directory (e.g., in a second terminal or from your test runner), run `go test` with `-args -sut_addr=localhost:9999` so `TestMain` connects directly to your running SUT controller instead of starting a KIND cluster:
   - For Single Control Card / Fixed Switch:

     ```bash
     go test -v -count=1 -run TestAttestz_InitialAttestation_TPM20_IDevID_SingleControlCard ./test/attestz -args -sut_addr=localhost:9999 -logtostderr -v=2
     ```

   - For Dual / Multiple Control Cards (Active + Standby):

     ```bash
     go test -v -count=1 -run TestAttestz_InitialAttestation_TPM20_IDevID_MultipleControlCards ./test/attestz -args -sut_addr=localhost:9999 -logtostderr -v=2
     ```

### Bare Metal Cleanup

Stop the running SUT controller process (e.g., press `Ctrl+C` in the terminal running `./test/attestz/run_attestz_sut.sh`).

---

## Monax Auto Test Method

### Monax Setup (a one-time effort)

1. Install [Docker](https://www.docker.com/) and [KIND (Kubernetes IN Docker)](https://kind.sigs.k8s.io/) on the test host.
2. Ensure IP network connectivity between the test host and the management address of your switch chassis.
3. Update `PrepareDUT()` in [`../dut/dut.go`](../dut/dut.go), `PKIProvider` in [`../caservice/caservice.go`](../caservice/caservice.go), `ExpectedPCRs()` in [`./pcrprovider/pcrprovider.go`](./pcrprovider/pcrprovider.go), and `TPMCertUtils` in [`./tpmutil/tpm2.go`](./tpmutil/tpm2.go).

### Monax Preparation

1. Create a KIND virtual cluster (if not already running):

   ```bash
   kind create cluster
   ```

2. _(Optional)_ If using a Kubernetes Secret (Option B in [Configure Owner CA Certificates](#5-configure-owner-ca-certificates)), apply it to the KIND cluster:

   ```bash
   kubectl apply -f ./test/attestz/sut/controller/deploy/secret.yaml
   ```

### Monax Run

From the `attestz` repository **root** directory, run the test case corresponding to your switch chassis (without `-sut_addr`):

- For Single Control Card / Fixed Switch:

  ```bash
  go test -v -count=1 -run TestAttestz_InitialAttestation_TPM20_IDevID_SingleControlCard ./test/attestz -args -logtostderr -v=2
  ```

- For Dual / Multiple Control Cards (Active + Standby):

  ```bash
  go test -v -count=1 -run TestAttestz_InitialAttestation_TPM20_IDevID_MultipleControlCards ./test/attestz -args -logtostderr -v=2
  ```

<br>

**What happens during `go test`:**

1. `TestMain` automatically builds the `openconfig/attestz-sut:latest` Docker image from the repository root, loads it into KIND, deploys the SUT controller pod and service into the `default` namespace, and establishes a gRPC client connection (`attestzSUTClient`).
2. `TestMain` calls `dut.PrepareDUT()` to prepare the switch and obtain `dutTarget.Host` and `dutTarget.Port`.
3. Each test case invokes `attestzSUTClient.AttestDevice()`, instructing the SUT controller to retrieve expected golden PCR measurements via `PCRProvider`, dial the switch over gNSI, request a signed TPM 2.0 quote, verify the `oIAK` certificate against the Owner CA trust bundle, verify the TPM 2.0 quote and signature via `TPMCertUtils`, and validate the reported PCR digests.

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

| Test Case                                                                            | Description                                                                                | Target Topology                      | Expected Result                                                                                                                                            |
| :----------------------------------------------------------------------------------- | :----------------------------------------------------------------------------------------- | :----------------------------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `TestAttestz_`<br>`InitialAttestation_`<br>`TPM20_IDevID_`<br>`SingleControlCard`    | Validates remote TPM 2.0 attestation of an active control card on a single-supervisor DUT. | Single Supervisor /<br>Fixed Switch  | SUT verifies the `oIAK` certificate, validates the TPM 2.0 quote signature and nonce, confirms PCR values match expected golden digests, and returns `OK`. |
| `TestAttestz_`<br>`InitialAttestation_`<br>`TPM20_IDevID_`<br>`MultipleControlCards` | Validates remote TPM 2.0 attestation across redundant (active and standby) control cards.  | Modular Chassis /<br>Dual Supervisor | Both control cards pass `oIAK` certificate verification, quote signature verification, and golden PCR validation, returning `OK`.                          |
