# Test Enrollz with Real Switch Chassis

The files located in this directory are intended to test [OpenConfig TPM 2.0 Enrollz](https://github.com/openconfig/attestz#tpm-20-enrollment-for-switch-owners) with a real switch chassis of your choice.

We use the **Monax Auto Test Method** via the [Monax](https://github.com/openconfig/monax) test framework to automatically build the Enrollz Controller SUT (System Under Test) container image, deploy it into a local KIND (Kubernetes IN Docker) cluster, prepare the switch chassis via `dut.PrepareDUT()`, and execute the integration test suite via `go test`.

## Prerequisite

- **A DUT (Device Under Test)**: This is the switch chassis of your choice, which must be running an image that supports the **OpenConfig TPM 2.0 Enrollz** gNSI service (listening on gRPC port `9339` by default).
  - For the **IDevID enrollment flow**, the switch must be provisioned with vendor hardware identity certificates (IDevID and IAK).

> [!NOTE] 
> If your switch requires initial vendor certificate provisioning, you can run the [Bootz test suite](https://github.com/openconfig/bootz/tree/main/test) first. **Configure the Enrollz SUT (System Under Test) Controller with the exact same Vendor Root CA certificate that you used to provision the switch during Bootz.**

- **A Test Host**: A host environment (such as a server or VM; Linux OS is recommended for local KIND networking) with IP network reachability to the DUT's management address. This host runs the **Enrollz Controller SUT** container (listening on TCP port `9999`) and executes the test suite against the DUT's gNSI service.

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

### 2. Implement `caservice.PKIProvider` ([`./caservice/caservice.go`](./caservice/caservice.go))

Implement the `PKIProvider` interface methods (`DeviceTrustBundle`, `IssueOIAK`, `IssueOIDevID`, and `GenerateClientCredentials`) in [`./caservice/caservice.go`](./caservice/caservice.go) to load your device trust anchors and sign the rotated Owner certificates (`oIAK` and `oIDevID`).

### 3. Configure Vendor & Owner CA Certificates

To verify the switch's hardware identity (IDevID/IAK) and sign the rotated Owner certificate, you must provide your Vendor Root CA certificate (`vendorca.crt`), Owner Root CA certificate (`ownerca.crt`), and Owner CA private key (`ownerca.key`) using one of the following two methods:

- **Option A: Kubernetes Secret**:
  1. Copy [`./sut/controller/deploy/secret.example.yaml`](./sut/controller/deploy/secret.example.yaml) to `./sut/controller/deploy/secret.yaml`.
  2. Paste your PEM-encoded `vendorca.crt` (the Vendor Root CA used in factory or Bootz provisioning), `ownerca.crt`, and `ownerca.key`.
  3. Apply the secret to your KIND cluster before running the test:
     ```bash
     kubectl apply -f ./sut/controller/deploy/secret.yaml
     ```
- **Option B: Baking Certificates into the Image (`./caservice/certs/`)**:
  Place your `vendorca.crt`, `ownerca.crt`, and `ownerca.key` files directly under [`./caservice/certs/`](./caservice/certs/) before running `go test`. During the Monax Docker build, these files are copied into `/app/certs/` inside the container image and loaded by the SUT controller if no Kubernetes Secret is mounted.

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
2. Apply your custom Vendor and Owner CA certificates secret to the KIND cluster:
   ```bash
   kubectl apply -f ./sut/controller/deploy/secret.yaml
   ```

### Monax Run

> [!IMPORTANT]
> The test cases in this suite are **not** meant to all be run at once. Depending on your switch hardware configuration, you can either:
>
> 1. **Select the applicable test case(s) using the `-run` flag**.
>
> 2. **Delete or comment out inapplicable test cases** in [`./enrollz_test.go`](./enrollz_test.go) before running `go test`.

From the `attestz` repository **root** directory, run the test case corresponding to your switch chassis:

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

| Test Case                                                         | Description                                                                                                                             | Target Topology                       | Expected Result                                                                                                      |
| :---------------------------------------------------------------- | :-------------------------------------------------------------------------------------------------------------------------------------- | :------------------------------------ | :------------------------------------------------------------------------------------------------------------------- |
| `TestEnrollz_InitialEnrollment_TPM20_IDevID_SingleControlCard`    | Validates initial TPM 2.0 enrollment of an active control card (`CONTROL_CARD_ROLE_ACTIVE`) on a single-processor DUT.                  | Single Route Processor / Fixed Switch | SUT validates vendor certificates (IDevID & IAK), rotates owner certificates, and returns `OK`.                      |
| `TestEnrollz_InitialEnrollment_TPM20_IDevID_MultipleControlCards` | Validates batch initial TPM 2.0 enrollment across redundant control cards (`CONTROL_CARD_ROLE_ACTIVE` and `CONTROL_CARD_ROLE_STANDBY`). | Modular Chassis / Dual Supervisor     | Both control cards complete certificate validation, rotate owner certificates in a single workflow, and return `OK`. |
