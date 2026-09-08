# Attestz Client

This package provides a Go client binary that invokes the `TpmAttestzService.Attest` gRPC method on a network device.

## Request Details

The client issues an `AttestRequest` configured as follows:

```text
AttestRequest{
    control_card_selection: ControlCardSelection{
        control_card_id: ControlCardSelection_Role{
            Role: CONTROL_CARD_ROLE_ACTIVE
        }
    },
    nonce: <32_byte_random>,
    hash_algo: TPM_2_0_HASH_ALGO_SHA384,
    pcr_indices: [<indices_from_expected_pcrs>]
}
```

- **Control Card Selection**: Active control card (`CONTROL_CARD_ROLE_ACTIVE`).
- **Nonce**: 32 cryptographically secure random bytes generated per request via `crypto/rand`.
- **Hash Algorithm**: TPM 2.0 PCR bank (`TPM_2_0_HASH_ALGO_SHA384` by default, or `TPM_2_0_HASH_ALGO_SHA256`).
- **PCR Indices**: Dynamically derived from the keys in `--expected_pcrs`.

---

## Configuration Flags

The binary accepts the following flags:

| Flag             | Type   | Default           | Description                                                                       |
| ---------------- | ------ | ----------------- | --------------------------------------------------------------------------------- |
| `-addr`          | string | `localhost:50051` | Address (`host:port`) of the `TpmAttestzService` gRPC server.                     |
| `-insecure`      | bool   | `false`           | Use insecure transport credentials (disable TLS). Set to `false` for TLS.         |
| `-owner_ca_cert` | string | `""`              | Path to the owner CA certificate file for TLS configuration.                      |
| `-owner_ca_key`  | string | `""`              | Path to the owner CA private key file for generating client mTLS credentials.     |
| `-expected_pcrs` | string | `""`              | JSON string mapping PCR index to hex digest (e.g. `'{"0":"<hex>","4":"<hex>"}'`). |
| `-hash_algo`     | string | `SHA384`          | TPM 2.0 PCR hash algorithm (`"SHA256"` or `"SHA384"`).                            |

---

## Building and Running with Bazel

```bash
bazel run //service/attest:attest -- \
  --insecure \
  --addr='[::]:4322' \
  --expected_pcrs='{"0":"...","4":"...","7":"..."}'
```

Unit tests can be run with:

```bash
bazel test //service/attest/...
```

---

## Running with Docker (OCI Container)

The package includes OCI rules (`rules_oci`) to package and load the `attest` binary into Docker.

### 1. Build and load the Docker image

Build the container image and load it directly into your local Docker daemon:

```bash
bazel run //service/attest:load_image
```

This tags the image as `open-config-attest:latest`.

### 2. Run the Docker container

Run the container against a target gRPC server:

```bash
docker run --rm --network=host \
  -v ~/path/to/certs:/certs/ open-config-attest:latest \
  --owner_ca_cert=/certs/owner_ca_cert.pem \
  --owner_ca_key=/certs/owner_ca_key.pem \
  --expected_pcrs='{"0":"AA","4":"BB","7":"CC"}' \
  --addr='[::]:4322' --alsologtostderr
```
