# Enrollz and Attestz _(Switch Owner)_ Services Emulation

The code located in this directory is intended to emulate typical Enrollz
and Attestz Services hosted by a switch owner. These services will
communicate with the networking devices hosting gRPC `enrollz` and
`attestz` endpoints and drive TPM 2.0 enrollment and attestation workflows.

## Running

You can run the Enrollz service emulator using `bazel run`:

> [!NOTE]
> The `--vendor_ca_trust_bundle`, `--owner_ca_cert`, and `--owner_ca_key` flags must be provided. When testing with the device emulator, pass the path to the certificate exported via the device emulator's `--ca_cert_out` flag along with the switch owner CA certificate and private key.

```bash
bazel run //service/emulator:enrollz_emulator -- \
  --alsologtostderr \
  --vendor_ca_trust_bundle=/tmp/vendor_ca.pem \
  --owner_ca_cert=/tmp/owner_ca_cert.pem \
  --owner_ca_key=/tmp/owner_ca_key.pem
```

### Flags

- `--vendor_ca_trust_bundle`: Path to switch vendor CA trust bundle PEM file (required).
- `--client_ip`: IP address of the switch (default: `127.0.0.1`).
- `--port`: Port of the switch (default: `4321`).
- `--owner_ca_cert`: Path to switch owner CA certificate PEM file (required in TLS mode).
- `--owner_ca_key`: Path to switch owner CA private key PEM file (required in TLS mode).
- `--alsologtostderr`: Logs output to stderr.

## End-to-End Example with Device Emulator

1. Generate a test switch owner CA certificate and key:

   ```bash
   openssl ecparam -name secp384r1 -genkey -noout -out /tmp/owner_ca_key.pem
   openssl req -new -x509 -key /tmp/owner_ca_key.pem -out /tmp/owner_ca_cert.pem -days 365 -subj "/O=Switch Owner/CN=Switch Owner Root CA"
   ```

2. Start the device emulator and export its vendor CA certificate:

   ```bash
   bazel run //device/emulator:device_emulator -- --alsologtostderr --ca_cert_out=/tmp/vendor_ca.pem
   ```

   To enforce client certificate verification against the owner CA on the device server, pass `--owner_ca_cert=/tmp/owner_ca_cert.pem`.

3. In another terminal, run the switch owner Enrollz service emulator:
   ```bash
   bazel run //service/emulator:enrollz_emulator -- \
     --alsologtostderr \
     --vendor_ca_trust_bundle=/tmp/vendor_ca.pem \
     --owner_ca_cert=/tmp/owner_ca_cert.pem \
     --owner_ca_key=/tmp/owner_ca_key.pem
   ```

## Container

To load and run the emulator as a container:

```bash
bazel run //service/emulator:load_enrollz_emulator_image

docker run --rm --network=host -v /tmp/:/tmp/ open-config-enrollz-emulator:latest \
  --alsologtostderr \
  --vendor_ca_trust_bundle=/tmp/vendor_ca.pem \
  --owner_ca_cert=/tmp/owner_ca_cert.pem \
  --owner_ca_key=/tmp/owner_ca_key.pem
```

The image can then be passed and run on other hosts:

```bash
<user>@<host_origin>:~$ docker save --output open_config_enrollz_emulator.tar open-config-enrollz-emulator:latest

<user>@<host_origin>:~$ scp open_config_enrollz_emulator.tar <user>@<host_destination>:~

<user>@<host_destination>:~$ docker load --input open_config_enrollz_emulator.tar
```
