# TPM Enrollment and Attestation of Networking Devices for Device Owners <!-- omit from toc -->

## Table of Contents <!-- omit from toc -->

- [Terminology](#terminology)
- [TPM 2.0 Enrollment for Switch Owners](#tpm-20-enrollment-for-switch-owners)
  - [Workflow Steps](#workflow-steps)
  - [Workflow Diagram](#workflow-diagram)
  - [Alternatives Conidered](#alternatives-conidered)
    - [1. EnrollZ Service serves TPM enrollment API endpoints](#1-enrollz-service-serves-tpm-enrollment-api-endpoints)
    - [2. Use IAK cert (as is) signed by the switch vendor CA](#2-use-iak-cert-as-is-signed-by-the-switch-vendor-ca)
    - [3. Switch owner uses EK (or EK cert) to issue LAK cert](#3-switch-owner-uses-ek-or-ek-cert-to-issue-lak-cert)
    - [4. Switch owner issues LAK cert based on IAK cert signed by switch vendor CA](#4-switch-owner-issues-lak-cert-based-on-iak-cert-signed-by-switch-vendor-ca)
- [TPM 2.0 Attestation for Switch Owners](#tpm-20-attestation-for-switch-owners)
- [Building](#building)

## Terminology

- [Bootz](https://github.com/openconfig/bootz) is an evolution of [sZTP](https://www.rfc-editor.org/rfc/rfc8572.html).
- TPM EnrollZ Service (or simply EnrollZ Service) is switch owner's internal infrastructure service responsible for TPM 2.0 enrollment workflow.
- TPM AttestZ Service (or simply AttestZ Service) is switch owner's internal infrastructure service responsible for TPM 2.0 attestation workflow.
- Switch owner CA is switch owner's internal Certificate Authority Service.
- Switch chassis consists of one or more *“control cards”* (or *“supervisors”*, *“routing engines”*, *“routing processors”*, etc.), each of which is equipped with its own CPU and TPM. The term control card will be used throughout the doc.

**Differences between various certs** *(more details in the [TCG spec](https://trustedcomputinggroup.org/wp-content/uploads/TPM-2p0-Keys-for-Device-Identity-and-Attestation_v1_r12_pub10082021.pdf))*:

| **Cert type** | **On which pub key is the cert based on?** | **Can there be more than one underlying keypair for a given TPM?** | **Which CA issues/signs the cert?** |
| :---: | :----: | :---: | :---: |
| Initial Attestation Key (IAK) | IAK pub | No | Switch Vendor |
| Local Attestation Key (LAK) | LAK pub | Yes| Switch Owner |
| Owner IAK (oIAK) | IAK pub | No | Switch Owner |
| Endorsement Key (EK) | EK pub | No | TPM Vendor |

## TPM 2.0 Enrollment for Switch Owners

In this workflow switch owner verifies device's Initial Attestation Key (IAK) and Initial DevID (IDevID) certificates (signed by the switch vendor CA) and installs/rotates owner IAK (oIAK) and owner IDevID (oIDevID) certificates (signed by switch owner CA). oIAK and oIDevID certs are based on the same underlying keys as IAK and IDevID certs, respectively, and give switch owner the ability to (1)
fully control certificate structure, revocation and expiration policies and (2) remove external dependency on switch vendor CA during TPM attestation workflow. The assumption is that before the device is shipped to the switch owner, a switch vendor provisions each control card with IAK and IDevID certificates following the TCG specification in
[Section 5.2](https://trustedcomputinggroup.org/wp-content/uploads/TPM-2p0-Keys-for-Device-Identity-and-Attestation_v1_r12_pub10082021.pdf#page=20) and [Section 6.2](https://trustedcomputinggroup.org/wp-content/uploads/TPM-2p0-Keys-for-Device-Identity-and-Attestation_v1_r12_pub10082021.pdf#page=30).

### Workflow Steps

1. On completion of bootz workflow, device obtains all necessary credentials and configurations to start serving TPM enrollment gRPC API endpoints.
2. On completion of bootz, EnrollZ Service is notified to enroll a TPM on a specific control card and calls the device's `GetIakCert` API to get back an IAK cert.
   - *Note: primary/active control card is also responsible for all RPCs directed to the secondary/standby control card. The mechanism of internal communication between the two control cards depends on the switch vendor and is out of scope of this doc.*
3. EnrollZ Service uses the trust bundle/anchor obtained (in advance) from the switch vendor to verify signature over the IAK cert.
   - *Note: EnrollZ Service must have access to the up-to-date switch vendor trust bundle/anchor needed to verify the signature over the IAK certificate. The mechanics of this workflow are out of scope of this doc, but the trust bundle could be retrieved from a trusted vendor portal on a scheduled basis.*
4. EnrollZ Service ensures that device identity fields in IAK cert match its expectations.
5. EnrollZ Service asks switch owner CA to issue an oIAK cert based on the IAK pub key and device identity fields.
6. EnrollZ Service obtains the oIAK cert from the CA and calls the device's `RotateOIakCert` API to persist the oIAK cert on the control card.
7. The switch verifies that the IAK pub key in oIAK cert matches the one in IAK cert.
8. The switch stores the oIAK cert in non-volatile memory and will present it in the TPM attestation workflow.
9. EnrollZ Service repeats the workflow for the second control card if one is available.

**Pros:**

- The approach effectively delegates much of the TPM enrollment workflow to the switch vendor which aligns with the TCG guidance/intention.
- Simplicity of TPM enrollment workflow on switch owner side which should streamline the implementation of the workflow for both switch owner and switch vendors and thus make it easier to onboard new and scale across vendors.
- Using oIAK cert gives switch owner more flexibility and control over the cert structure, management (e.g. revocation) and lifecycle.
- AttestZ Service does not have an external dependency on switch vendor CA on every switch attestation.
- Switch vendors do not need to support issuance of LAKs.

**Cons:**

- Need to trust that switch vendors actually performed proper TPM enrollment following TCG spec.

### Workflow Diagram

![Alt text](assets/tpm-20-enrollment-workflow-diagram.svg "a title")

### Alternatives Conidered

#### 1. EnrollZ Service serves TPM enrollment API endpoints

**Pros:**

- A device knows exactly when it is ready to kick off TPM enrollment workflow (right after bootz workflow and potential subsequent reboot are complete) whereas in the proposed workflow EnrollZ Service will likely need to repeatedly try to reach out to the device until it is ready for TPM enrollment.
- Can be achieved with a single `ExchangeIakCert` API: given an IAK cert return an oIAK cert.

**Cons:**

- From a security standpoint switches generally should not be initiating connections.
- The design will be cleaner if TPM enrollment followed the same pattern as TPM attestation and gNxI APIs where the device serves the endpoints.

#### 2. Use IAK cert (as is) signed by the switch vendor CA

The workflow would follow the TCG specification documented in [section 5.1](https://trustedcomputinggroup.org/wp-content/uploads/TPM-2p0-Keys-for-Device-Identity-and-Attestation_v1_r12_pub10082021.pdf#page=19) and [section 6.1](https://trustedcomputinggroup.org/wp-content/uploads/TPM-2p0-Keys-for-Device-Identity-and-Attestation_v1_r12_pub10082021.pdf#page=27).

**Pros:**

- Simplifies the workflow and practically removes TPM enrollment workflow on the switch owner side.

**Cons:**

- Introduces a strong runtime dependency on switch vendor CA every time AttestZ Service performs TPM attestation.
- Using a switch-vendor-issued IAK cert gives switch owner no control over the cert structure, management (e.g. revocation) and lifecycle.
- Need to trust that the switch vendor actually performed proper TPM enrollment following TCG spec.

#### 3. Switch owner uses EK (or EK cert) to issue LAK cert

The workflow would follow the TCG specification documented in [section 5.6](https://trustedcomputinggroup.org/wp-content/uploads/TPM-2p0-Keys-for-Device-Identity-and-Attestation_v1_r12_pub10082021.pdf#page=24) and [section 6.6](https://trustedcomputinggroup.org/wp-content/uploads/TPM-2p0-Keys-for-Device-Identity-and-Attestation_v1_r12_pub10082021.pdf#page=34). In this case the switch vendor would
not perform TPM enrollment at all.

**Pros:**

- Using LAK gives switch owner more flexibility and control over the cert structure, management (e.g. revocation) and lifecycle.
- No need to trust that the switch vendor actually performed proper TPM enrollment following TCG spec.
- Switch vendors do not need to do TPM enrollment and provision the switch with an IAK.
- AttestZ Service does not have an external dependency on switch vendor CA on every switch attestation.

**Cons:**

- Switch owner has to develop and support complex TPM enrollment logic that verifies that the device indeed possesses EK private key.
- Either (1) all switch vendors have to publish EK pub on their portal and switch owner to build an automatic system (for each vendor) to fetch and persist it in advance of device shipment or (2) switch owner to obtain and manage a TPM manufacturer trust bundle to verify EK cert with which all switches must be provisioned.
- Switch vendors need to support issuance of LAKs.
- LAKs are also primarily used in scenarios where device/user privacy is important. In the case of network switches (especially the ones running in switch owner's own data centers), however, infra components would actually want to know exactly the identities of the switches, so their privacy is not desirable. Consult
[section 11](https://trustedcomputinggroup.org/wp-content/uploads/TPM-2p0-Keys-for-Device-Identity-and-Attestation_v1_r12_pub10082021.pdf#page=64) of the TCG spec for more details.

#### 4. Switch owner issues LAK cert based on IAK cert signed by switch vendor CA

The workflow would follow the TCG specification documented in [section 5.3](https://trustedcomputinggroup.org/wp-content/uploads/TPM-2p0-Keys-for-Device-Identity-and-Attestation_v1_r12_pub10082021.pdf#page=21) and [section 6.3](https://trustedcomputinggroup.org/wp-content/uploads/TPM-2p0-Keys-for-Device-Identity-and-Attestation_v1_r12_pub10082021.pdf#page=32).

**Pros:**

- Using LAK gives switch owners more flexibility and control over the cert structure, management (e.g. revocation) and lifecycle.
- AttestZ Service (a performance-critical service) does not have an external dependency on switch vendor CA on every switch attestation.

**Cons:**

- Need to trust that the switch vendor actually performed proper TPM enrollment following TCG spec.
- The most expensive approach in terms of software development/maintenance perspective as both switch vendors and switch owner will need to engineer complex TPM enrollment logic (see TCG spec for more details).
- Switch vendors need to support issuance of LAKs.
- LAKs are also primarily used in scenarios where device/user privacy is important. In the case of network switches (especially the ones running in switch owner's own data centers), however, infra components would actually want to know exactly the identities of the switches, so their privacy is not desirable. Consult
[section 11](https://trustedcomputinggroup.org/wp-content/uploads/TPM-2p0-Keys-for-Device-Identity-and-Attestation_v1_r12_pub10082021.pdf#page=64) of the TCG spec for more details.

## TPM 2.0 Attestation for Switch Owners

## Building

`bazel build //proto:*`
