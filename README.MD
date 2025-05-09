Aztec Noir DNSSEC DKIM Registry
===========

A registry for verification of a DKIM key signature up to [the DNSSEC root]. The project stemmed from an idea of building a system which would onboard users to Aztec using emails, or any other open system relying on structured messaging, so the sender domains an user needs to verify is unknown beforehand.

[the DNSSEC root]: during the hackathon @skaunov identified and filed the bug in `noir_rsa` which prevents RSA RRSIG verification, hence "com." was chosen for the prototype instead of ".".

## Overview
This project implements a registry for DNSSEC (Domain Name System Security Extensions) and DKIM (DomainKeys Identified Mail) keys, allowing for cryptographic verification of domain ownership and email authenticity. The contract maintains a chain of trust starting from trusted DNS root keys down to individual domain DKIM keys.

## Features
- DNSSEC Chain of Trust: Verifies and registers DNS key signing keys (KSK) and zone signing keys (ZSK) through cryptographic proofs
- DKIM Key Registration: Registers DKIM keys for domains after verifying their authenticity through the DNSSEC chain
- Revocation Support: Tracks the revocation status of registered keys
- ECDSA Verification: Uses ECDSA with the secp256r1 curve for signature verification
- RSA Support: Includes RSA 2048 key handling for DKIM records
### next steps
#### root management
#### one algo of 13
ECDSAP256SHA256
#### CNAME 
last day of submitting deadline
#### checking values like ZSK, KSK, ...
does anyone need this?
#### negations and time windows
delegate then remove then delegate again
#### revocations
## Technical Details
### Key Types
- Key Signing Keys (KSK): Used to sign other keys in the DNSSEC hierarchy
- Zone Signing Keys (ZSK): Used to sign DNS records for a specific zone
- DKIM Keys: Used for email authentication, typically RSA keys
### Contract Functions
#### Initialization
`initialize()`
Initializes the contract with the "com." KSK as a trusted starting point. In a production environment, this would be the root "." KSK.
#### Adding Zone Signing Keys
`add_zsigk_len64_signed_ecdsa256sha256(...)`
Adds a zone signing key after verifying it's signed by a trusted key signing key.
#### Adding Delegation Signer Records
`add_ds_ecdsa(...)`
Registers a delegation signer record, establishing trust for a subdomain's key signing key.
#### Adding DKIM Keys
`add_dkim_rsa2048_signed_ecdsa256sha256(...)`
Registers a DKIM key after verifying it's properly signed by a trusted zone signing key.
#### Verifying DKIM Keys
`check_rsa2048(...)`
Verifies that a DKIM key is registered and not revoked.
### Data Structures
- `Bytes64DnsKey`: Represents a DNSSEC key with domain and key components
- `DkimKeyRsa2048`: Represents a DKIM key with domain, selector, and key components
- `DnskeyRecordSetBytes` and `DsRecordSetBytes`: Store DNS record sets for verification
### Implementation Notes
- The contract uses Pedersen hashing for storage keys
- ECDSA with SHA-256 is used for signature verification
- The contract handles bounded vectors to manage domain name and record size constraints
- Maximum FQDN length is enforced according to DNS standards
### Limitations
- Currently starts trust from the "com." KSK due to RSA verification limitations
- Future versions will start from the root "." KSK when RSA verification is fully implemented
- Some optimizations are noted in the code for future implementation
### Testing
The codebase includes test functions to verify the ECDSA signature verification for:
- <PayPal.com> DKIM records and
- ".com" DNSKEY records.