Aztec Noir DNSSEC DKIM Registry
===========

A registry for verification of a DKIM key signature up to [the DNSSEC root]. The project stemmed from an idea of building a system which would onboard users to Aztec using emails, or any other open system relying on structured messaging, so the sender domains an user needs to verify is unknown beforehand.

This primarily saves users from a situation when
- the keys checked with ZK-email are rolled-over and verification doesn't pass until a contract owner introduce the new key (if ever),
- a key are spooffed and any email attacker issues gets verified.

[the DNSSEC root]: during the hackathon @skaunov identified and filed the bug in `noir_rsa` which prevents RSA RRSIG verification, hence "com." was chosen for the prototype instead of ".".

## Overview
This project implements a registry for DNSSEC (Domain Name System Security Extensions) and DKIM (DomainKeys Identified Mail) keys, allowing for cryptographic verification of a DKIM key for email authenticity. The contract maintains a chain of trust starting from trusted DNSSEC root key down to individual domain DKIM keys. Once a signed key was presented to the contract it stores it hashed identification parameters and anyone checking that key will be asserted that it's genuine.

## Features
This really is focused on one task: integrating this contract into ZK-email based contracts with a very simple call so that keys they use could be asserted when possible to be genuine. Adding a key takes much more convoluted calls and also takes some storage.
### next steps
This section is long but important. A lot of time and effort sunk into learning DNS, DNSSEC, and adaptation to the difference from Alphabuild (which was a perfect format). The result is design items I didn't saw in the beginning of the journey and would like to implement if somebody finds the whole idea to be interesting.
#### root management
As much as this project solves DKIM keys management problem for DNSSEC domains, it actually reduces that to management of the DNSSEC root keys. But it's quite a smaller one: they're easily verifiable, rotated once in a few year, generated in advance, and can be added for the entire network via this contract. So they're perfect for management with any kind of simple DAO, Aztec, or another company.
#### algorithms support
DNSSEC has 13 algorithms which popularity looks like Pareto principle (where 20% of items covers 80% of cases). So it's easy to add other algorithms covering most popular setups. The fact of such a variety of algorithms makes the API inevitable bloated/fragmented. But the good news are that the implementations differs quite slightly and all the primitives seems to be available in Noir. The prototype implements ECDSAP256SHA256, which can be named second most useful, counting from the root. Root is secured with RSA, which Noir implementation had a bug which was filed to that library during the hackathon. (Also it should be noted that DKIM offers like two popular algorithms, where RSA dominates.)
#### CNAME delegated DKIM
On the very last day for NoirHack submission I understood how CNAME delegated DKIM works (early misconception evidence are burried in the commits) so it didn't make into the code obviously. This approach would require another record type function and the `Map` for it, but aside from this it works just the same as the straight-forward approach implemented.
#### negations and time windows
The variation with delegation mentioned in the previous section sound simple, but actually it entails quite intricate cases which require to introduce manipulation with more complex data structures. Particularly to track when a key (record) was seen. (And as there's no dates attached to the keys itself, but only to the signatures it becomes estimating validity based on those.) So to process a situation when domain delegated DKIM management to another domain, then took that management to itself, and then delegated again it takes some data and development.

#### revocations
The inticate case mentioned in the previous section shows that CNAME implementation requires also NSEC implementation (which enables verification of a subdomain absence). But it also helpful in another often overlooked topic of key revocation. So NSEC also enables a selector shut down and verification of an email only for the moments before that. DNSSEC keys have their own revocation protocol. And DKIM deserves an entire subsection.

##### DKIM

I couldn't find a specification for it. My guess the reason is the verification was designed to be done _on receive_ and just removing the key would be enough leaving only those who cached vulnerable for the TTL amount of time. But for a ZK-email based contract this would be a **disaster.**

So the registry would need some kind of its own mechanism for this. For example presenting the private key to mark the DKIM-key revoked. The problem is that publishing the private key of a probably compromised public key can do more harm than good. In the same time it's not a great approach to allow revocation without publication of the private key since it can be used for censorship by the key owner. So DKIM `Map` should receive the second flag for a _weak revocation_ signalling that the key owner doesn't recommend using this key; respecting this is up to the caller of the contract. This weak revocation would be done by presentating private key privately; while ordinary revocation by presenting the private key via a public function -- and that would prevent further verification with this public key.

#### API to check DNSSEC keys
It's easy to add functions to check domain keys (ZSK, KSK) like the DKIM check exposed. Those are used to enable registering a DKIM key in the contract. I would like to see a project/case which would need such functions.

## Technical Details
### Key Types
- Key Signing Keys (KSK): Used to sign other keys in the DNSSEC hierarchy
- Zone Signing Keys (ZSK): Used to sign DNS records for a specific zone
- DKIM Keys: Used for email authentication, typically RSA keys
### Implementation Notes
- The contract uses Pedersen hashing for storage keys because only collision resistance is important, and preimage is covered with a signature algorithm used to add the key.
- ECDSA with SHA-256 is covered in the prototype.
- The contract handles bounded vectors to manage domain name and record size constraints
- Maximum FQDN length is enforced according to DNS standards
### Testing
The codebase includes test functions to verify the ECDSA signature verification for:
- <PayPal.com> DKIM records and
- ".com" DNSKEY records.