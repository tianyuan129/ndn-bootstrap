Name Authentication and Assignment Protocol
============
### Authors
Tianyuan Yu (tianyuan@cs.ucla.edu)
## 1. Terminology
* _Trust Domain Controller_ or _Controller_. A trust domain controller or a controller is an NDN entity who controls the Hydra trust anchor private key. "Trust Domain Controller" and "Controller" are used interchangeably in this document.
* _User Entity_. A user entity is a process that interacts with Hydra users with command line  UI and requests for name authentication and assignment from the controller.
* _Server Entity_. A server entity is a process that runs on a Hydra server.
`<variable>` represents one or more name components in an NDN name. For example, `/<controller-prefix>/NAA/NOTIFY` refers to `/hydra/NAA/NOTIFY` when controller’s prefix is `/hydra`
`<timestamp>`, `<version>`, `<segment>`, and `<ParametersSha256Digest>` are one name component which contains a timestamp, a version number, a segment number, and a SHA-256 digest value, respectively. For more details on these name components, please see  NDN naming conventions.
* _Local Forwarder_. An NDN entity F is entity A’s local forwarder means
   - F is a forwarder.
   - A is able to manage F’s Face Table, Forwarding Information Base (FIB) and Routing Information Base (RIB).
* _Connectivity_. An NDN entity A has connectivity to B under name N means: B is able to receive at least one Interest packet prefixed by N and sent by A.
## 2. Overview
Hydra user and server entity requires security bootstrapping. In this process, user and server entities obtain trust anchor, trust schema, name assignment, and certificate. Specifically, in order for controllers to assign names for user and server entities, they need to be authenticated by the controller.

Name Authentication and Assignment Protocol (NAAP) aims to provide user and server entity authentication and name assignment. NAAP starts with manually established, out-of-band trust relations between user or server entities and the controller, and automates the rest of the authentication and name assignment steps.

The overview of NAAP workflow is shown below
```
User/Server Entity                                           Controller
       |         ----------Bootstrapping Request---------->      |
       |                                                         |
       |         <-----Bootstrapping Parameters Request----      |
       |         -----Bootstrapping Parameters Response---->     |
       |                                                         |
       |         <---------Bootstrapping Response----------      |
       |                                                         |
       |         ----------Identity Proof Request---------->     |
       |                                                         |
       |         <-----Identity Proof Parameter Request----      |
       |         -----Identity Proof Parameter Response---->     |
       |                                                         |
       |         <---------Identity Proof Response---------      |

```
## 3. Assumptions
* Each user or server entity has obtained trust anchor and trust schema.
* Each user or server entity is aware of its local forwarder’s name.
* Each user or server entity has connectivity to the controller under its name.
* Each user or server entity has registered a prefix to their local forwarders. In the rest of this document, we note this prefix as _local prefix_.
* Controller has connectivity to user and server entities' local forwarders under their names.
* Controller has a membership list of allowed user email addresses and server DNS names (i.e., X.509 common names).
## 4. Packet Specification
### 4.1 Bootstrapping Request
#### 4.1.1 Specification
Server and user entities send a bootstrapping request to initiate the name authentication. A bootstrapping request is an Interest packet.
#### 4.1.2 Packet Format
Interest format:
| Field | Description |
|------:|:------------|
| Name | `/<controller-prefix>/NAA/BOOT/<nonce>/NOTIFY/<ParametersSha256Digest>` |
| CanBePrefix | False |
| MustBeFresh | True |
| ApplicationParameters | See below |
| Signature | Not required |

```abnf
ApplicationParameters = APPLICATION-PARAMETERS-TYPE TLV-LENGTH
                        local-prefix
                        [local-forwarder]
local-prefix = LOCAL-PREFIX-TYPE TLV-LENGTH *OCTET
local-forwarder = LOCAL-FORWARDER-TYPE TLV-LENGTH *OCTET
```
* `<nonce>`, name component of 8 bytes value, a random number.
* `local-prefix`, bytes value, the same as the TLV encoding of an user or server entity's local prefix.
* `local-forwarder`, bytes value, the same as the TLV encoding of a local forwarder name of an user or server entity. An user or user entity must include `local-forwarder` if it does not share the same local forwarder with controller.

### 4.2 Bootstrapping Parameters Request
#### 4.2.1 Specification
Controller sends a bootstrapping parameters request to an user or server entity to fetch parameters it uses for authentication.
A bootstrapping parameters request is an Interest packet.
#### 4.2.2 Packet Format
Interest format:
| Field | Description |
|------:|:------------|
| Name | `/<local-prefix>/NAA/BOOT/<nonce>/MSG` |
| CanBePrefix | False |
| MustBeFresh | True |
| Forwarding Hint | See below |
| Signature | Not required |

* `<local-prefix>`, name, the same as the `local-prefix` in bootstrapping request.
* `<nonce>`, name component, the same as the `<nonce>` in bootstrapping request.
* `Forwarding Hint` must present if the bootstrapping request with the same `<nonce>` includes `local-forwarder`. The value of `Forwarding Hint` is the same with the received `local-forwarder`.

### 4.3 Bootstrapping Parameters Response
#### 4.3.1 Specification
An user or server entity use Bootstrapping Parameters Response to respond controller's Bootstrapping Parameters Request.
A Bootstrapping Parameters is a Data packet.

An user and a server entity send Bootstrapping Parameters Response in different Data format.
#### 4.3.2 Packet Format (User Entity Mode)
Data format:
| Field | Description |
|------:|:------------|
| Name | `/<local-prefix>/NAA/BOOT/<nonce>/MSG` |
| FreshnessPeriod | 4 seconds |
| Content | See below |
| Signature | See below ||

```abnf
Content = CONTENT-TYPE TLV-LENGTH
          ecdh-pub
          email-address
          cert-request
ecdh-pub = ECDH-PUB-TYPE
           TLV-LENGTH ; == 65
           65OCTET
email-address = EMAIL-ADDRESS-TYPE
                TLV-LENGTH
                *OCTET
cert-request = CERT-REQUEST-TYPE TLV-LENGTH *OCTET
```
* `email-address`, UTF-8 string value, the email address user entity uses for authentication.
* `ecdh-pub`, bytes value, requester's ECDH public key. See section 4.3.4 for details.
* `cert-request`, bytes value, the TLV of a self-signed certificate generated by the user entity. It should follow the [NDN certificate format](https://named-data.net/doc/ndn-cxx/0.7.0/specs/certificate-format.html).
* User entity should sign Bootstrapping Parameters with the same key presents in the `cert-request` KeyLocator.

#### 4.3.3 Packet Format (Server Entity Mode)
Data format:
| Field | Description |
|------:|:------------|
| Name | `/<local-prefix>/NAA/BOOT/<nonce>/MSG` |
| FreshnessPeriod | 4 seconds |
| Content | See below |
| Signature | See below ||

```abnf
Content = CONTENT-TYPE TLV-LENGTH
          ecdh-pub
          x509-cert-chain
ecdh-pub = ECDH-PUB-TYPE
           TLV-LENGTH ; == 65
           65OCTET
x509-cert-chain = X509-CERT-CHAIN-TYPE
                  TLV-LENGTH
                  *OCTET
```
* `x509-cert-chain`, bytes value, the PEM encoding of server entity's X.509 certificate chain.
* User entity should sign Bootstrapping Parameters with the same key certified by `x509-cert-chain`. The KeyLocator should be `/<local-prefix>/KEY/<keyid>`, where `<keyid>` is a name component of 8-byte random number.

When controller receives `x509-cert-chain`, it must validate the whole certificate chain.
This procedure may require configuring implementation with CA root certificates, which is out of scope of this document. 

#### 4.3.4 Elliptic-Curve Diffie-Hellman (ECDH) Key Agreement
In preparing Boostrapping Parameters, the user or server entity generates a fresh ECC key pair for ECDH purpose.
This key should be generated with a cryptographically secure pseudo random generator, and each Bootstrapping Parameters must use a unique key.
The ECC curve is prime256v1 (same as NIST P-256 and secp256r1).
The public key is sent to the other party in `ecdh-pub` field of Bootstrapping Parameters, encoded as uncompressed format.

### 4.4 Bootstrapping Response
#### 4.4.1 Specification
Controller entity uses Bootstrapping Response to reply Bootstrapping Request if and only if the provided email address or X.509 common name is within the membership list.
Bootstrapping Response is a Data packet.
Depending on the modes of the received Bootstrapping Parameters Response, controller replies Bootstrapping Response with different packet format.
#### 4.4.2 Packet Format (User Entity Mode)
Data format:
| Field | Description |
|------:|:------------|
| Name | `/<controller-prefix>/NAA/BOOT/<nonce>/NOTIFY/<ParametersSha256Digest>` |
| FreshnessPeriod | 4 seconds |
| Content | See below |
| Signature | Required ||

```abnf
Content = CONTENT-TYPE TLV-LENGTH
          ecdh-pub
          salt
ecdh-pub = ECDH-PUB-TYPE
           TLV-LENGTH ; == 65
           65OCTET
salt = SALT-TYPE
       TLV-LENGTH ; == 32
       32OCTET
```
* `<ParametersSha256Digest>`, name component, the same as the `<ParametersSha256Digest>` in Bootstrapping Request.
* `ecdh-pub`, bytes value, controller's ECDH public key. See section 4.3.4 for details.
* `salt`, bytes value, 32 bytes value. See section 4.4.4 for details.

After sending Bootstrapping Response, controller perform the following steps
1. Running ECDH (See section 4.3.4) with the two ECC key pairs and obtaining a 256-bit shared-secret, which is then passed to the HKDF step below.
2. Freshly generating a 6-digit verification code using a cryptographically secure pseudo random generator.
3. Sending to the email address found in Boostrapping Parameters.

#### 4.4.3 Packet Format (Server Entity Mode)
Data format:
| Field | Description |
|------:|:------------|
| Name | `/<controller-prefix>/NAA/BOOT/<nonce>/NOTIFY/<ParametersSha256Digest>` |
| FreshnessPeriod | 4 seconds |
| Content | See below |
| Signature | Required ||

```abnf
Content = CONTENT-TYPE TLV-LENGTH
          rand
rand = RAND-TYPE
       TLV-LENGTH ; == 8
       8OCTET
```
* `rand`, bytes value, 8 bytes value. Freshly generated by the controller for each request using a cryptographically secure pseudo random generator.

#### 4.4.4 HMAC-based Key Derivation Function (HKDF)
After ECDH, the user entity and the controller each runs the HKDF algorithm to generate a 128-bit AES key, used for encrypting Data Content of Identity Proof (See section ).
Following the notation used in [RFC 5869](https://tools.ietf.org/html/rfc5869), we consider the format of HKDF to be `(Hash, IKM, salt, Info, L) -> OKM`.

In NAAP, we have:
* The `Hash` function is SHA-256.
* The `IKM` is the 256-bit result of the ECDH, as described in section 4.3.4.
* The `Salt` is a 32-byte value freshly generated by the controller for each request using a cryptographically secure pseudo random generator, and communicated to the requester in `salt` field of the Bootstrapping Response Data.
* The `Info` is the 8 byte value of `<nonce>`.
* The `L` should be 16 bytes (128 bit).

### 4.5 Identity Proof Request
#### 4.5.1 Specification
The user or server entity sends Identity Proof Request to notify the controller fetching the Identity Proof Parameter (See Section 4.7).
An Identity Proof Request is an Interest packet.
#### 4.5.2 Packet Format
Interest format:
| Field | Description |
|------:|:------------|
| Name | `/<controller-prefix>/NAA/PROOF/<nonce>/NOTIFY` |
| CanBePrefix | False |
| MustBeFresh | True |
| Signature | Not required |
* `<nonce>`, name component, the same as the `<nonce>` in Bootstrapping Request.

### 4.6 Identity Proof Parameter Request
#### 4.6.1 Specification
Controller sends Identity Proof Parameter Request to obtain the identity proof of the user or server entity.
An Identity Proof Parameter Request is an Interest packet.
#### 4.6.2 Packet Format
Interest format:
| Field | Description |
|------:|:------------|
| Name | `/<local-prefix>/NAA/PROOF/<nonce>/MSG` |
| CanBePrefix | False |
| MustBeFresh | True |
| Forwarding Hint | See below |
| Signature | Not required |
* `Forwarding Hint` must present if the Bootstrapping Request with the same `<nonce>` includes `local-forwarder`. The value of `Forwarding Hint` is the same with the corresponding `local-forwarder`.

### 4.7 Identity Proof Parameter Response
#### 4.7.1 Specification
The user or server entity sends Identity Proof Parameter Response as the reply to the Identity Proof Parameter Request.
An Identity Proof Parameter Response is a Data packet, and its packet formats differs in two modes.

#### 4.7.2 Packet Format (User Entity Mode)
| Field | Description |
|------:|:------------|
| Name | `/<local-prefix>/NAA/PROOF/<nonce>/MSG` |
| FreshnessPeriod | 4 seconds |
| Content | See below |
| Signature | See below ||

```abnf
Content = CONTENT-TYPE TLV-LENGTH
          encrypted-code
encrypted-code = ENCRYPTED-CODE-TYPE
                 TLV-LENGTH
                 *OCTET
```
* `encrypted-code`, bytes value, 6-digit verification code encrypted by the AES-128 key derived from ECDH and HKDF (see Section 4.7.3 for details)
* User entity should sign Identity Proof Parameter Response with the same key presents in the `cert-request` KeyLocator.

#### 4.7.2 Packet Format (Server Entity Mode)
| Field | Description |
|------:|:------------|
| Name | `/<local-prefix>/NAA/PROOF/<nonce>/MSG` |
| FreshnessPeriod | 4 seconds |
| Content | See below |
| Signature | See below ||

```abnf
Content = CONTENT-TYPE TLV-LENGTH
          encrypted-code
signed-rand = SIGNED-RAND-TYPE
              TLV-LENGTH
              *OCTET
```
* `signed-rand`, bytes value, signature of `rand` using the key certified by `x509-cert-chain`.
The signature algorithm must correspond to public key algorithm in leaf certificate.
For example, if the public key algorithm used in leaf certificate is `rsaEncryption`, then `signed-rand` must be produced by algorithm `sha256WithRSAEncryption`.
* Server entity should sign Identity Proof Parameter Response with the same key certified by `x509-cert-chain`. The KeyLocator must be the same with the one in Bootstrapping Parameters Response.

#### 2.4.2 AES-GCM Encryption
Messages in Identity Proof Response (User Mode) are encrypted with AES-GCM-128.
Encrypted messages are encoded as follows:

```abnf
encrypted-message = initialization-vector
                    authentication-tag
                    encrypted-payload
initialization-vector = INITIALIZATION-VECTOR-TYPE
                        TLV-LENGTH ; == 12
                        12OCTET
authentication-tag = AUTHENTICATION-TAG-TYPE
                     TLV-LENGTH ; == 16
                     16OCTET
encrypted-payload = ENCRYPTED-PAYLOAD-TYPE TLV-LENGTH *OCTET
```
AES-GCM supports [Authenticated Encryption with Associated Data (AEAD)](https://tools.ietf.org/html/rfc5116) feature: in the encryption process, besides secret key, nonce, plaintext, there is an additional parameter called associated data.
The associated data is not encrypted but can be used for authentication.
NAAP uses the value of `<nonce>` as associated data, to cryptographically bind the encryption to a specific request.

Security of AES-GCM depends on choosing a unique initialization vector for every encryption performed with the same key.
To ensure this requirement is met, the initialization vectors must be randomly generated.
Recipient of each message should verify the uniqueness of initialization vectors.
In particular, it should check that the vector differs from the recipient's own random value.

### 4.8 Identity Proof Response
#### 4.7.1 Specification
Controller sends Identity Proof Response if and only the received Identity Proof Parameter Proof passes the following check:
* _User Entity Mode_: controller decrypts the `encrypted-code` with the derived AES key and checks if the plaintext code matches with the code sent in email.
* _Server Entity Mode_: controller verifies `signed-rand` with the public key certified in `x509-cert-chain` and corresponding signature algorithm.

#### 4.7.2 Packet Format
| Field | Description |
|------:|:------------|
| Name | `/<local-prefix>/NAA/PROOF/<nonce>/NOTIFY` |
| FreshnessPeriod | 4 seconds |
| Content | See below |
| Signature | Required ||

```abnf
Content = CONTENT-TYPE TLV-LENGTH
          proof-of-possession
proof-of-possession = PROO-OF-POSSESSION-TYPE TLV-LENGTH *OCTET
```
* `proof-of-possession`, bytes value, the TLV of a proof of possession generated by the user entity. See Section 4.7.3 for details.

#### 4.7.3 Proof of Possession
A Proof of Possession is an [NDN certificate](https://named-data.net/doc/ndn-cxx/0.7.0/specs/certificate-format.html).
Controller produces Proof of Possession with the naming convention `/32=authenticate/<identity-name>/KEY/<keyid>/controller/<version>`.
* `<identity-name>` is the assigned entity name based on provided email addresses or X.509 common name. See Section 4.7.4 for details.
* `<keyid>` is the same with the one presents in the KeyLocator of Bootstrapping Parameters Response.
* `<version>` is a timestamp based version number component as defined in [NDN Memo for Naming Convention](https://named-data.net/wp-content/uploads/2021/10/ndn-tr-22-3-ndn-memo-naming-conventions.pdf). The timestamp used in Proof of Possession is the Data production timestamp.
* Certificate ValidityPeriod is decided by the controller configuration.

#### 4.7.4 Naming Function
Naming Function assigns an user entity or server entity a name by applying specific name conversion rules to existing email addresses or X.509 common names.
* _User Entity Naming_: `/hydra/32=users/<email-address>`. And `<email-address>` is a name component includes user email address.
* _Server Entity Naming_: `/hydra/32=users/<common-name>`. And `<common-name>` is a name component includes server's common name certified in `x509-cert-chain`.

For example, the following name conversions will apply to email address `alice@cs.ucla.edu` and common name `bruins.cs.ucla.edu`.
```
alice@cs.ucla.edu -> /hydra/32=users/alice@cs.ucla.edu
bruins.cs.ucla.edu -> /hydra/32=nodes/bruins.cs.ucla.edu
```

## 5. Error Handling
This section defines the format for the error messages used in NAAP.
When there is an error in processing Bootstrapping Request, Bootstrapping Parameters Response and Identity Proof Parameter Response, the controller should abort the request and erase the state used for the session.

### 3.1 Error Message Data Packet Format

Data format:

| Field | Description |
|------:|:------------|
| Name | See below |
| Content | See below |
| Signature | Required |

```abnf
Content = CONTENT-TYPE TLV-LENGTH
          error-code
          error-info
error-code = ERROR-CODE-TYPE
             TLV-LENGTH ; == 1
             NonNegativeInteger
error-info = ERROR-INFO-TYPE TLV-LENGTH *OCTET
```
* The name of error message data packet depends on which packet triggers the error.
  - If the error happens in processing Bootstrapping Request, the error message uses the name of Bootstrapping Response.
  - If the error happens in processing Bootstrapping Parameters Response, the error message uses the name of Bootstrapping Response.
  - If the error happens in processing Identity Proof Parameter Response, the error message uses the name of Identity Proof Response.
* `error-code`, non negative integer value, the error code.
* `error-info`, UTF-8 string value, a human-readable error message.


### 3.2 Error Code and Reason

| Error Code | Bootstrapping Request | Bootstrapping Parameters Response | Identity Proof Parameter Response | Definition |
|:-:|:-:|:-:|:-:|:-:|
| 1 | ✔️ | ❌ | ❌ | Bad Interest Format: the Interest format is incorrect, e.g., no ApplicationParameters.  |
| 2 | ✔️ | ❌ | ❌ | Bad Interest Parameter Format: the ApplicationParameters field is not correctly formed. |
| 3 | ❌ | ✔️ | ✔️ | Bad Signature or signature info: the Interest carries an invalid signature. |
| 4 | ❌ | ✔️ | ✔️ | Bad Response Format: Bootstrapping Parameters Response or Identity Proof Parameter Response is not correctly formed. |
| 5 | ❌ | ✔️ | ❌ | Identity not allowed: the provided email address or X.509 common name is not allowed by controller. |
| 6 | ❌ | ❌ | ✔️ | Bad Identity Proof: provided identity proof parameter cannot be verified, e.g., wrong email verification code. |

## Appendix A: TLV-TYPE Numbers

| Attribute | TLV-TYPE Number (decimal) |  TLV-TYPE Number (hexadecimal) |
|:-:|:-:|:-:|
| local-prefix | 129 | 81 |
| local-forwarder | 131 | 83 |
| ecdh-pub | 133 | 85 |
| email-address | 135 | 87 |
| cert-request | 137 | 89 |
| x509-cert-chain | 139 | 8B |
| salt | 141 | 8D |
| rand | 143 | 8F |
| encrypted-code | 145 | 91 |
| signed-rand| 147 | 93 |
| salt | 149 | 95 |
| initialization-vector | 151 | 97 |
| authentication-tag | 153 | 99 |
| encrypted-payload | 155 | 9B |
| initialization-vector | 157 | 9D |
| proof-of-possession | 159 | 9F |
| selected-challenge | 161 | A1 |
| error-code | 163 | A3 |
| error-info | 165 | A5 |
