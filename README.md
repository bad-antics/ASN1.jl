# ASN1.jl

[![Tests](https://img.shields.io/badge/tests-106%20passed-brightgreen)]()

A pure-Julia ASN.1 (Abstract Syntax Notation One) encoder/decoder supporting DER and BER encoding rules, with built-in X.509 certificate parsing. Zero external dependencies.

## Features

- **DER/BER Decoder** — parse any DER/BER-encoded ASN.1 data into a tree
- **DER Encoder** — encode ASN.1 nodes back to DER format
- **All universal types** — BOOLEAN, INTEGER, BIT STRING, OCTET STRING, NULL, OID, SEQUENCE, SET, UTCTime, GeneralizedTime, UTF8String, PrintableString, IA5String
- **X.509 Certificate Parser** — extract version, serial, issuer, subject, validity, public key, extensions
- **PEM Support** — decode PEM-wrapped certificates
- **OID Registry** — human-readable names for common OIDs
- **Round-trip safe** — encode → decode → encode produces identical output
- **BigInt support** — handles arbitrarily large integers

## Installation

```julia
using Pkg
Pkg.add("ASN1")
```

## Quick Start

```julia
using ASN1

# Decode DER data
node = decode(der_bytes)

# Encode to DER
bytes = encode(node)

# Parse X.509 certificate
cert = parse_x509(der_bytes)
println(cert.subject)        # Dict("commonName" => "example.com", ...)
println(cert.not_after)      # DateTime
println(cert.signature_algorithm)  # "sha256WithRSAEncryption"

# Parse PEM certificate
cert = parse_x509_pem(pem_string)
```

## Building ASN.1 Structures

```julia
using ASN1

# Primitives
ASN1.asn1_boolean(true)
ASN1.asn1_integer(42)
ASN1.asn1_integer(BigInt(2)^256)
ASN1.asn1_null()
ASN1.asn1_octet_string(UInt8[0x01, 0x02])
ASN1.asn1_bit_string(UInt8[0xFF])
ASN1.asn1_oid("1.2.840.113549.1.1.11")
ASN1.asn1_utf8string("Hello")
ASN1.asn1_printable_string("Test")

# Constructed types
ASN1.asn1_sequence([node1, node2])
ASN1.asn1_set([node1, node2])

# Time
ASN1.asn1_utctime(DateTime(2025, 1, 1))
ASN1.asn1_generalized_time(DateTime(2025, 1, 1))

# Context-specific tags
ASN1.asn1_context(0, [child_node])
```

## Value Extraction

```julia
ASN1.extract_boolean(node)           # Bool
ASN1.extract_integer(node)           # BigInt
ASN1.extract_string(node)            # String
ASN1.extract_oid(node)               # "1.2.840.113549.1.1.11"
ASN1.extract_utctime(node)           # DateTime
ASN1.extract_generalized_time(node)  # DateTime
```

## X.509 Certificate Fields

```julia
cert = parse_x509(der_bytes)

cert.version               # Int (1, 2, or 3)
cert.serial_number         # BigInt
cert.signature_algorithm   # String
cert.issuer                # Dict{String,String}
cert.subject               # Dict{String,String}
cert.not_before            # DateTime
cert.not_after             # DateTime
cert.public_key_algorithm  # String
cert.public_key_bytes      # Vector{UInt8}
cert.extensions            # Dict{String,Any}
```

## API Reference

| Function | Description |
|----------|-------------|
| `decode(data)` | Decode DER/BER bytes to ASN1Node tree |
| `encode(node)` | Encode ASN1Node tree to DER bytes |
| `decode_pem(pem)` | Decode PEM string to raw DER bytes |
| `parse_x509(der)` | Parse DER-encoded X.509 certificate |
| `parse_x509_pem(pem)` | Parse PEM-encoded X.509 certificate |

## License

MIT
