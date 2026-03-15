using Test
using ASN1
using Dates

@testset "ASN1.jl" begin

    @testset "Tag decoding" begin
        # SEQUENCE tag (0x30 = UNIVERSAL | CONSTRUCTED | 0x10)
        tag, pos = ASN1._decode_tag(UInt8[0x30], 1)
        @test tag.class == ASN1.UNIVERSAL
        @test tag.constructed == true
        @test tag.number == 0x10

        # INTEGER tag (0x02)
        tag2, pos2 = ASN1._decode_tag(UInt8[0x02], 1)
        @test tag2.class == ASN1.UNIVERSAL
        @test tag2.constructed == false
        @test tag2.number == 0x02

        # Context-specific [0] constructed (0xA0)
        tag3, pos3 = ASN1._decode_tag(UInt8[0xA0], 1)
        @test tag3.class == ASN1.CONTEXT
        @test tag3.constructed == true
        @test tag3.number == 0x00
    end

    @testset "Length decoding" begin
        # Short form: length < 128
        len, pos = ASN1._decode_length(UInt8[0x05], 1)
        @test len == 5
        @test pos == 2

        # Long form: 1 byte
        len2, pos2 = ASN1._decode_length(UInt8[0x81, 0xFF], 1)
        @test len2 == 255
        @test pos2 == 3

        # Long form: 2 bytes
        len3, pos3 = ASN1._decode_length(UInt8[0x82, 0x01, 0x00], 1)
        @test len3 == 256
        @test pos3 == 4
    end

    @testset "Length encoding" begin
        buf = UInt8[]
        ASN1._encode_length!(buf, 5)
        @test buf == UInt8[0x05]

        buf2 = UInt8[]
        ASN1._encode_length!(buf2, 200)
        @test buf2 == UInt8[0x81, 0xC8]

        buf3 = UInt8[]
        ASN1._encode_length!(buf3, 300)
        @test buf3 == UInt8[0x82, 0x01, 0x2C]
    end

    @testset "Encode/decode BOOLEAN" begin
        node_t = ASN1.asn1_boolean(true)
        bytes = encode(node_t)
        @test bytes == UInt8[0x01, 0x01, 0xFF]

        node_f = ASN1.asn1_boolean(false)
        bytes_f = encode(node_f)
        @test bytes_f == UInt8[0x01, 0x01, 0x00]

        # Round-trip
        decoded = decode(bytes)
        @test ASN1.extract_boolean(decoded) == true
    end

    @testset "Encode/decode INTEGER" begin
        # Zero
        n0 = ASN1.asn1_integer(0)
        b0 = encode(n0)
        @test b0 == UInt8[0x02, 0x01, 0x00]
        @test ASN1.extract_integer(decode(b0)) == 0

        # Small positive
        n1 = ASN1.asn1_integer(127)
        b1 = encode(n1)
        @test ASN1.extract_integer(decode(b1)) == 127

        # Need leading zero (high bit set)
        n128 = ASN1.asn1_integer(128)
        b128 = encode(n128)
        d128 = decode(b128)
        @test ASN1.extract_integer(d128) == 128

        # Larger integer
        n256 = ASN1.asn1_integer(256)
        b256 = encode(n256)
        @test ASN1.extract_integer(decode(b256)) == 256

        # Negative
        nm1 = ASN1.asn1_integer(-1)
        bm1 = encode(nm1)
        @test ASN1.extract_integer(decode(bm1)) == -1

        # Large positive
        big_val = BigInt(2)^64
        nbig = ASN1.asn1_integer(big_val)
        bbig = encode(nbig)
        @test ASN1.extract_integer(decode(bbig)) == big_val
    end

    @testset "Encode/decode NULL" begin
        n = ASN1.asn1_null()
        b = encode(n)
        @test b == UInt8[0x05, 0x00]
        d = decode(b)
        @test d.tag.number == 0x05
        @test isempty(d.value)
    end

    @testset "Encode/decode OCTET STRING" begin
        data = UInt8[0x01, 0x02, 0x03, 0x04]
        n = ASN1.asn1_octet_string(data)
        b = encode(n)
        d = decode(b)
        @test d.tag.number == 0x04
        @test d.value == data
    end

    @testset "Encode/decode BIT STRING" begin
        data = UInt8[0xFF, 0xF0]
        n = ASN1.asn1_bit_string(data; unused_bits=0x04)
        b = encode(n)
        d = decode(b)
        @test d.tag.number == 0x03
        @test d.value[1] == 0x04  # unused bits
        @test d.value[2:3] == data
    end

    @testset "Encode/decode strings" begin
        # UTF8String
        n1 = ASN1.asn1_utf8string("Hello, World!")
        b1 = encode(n1)
        d1 = decode(b1)
        @test ASN1.extract_string(d1) == "Hello, World!"

        # PrintableString
        n2 = ASN1.asn1_printable_string("Test Org")
        b2 = encode(n2)
        d2 = decode(b2)
        @test ASN1.extract_string(d2) == "Test Org"

        # IA5String
        n3 = ASN1.asn1_ia5string("user@example.com")
        b3 = encode(n3)
        d3 = decode(b3)
        @test ASN1.extract_string(d3) == "user@example.com"
    end

    @testset "Encode/decode OID" begin
        # RSA OID: 1.2.840.113549.1.1.1
        n = ASN1.asn1_oid("1.2.840.113549.1.1.1")
        b = encode(n)
        d = decode(b)
        @test ASN1.extract_oid(d) == "1.2.840.113549.1.1.1"

        # Simple OID: 2.5.4.3 (commonName)
        n2 = ASN1.asn1_oid("2.5.4.3")
        b2 = encode(n2)
        d2 = decode(b2)
        @test ASN1.extract_oid(d2) == "2.5.4.3"

        # SHA-256 with RSA: 1.2.840.113549.1.1.11
        n3 = ASN1.asn1_oid("1.2.840.113549.1.1.11")
        b3 = encode(n3)
        d3 = decode(b3)
        @test ASN1.extract_oid(d3) == "1.2.840.113549.1.1.11"
    end

    @testset "OID name lookup" begin
        @test ASN1.oid_name("2.5.4.3") == "commonName"
        @test ASN1.oid_name("1.2.840.113549.1.1.11") == "sha256WithRSAEncryption"
        @test ASN1.oid_name("9.9.9.9") == "9.9.9.9"  # Unknown OID
    end

    @testset "Encode/decode SEQUENCE" begin
        children = ASN1Node[
            ASN1.asn1_integer(42),
            ASN1.asn1_boolean(true),
            ASN1.asn1_null()
        ]
        seq = ASN1.asn1_sequence(children)
        b = encode(seq)
        d = decode(b)

        @test d.tag.constructed == true
        @test d.tag.number == 0x10
        dchildren = d.value::Vector{ASN1Node}
        @test length(dchildren) == 3
        @test ASN1.extract_integer(dchildren[1]) == 42
        @test ASN1.extract_boolean(dchildren[2]) == true
        @test dchildren[3].tag.number == 0x05
    end

    @testset "Encode/decode SET" begin
        children = ASN1Node[
            ASN1.asn1_integer(1),
            ASN1.asn1_integer(2),
        ]
        s = ASN1.asn1_set(children)
        b = encode(s)
        d = decode(b)
        @test d.tag.number == 0x11
        @test d.tag.constructed == true
    end

    @testset "Encode/decode UTCTime" begin
        dt = DateTime(2025, 3, 15, 12, 30, 45)
        n = ASN1.asn1_utctime(dt)
        b = encode(n)
        d = decode(b)
        @test ASN1.extract_utctime(d) == dt
    end

    @testset "Encode/decode GeneralizedTime" begin
        dt = DateTime(2025, 12, 31, 23, 59, 59)
        n = ASN1.asn1_generalized_time(dt)
        b = encode(n)
        d = decode(b)
        @test ASN1.extract_generalized_time(d) == dt
    end

    @testset "Context-specific tags" begin
        children = ASN1Node[ASN1.asn1_integer(3)]
        ctx = ASN1.asn1_context(0, children)
        b = encode(ctx)
        d = decode(b)
        @test d.tag.class == ASN1.CONTEXT
        @test d.tag.number == 0
        @test d.tag.constructed == true
    end

    @testset "Nested structures" begin
        # SEQUENCE { SEQUENCE { INTEGER, OID }, OCTET STRING }
        inner = ASN1.asn1_sequence(ASN1Node[
            ASN1.asn1_integer(42),
            ASN1.asn1_oid("1.2.3.4.5")
        ])
        outer = ASN1.asn1_sequence(ASN1Node[
            inner,
            ASN1.asn1_octet_string(UInt8[0xDE, 0xAD])
        ])

        b = encode(outer)
        d = decode(b)
        outer_children = d.value::Vector{ASN1Node}
        @test length(outer_children) == 2

        inner_children = outer_children[1].value::Vector{ASN1Node}
        @test ASN1.extract_integer(inner_children[1]) == 42
        @test ASN1.extract_oid(inner_children[2]) == "1.2.3.4.5"

        @test outer_children[2].value == UInt8[0xDE, 0xAD]
    end

    @testset "Round-trip complex structure" begin
        # Build a structure similar to X.509 TBSCertificate (simplified)
        version = ASN1.asn1_context(0, ASN1Node[ASN1.asn1_integer(2)])
        serial = ASN1.asn1_integer(BigInt(123456789))
        sig_alg = ASN1.asn1_sequence(ASN1Node[
            ASN1.asn1_oid("1.2.840.113549.1.1.11"),
            ASN1.asn1_null()
        ])

        tbs = ASN1.asn1_sequence(ASN1Node[version, serial, sig_alg])
        b = encode(tbs)
        d = decode(b)

        tbs_children = d.value::Vector{ASN1Node}
        @test length(tbs_children) == 3

        # Version context [0]
        @test tbs_children[1].tag.class == ASN1.CONTEXT
        ver_children = tbs_children[1].value::Vector{ASN1Node}
        @test ASN1.extract_integer(ver_children[1]) == 2

        # Serial
        @test ASN1.extract_integer(tbs_children[2]) == 123456789

        # Sig algorithm OID
        sa_children = tbs_children[3].value::Vector{ASN1Node}
        @test ASN1.extract_oid(sa_children[1]) == "1.2.840.113549.1.1.11"
    end

    @testset "PEM decode" begin
        # A minimal PEM-like block
        pem = """
        -----BEGIN TEST-----
        AQIDBA==
        -----END TEST-----
        """
        raw = decode_pem(pem)
        @test raw == UInt8[0x01, 0x02, 0x03, 0x04]
    end

    @testset "Base64 decode" begin
        @test ASN1.base64_decode("AQID") == UInt8[0x01, 0x02, 0x03]
        @test ASN1.base64_decode("AQIDBA==") == UInt8[0x01, 0x02, 0x03, 0x04]
        @test ASN1.base64_decode("") == UInt8[]
    end

    @testset "Self-signed X.509 cert (constructed)" begin
        # Build a minimal self-signed X.509 certificate structure
        # Certificate ::= SEQUENCE { TBSCertificate, SignatureAlgorithm, SignatureValue }

        # TBSCertificate
        version = ASN1.asn1_context(0, ASN1Node[ASN1.asn1_integer(2)])  # v3
        serial = ASN1.asn1_integer(BigInt(1))
        sig_alg = ASN1.asn1_sequence(ASN1Node[
            ASN1.asn1_oid("1.2.840.113549.1.1.11"),  # SHA256withRSA
            ASN1.asn1_null()
        ])

        # Issuer
        issuer_cn = ASN1.asn1_sequence(ASN1Node[
            ASN1.asn1_oid("2.5.4.3"),
            ASN1.asn1_printable_string("Test CA")
        ])
        issuer = ASN1.asn1_sequence(ASN1Node[ASN1.asn1_set(ASN1Node[issuer_cn])])

        # Validity
        not_before = ASN1.asn1_utctime(DateTime(2025, 1, 1, 0, 0, 0))
        not_after = ASN1.asn1_utctime(DateTime(2026, 1, 1, 0, 0, 0))
        validity = ASN1.asn1_sequence(ASN1Node[not_before, not_after])

        # Subject
        subject_cn = ASN1.asn1_sequence(ASN1Node[
            ASN1.asn1_oid("2.5.4.3"),
            ASN1.asn1_printable_string("Test Subject")
        ])
        subject_o = ASN1.asn1_sequence(ASN1Node[
            ASN1.asn1_oid("2.5.4.10"),
            ASN1.asn1_printable_string("Test Org")
        ])
        subject = ASN1.asn1_sequence(ASN1Node[
            ASN1.asn1_set(ASN1Node[subject_cn]),
            ASN1.asn1_set(ASN1Node[subject_o])
        ])

        # SubjectPublicKeyInfo
        pk_alg = ASN1.asn1_sequence(ASN1Node[
            ASN1.asn1_oid("1.2.840.113549.1.1.1"),  # RSA
            ASN1.asn1_null()
        ])
        pk_bits = ASN1.asn1_bit_string(UInt8[0x00, 0x01, 0x02, 0x03])
        spki = ASN1.asn1_sequence(ASN1Node[pk_alg, pk_bits])

        tbs = ASN1.asn1_sequence(ASN1Node[
            version, serial, sig_alg, issuer, validity, subject, spki
        ])

        # Outer certificate
        outer_sig_alg = ASN1.asn1_sequence(ASN1Node[
            ASN1.asn1_oid("1.2.840.113549.1.1.11"),
            ASN1.asn1_null()
        ])
        sig_value = ASN1.asn1_bit_string(UInt8[0xAA, 0xBB, 0xCC])

        cert_node = ASN1.asn1_sequence(ASN1Node[tbs, outer_sig_alg, sig_value])

        # Encode to DER
        der = encode(cert_node)
        @test length(der) > 50

        # Parse as X.509
        cert = parse_x509(der)
        @test cert.version == 3
        @test cert.serial_number == 1
        @test cert.signature_algorithm == "sha256WithRSAEncryption"
        @test cert.issuer["commonName"] == "Test CA"
        @test cert.subject["commonName"] == "Test Subject"
        @test cert.subject["organizationName"] == "Test Org"
        @test cert.not_before == DateTime(2025, 1, 1, 0, 0, 0)
        @test cert.not_after == DateTime(2026, 1, 1, 0, 0, 0)
        @test cert.public_key_algorithm == "rsaEncryption"
        @test length(cert.public_key_bytes) > 0
    end

    @testset "X.509 with extensions" begin
        # Build cert with extensions
        version = ASN1.asn1_context(0, ASN1Node[ASN1.asn1_integer(2)])
        serial = ASN1.asn1_integer(BigInt(42))
        sig_alg = ASN1.asn1_sequence(ASN1Node[
            ASN1.asn1_oid("1.2.840.113549.1.1.11"),
            ASN1.asn1_null()
        ])
        issuer = ASN1.asn1_sequence(ASN1Node[
            ASN1.asn1_set(ASN1Node[ASN1.asn1_sequence(ASN1Node[
                ASN1.asn1_oid("2.5.4.3"),
                ASN1.asn1_printable_string("CA")
            ])])
        ])
        validity = ASN1.asn1_sequence(ASN1Node[
            ASN1.asn1_utctime(DateTime(2025, 1, 1)),
            ASN1.asn1_utctime(DateTime(2026, 1, 1))
        ])
        subject = ASN1.asn1_sequence(ASN1Node[
            ASN1.asn1_set(ASN1Node[ASN1.asn1_sequence(ASN1Node[
                ASN1.asn1_oid("2.5.4.3"),
                ASN1.asn1_printable_string("Server")
            ])])
        ])
        spki = ASN1.asn1_sequence(ASN1Node[
            ASN1.asn1_sequence(ASN1Node[
                ASN1.asn1_oid("1.2.840.113549.1.1.1"),
                ASN1.asn1_null()
            ]),
            ASN1.asn1_bit_string(UInt8[0x00])
        ])

        # Extensions
        basic_constraints = ASN1.asn1_sequence(ASN1Node[
            ASN1.asn1_oid("2.5.29.19"),
            ASN1.asn1_boolean(true),
            ASN1.asn1_octet_string(encode(ASN1.asn1_sequence(ASN1Node[
                ASN1.asn1_boolean(true)
            ])))
        ])
        extensions_seq = ASN1.asn1_sequence(ASN1Node[basic_constraints])
        extensions_ctx = ASN1.asn1_context(3, ASN1Node[extensions_seq])

        tbs = ASN1.asn1_sequence(ASN1Node[
            version, serial, sig_alg, issuer, validity, subject, spki, extensions_ctx
        ])

        cert_node = ASN1.asn1_sequence(ASN1Node[
            tbs,
            ASN1.asn1_sequence(ASN1Node[
                ASN1.asn1_oid("1.2.840.113549.1.1.11"),
                ASN1.asn1_null()
            ]),
            ASN1.asn1_bit_string(UInt8[0xFF])
        ])

        der = encode(cert_node)
        cert = parse_x509(der)
        @test cert.version == 3
        @test cert.serial_number == 42
        @test haskey(cert.extensions, "basicConstraints")
        @test cert.extensions["basicConstraints"]["critical"] == true
    end

    @testset "decode_all" begin
        # Encode two separate nodes
        n1 = ASN1.asn1_integer(1)
        n2 = ASN1.asn1_integer(2)
        b = vcat(encode(n1), encode(n2))
        
        nodes = ASN1.decode_all(b)
        @test length(nodes) == 2
        @test ASN1.extract_integer(nodes[1]) == 1
        @test ASN1.extract_integer(nodes[2]) == 2
    end

    @testset "Show methods" begin
        node = ASN1.asn1_sequence(ASN1Node[
            ASN1.asn1_integer(42),
            ASN1.asn1_null()
        ])
        io = IOBuffer()
        show(io, node)
        s = String(take!(io))
        @test occursin("SEQUENCE", s)

        cert_node = ASN1.asn1_sequence(ASN1Node[
            ASN1.asn1_sequence(ASN1Node[
                ASN1.asn1_context(0, ASN1Node[ASN1.asn1_integer(2)]),
                ASN1.asn1_integer(1),
                ASN1.asn1_sequence(ASN1Node[ASN1.asn1_oid("1.2.840.113549.1.1.11"), ASN1.asn1_null()]),
                ASN1.asn1_sequence(ASN1Node[ASN1.asn1_set(ASN1Node[ASN1.asn1_sequence(ASN1Node[ASN1.asn1_oid("2.5.4.3"), ASN1.asn1_printable_string("Test")])])]),
                ASN1.asn1_sequence(ASN1Node[ASN1.asn1_utctime(DateTime(2025,1,1)), ASN1.asn1_utctime(DateTime(2026,1,1))]),
                ASN1.asn1_sequence(ASN1Node[ASN1.asn1_set(ASN1Node[ASN1.asn1_sequence(ASN1Node[ASN1.asn1_oid("2.5.4.3"), ASN1.asn1_printable_string("Test")])])]),
                ASN1.asn1_sequence(ASN1Node[ASN1.asn1_sequence(ASN1Node[ASN1.asn1_oid("1.2.840.113549.1.1.1"), ASN1.asn1_null()]), ASN1.asn1_bit_string(UInt8[0x00])]),
            ]),
            ASN1.asn1_sequence(ASN1Node[ASN1.asn1_oid("1.2.840.113549.1.1.11"), ASN1.asn1_null()]),
            ASN1.asn1_bit_string(UInt8[0xFF]),
        ])
        der = encode(cert_node)
        cert = parse_x509(der)
        io2 = IOBuffer()
        show(io2, cert)
        s2 = String(take!(io2))
        @test occursin("X509Certificate", s2)
        @test occursin("Test", s2)
    end

    @testset "Edge cases" begin
        # Single byte data
        node = ASN1.asn1_integer(0)
        @test ASN1.extract_integer(decode(encode(node))) == 0

        # Empty SEQUENCE
        seq = ASN1.asn1_sequence(ASN1Node[])
        b = encode(seq)
        @test b == UInt8[0x30, 0x00]
        d = decode(b)
        @test isempty(d.value)

        # Large integer round-trip
        big_n = BigInt(2)^128 - 1
        node = ASN1.asn1_integer(big_n)
        @test ASN1.extract_integer(decode(encode(node))) == big_n
    end

    @testset "Tag constants" begin
        @test TAG_BOOLEAN == 0x01
        @test TAG_INTEGER == 0x02
        @test TAG_BIT_STRING == 0x03
        @test TAG_OCTET_STRING == 0x04
        @test TAG_NULL == 0x05
        @test TAG_OID == 0x06
        @test TAG_SEQUENCE == 0x30
        @test TAG_SET == 0x31
    end

    @testset "Error handling" begin
        @test_throws ErrorException decode(UInt8[])
        @test_throws ErrorException ASN1._decode_length(UInt8[0x80], 1)  # Indefinite length
    end
end
