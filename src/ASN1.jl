"""
    ASN1

Pure-Julia ASN.1 (Abstract Syntax Notation One) encoder/decoder supporting
DER (Distinguished Encoding Rules) and BER (Basic Encoding Rules), with
X.509 certificate parsing.

# Quick Start
```julia
using ASN1

# Parse DER-encoded data
node = decode(der_bytes)

# Encode to DER
bytes = encode(node)

# Parse X.509 certificate
cert = parse_x509(cert_bytes)
println(cert.subject)
```
"""
module ASN1

using Dates

export ASN1Node, ASN1Tag, TagClass, decode, encode, decode_pem, encode_der,
       X509Certificate, parse_x509, parse_x509_pem,
       # Tag constants
       TAG_BOOLEAN, TAG_INTEGER, TAG_BIT_STRING, TAG_OCTET_STRING,
       TAG_NULL, TAG_OID, TAG_UTF8STRING, TAG_SEQUENCE, TAG_SET,
       TAG_PRINTABLE_STRING, TAG_IA5STRING, TAG_UTC_TIME,
       TAG_GENERALIZED_TIME, TAG_CONTEXT

# ─────────────────────────────────────────────────────────────────────────────
#                              TAG DEFINITIONS
# ─────────────────────────────────────────────────────────────────────────────

"""ASN.1 tag class."""
@enum TagClass begin
    UNIVERSAL       = 0x00
    APPLICATION     = 0x40
    CONTEXT         = 0x80
    PRIVATE         = 0xC0
end

# Universal tag numbers
const TAG_BOOLEAN           = 0x01
const TAG_INTEGER           = 0x02
const TAG_BIT_STRING        = 0x03
const TAG_OCTET_STRING      = 0x04
const TAG_NULL              = 0x05
const TAG_OID               = 0x06
const TAG_ENUMERATED        = 0x0A
const TAG_UTF8STRING        = 0x0C
const TAG_SEQUENCE          = 0x30
const TAG_SET               = 0x31
const TAG_NUMERIC_STRING    = 0x12
const TAG_PRINTABLE_STRING  = 0x13
const TAG_T61STRING         = 0x14
const TAG_IA5STRING         = 0x16
const TAG_UTC_TIME          = 0x17
const TAG_GENERALIZED_TIME  = 0x18
const TAG_VISIBLE_STRING    = 0x1A
const TAG_BMP_STRING        = 0x1E
const TAG_CONTEXT           = 0xA0  # Context-specific constructed [0]

"""ASN.1 tag information."""
struct ASN1Tag
    class::TagClass
    constructed::Bool
    number::UInt32
end

"""ASN.1 node in the parsed tree."""
struct ASN1Node
    tag::ASN1Tag
    value::Union{Vector{UInt8}, Vector{ASN1Node}, Nothing}
    raw_tag_byte::UInt8
end

function ASN1Node(tag::ASN1Tag, value)
    raw = UInt8(UInt8(tag.class) | (tag.constructed ? 0x20 : 0x00) | UInt8(min(tag.number, 0x1F)))
    ASN1Node(tag, value, raw)
end

function Base.show(io::IO, node::ASN1Node)
    _show_node(io, node, 0)
end

function _show_node(io::IO, node::ASN1Node, indent::Int)
    prefix = " " ^ indent
    tag_name = _tag_name(node.tag)
    if node.tag.constructed && node.value isa Vector{ASN1Node}
        println(io, "$(prefix)$(tag_name) ($(length(node.value)) children)")
        for child in node.value
            _show_node(io, child, indent + 2)
        end
    elseif node.value isa Vector{UInt8}
        vlen = length(node.value)
        if vlen <= 20
            hex = join(string.(node.value; base=16, pad=2), " ")
            println(io, "$(prefix)$(tag_name) [$(vlen)] = $(hex)")
        else
            println(io, "$(prefix)$(tag_name) [$(vlen) bytes]")
        end
    else
        println(io, "$(prefix)$(tag_name) = NULL")
    end
end

function _tag_name(tag::ASN1Tag)
    if tag.class == UNIVERSAL
        names = Dict(
            0x01 => "BOOLEAN", 0x02 => "INTEGER", 0x03 => "BIT STRING",
            0x04 => "OCTET STRING", 0x05 => "NULL", 0x06 => "OID",
            0x0A => "ENUMERATED", 0x0C => "UTF8String",
            0x10 => "SEQUENCE", 0x11 => "SET",
            0x12 => "NumericString", 0x13 => "PrintableString",
            0x14 => "T61String", 0x16 => "IA5String",
            0x17 => "UTCTime", 0x18 => "GeneralizedTime",
            0x1A => "VisibleString", 0x1E => "BMPString",
        )
        return get(names, tag.number, "UNIVERSAL($(tag.number))")
    elseif tag.class == CONTEXT
        return "[$(tag.number)]"
    elseif tag.class == APPLICATION
        return "APPLICATION($(tag.number))"
    else
        return "PRIVATE($(tag.number))"
    end
end

# ─────────────────────────────────────────────────────────────────────────────
#                              DER/BER DECODER
# ─────────────────────────────────────────────────────────────────────────────

"""
    decode(data::Vector{UInt8}) -> ASN1Node

Decode DER/BER-encoded ASN.1 data into a tree of ASN1Nodes.
"""
function decode(data::Vector{UInt8})::ASN1Node
    node, _ = _decode_tlv(data, 1)
    return node
end

"""
    decode_all(data::Vector{UInt8}) -> Vector{ASN1Node}

Decode all TLV structures from data (may contain multiple top-level nodes).
"""
function decode_all(data::Vector{UInt8})::Vector{ASN1Node}
    nodes = ASN1Node[]
    pos = 1
    while pos <= length(data)
        node, pos = _decode_tlv(data, pos)
        push!(nodes, node)
    end
    return nodes
end

"""Decode a single TLV (Tag-Length-Value) from data at position pos."""
function _decode_tlv(data::Vector{UInt8}, pos::Int)::Tuple{ASN1Node, Int}
    pos > length(data) && error("ASN1: unexpected end of data at position $pos")
    
    # Decode tag
    tag_byte = data[pos]
    tag, pos = _decode_tag(data, pos)
    
    # Decode length
    len, pos = _decode_length(data, pos)
    
    if tag.constructed
        # Parse children
        children = ASN1Node[]
        end_pos = pos + len
        child_pos = pos
        while child_pos < end_pos
            child, child_pos = _decode_tlv(data, child_pos)
            push!(children, child)
        end
        return ASN1Node(tag, children, tag_byte), end_pos
    else
        # Primitive: extract raw value bytes
        end_pos = pos + len
        end_pos - 1 > length(data) && error("ASN1: value extends beyond data (need $end_pos, have $(length(data)))")
        value = data[pos:end_pos-1]
        return ASN1Node(tag, value, tag_byte), end_pos
    end
end

"""Decode ASN.1 tag."""
function _decode_tag(data::Vector{UInt8}, pos::Int)::Tuple{ASN1Tag, Int}
    b = data[pos]
    cls = TagClass(b & 0xC0)
    constructed = (b & 0x20) != 0
    number = UInt32(b & 0x1F)
    pos += 1
    
    if number == 0x1F
        # Long form tag
        number = UInt32(0)
        while pos <= length(data)
            b = data[pos]
            number = (number << 7) | UInt32(b & 0x7F)
            pos += 1
            (b & 0x80) == 0 && break
        end
    end
    
    return ASN1Tag(cls, constructed, number), pos
end

"""Decode ASN.1 length."""
function _decode_length(data::Vector{UInt8}, pos::Int)::Tuple{Int, Int}
    pos > length(data) && error("ASN1: unexpected end of data reading length")
    b = data[pos]
    pos += 1
    
    if b == 0x80
        # Indefinite length (BER only) — not supported in DER
        error("ASN1: indefinite length encoding not supported")
    elseif (b & 0x80) == 0
        # Short form
        return Int(b), pos
    else
        # Long form
        num_bytes = Int(b & 0x7F)
        num_bytes == 0 && error("ASN1: invalid length encoding")
        len = 0
        for _ in 1:num_bytes
            pos > length(data) && error("ASN1: unexpected end of data reading length")
            len = (len << 8) | Int(data[pos])
            pos += 1
        end
        return len, pos
    end
end

# ─────────────────────────────────────────────────────────────────────────────
#                              DER ENCODER
# ─────────────────────────────────────────────────────────────────────────────

"""
    encode(node::ASN1Node) -> Vector{UInt8}

Encode an ASN1Node tree to DER format.
"""
function encode(node::ASN1Node)::Vector{UInt8}
    result = UInt8[]
    _encode_node!(result, node)
    return result
end

"""Alias for encode."""
encode_der(node::ASN1Node) = encode(node)

"""Encode a node into the result buffer."""
function _encode_node!(result::Vector{UInt8}, node::ASN1Node)
    # Encode tag
    _encode_tag!(result, node.tag)
    
    if node.tag.constructed && node.value isa Vector{ASN1Node}
        # Encode children first to get total length
        children_bytes = UInt8[]
        for child in node.value
            _encode_node!(children_bytes, child)
        end
        _encode_length!(result, length(children_bytes))
        append!(result, children_bytes)
    elseif node.value isa Vector{UInt8}
        _encode_length!(result, length(node.value))
        append!(result, node.value)
    else
        # NULL
        _encode_length!(result, 0)
    end
end

"""Encode ASN.1 tag."""
function _encode_tag!(result::Vector{UInt8}, tag::ASN1Tag)
    b = UInt8(tag.class) | (tag.constructed ? UInt8(0x20) : UInt8(0x00))
    
    if tag.number < 0x1F
        push!(result, b | UInt8(tag.number))
    else
        push!(result, b | UInt8(0x1F))
        _encode_tag_number!(result, tag.number)
    end
end

"""Encode long-form tag number."""
function _encode_tag_number!(result::Vector{UInt8}, number::UInt32)
    bytes = UInt8[]
    n = number
    pushfirst!(bytes, UInt8(n & 0x7F))
    n >>= 7
    while n > 0
        pushfirst!(bytes, UInt8(0x80 | (n & 0x7F)))
        n >>= 7
    end
    append!(result, bytes)
end

"""Encode DER length."""
function _encode_length!(result::Vector{UInt8}, len::Int)
    if len < 0x80
        push!(result, UInt8(len))
    elseif len < 0x100
        push!(result, UInt8(0x81))
        push!(result, UInt8(len))
    elseif len < 0x10000
        push!(result, UInt8(0x82))
        push!(result, UInt8((len >> 8) & 0xFF))
        push!(result, UInt8(len & 0xFF))
    elseif len < 0x1000000
        push!(result, UInt8(0x83))
        push!(result, UInt8((len >> 16) & 0xFF))
        push!(result, UInt8((len >> 8) & 0xFF))
        push!(result, UInt8(len & 0xFF))
    else
        push!(result, UInt8(0x84))
        push!(result, UInt8((len >> 24) & 0xFF))
        push!(result, UInt8((len >> 16) & 0xFF))
        push!(result, UInt8((len >> 8) & 0xFF))
        push!(result, UInt8(len & 0xFF))
    end
end

# ─────────────────────────────────────────────────────────────────────────────
#                              VALUE HELPERS
# ─────────────────────────────────────────────────────────────────────────────

"""Create a BOOLEAN node."""
function asn1_boolean(val::Bool)
    tag = ASN1Tag(UNIVERSAL, false, 0x01)
    ASN1Node(tag, UInt8[val ? 0xFF : 0x00])
end

"""Create an INTEGER node from a BigInt or Int."""
function asn1_integer(val::Integer)
    tag = ASN1Tag(UNIVERSAL, false, 0x02)
    if val == 0
        return ASN1Node(tag, UInt8[0x00])
    end
    
    bytes = UInt8[]
    v = abs(val)
    while v > 0
        pushfirst!(bytes, UInt8(v & 0xFF))
        v >>= 8
    end
    
    # Add leading zero if high bit set (positive number)
    if val > 0 && (bytes[1] & 0x80) != 0
        pushfirst!(bytes, 0x00)
    end
    
    # Two's complement for negative
    if val < 0
        # Invert and add 1
        for i in eachindex(bytes)
            bytes[i] = ~bytes[i]
        end
        carry = true
        for i in length(bytes):-1:1
            if carry
                if bytes[i] == 0xFF
                    bytes[i] = 0x00
                else
                    bytes[i] += 1
                    carry = false
                end
            end
        end
    end
    
    ASN1Node(tag, bytes)
end

"""Create a NULL node."""
function asn1_null()
    tag = ASN1Tag(UNIVERSAL, false, 0x05)
    ASN1Node(tag, UInt8[])
end

"""Create an OCTET STRING node."""
function asn1_octet_string(data::Vector{UInt8})
    tag = ASN1Tag(UNIVERSAL, false, 0x04)
    ASN1Node(tag, data)
end

"""Create a BIT STRING node."""
function asn1_bit_string(data::Vector{UInt8}; unused_bits::UInt8=0x00)
    tag = ASN1Tag(UNIVERSAL, false, 0x03)
    ASN1Node(tag, vcat(UInt8[unused_bits], data))
end

"""Create a UTF8String node."""
function asn1_utf8string(s::AbstractString)
    tag = ASN1Tag(UNIVERSAL, false, 0x0C)
    ASN1Node(tag, Vector{UInt8}(s))
end

"""Create a PrintableString node."""
function asn1_printable_string(s::AbstractString)
    tag = ASN1Tag(UNIVERSAL, false, 0x13)
    ASN1Node(tag, Vector{UInt8}(s))
end

"""Create an IA5String node."""
function asn1_ia5string(s::AbstractString)
    tag = ASN1Tag(UNIVERSAL, false, 0x16)
    ASN1Node(tag, Vector{UInt8}(s))
end

"""Create a SEQUENCE node."""
function asn1_sequence(children::Vector{ASN1Node})
    tag = ASN1Tag(UNIVERSAL, true, 0x10)
    ASN1Node(tag, children)
end

"""Create a SET node."""
function asn1_set(children::Vector{ASN1Node})
    tag = ASN1Tag(UNIVERSAL, true, 0x11)
    ASN1Node(tag, children)
end

"""Create an OID node from a dotted string like "1.2.840.113549"."""
function asn1_oid(oid_str::AbstractString)
    tag = ASN1Tag(UNIVERSAL, false, 0x06)
    parts = parse.(Int, split(oid_str, "."))
    length(parts) < 2 && error("OID must have at least 2 components")
    
    bytes = UInt8[]
    # First two components encoded as 40*X + Y
    push!(bytes, UInt8(40 * parts[1] + parts[2]))
    
    for i in 3:length(parts)
        _encode_oid_component!(bytes, parts[i])
    end
    
    ASN1Node(tag, bytes)
end

"""Encode a single OID component in base-128."""
function _encode_oid_component!(bytes::Vector{UInt8}, val::Int)
    if val < 128
        push!(bytes, UInt8(val))
        return
    end
    
    # Encode in base-128, high bit set except for last byte
    temp = UInt8[]
    v = val
    pushfirst!(temp, UInt8(v & 0x7F))
    v >>= 7
    while v > 0
        pushfirst!(temp, UInt8(0x80 | (v & 0x7F)))
        v >>= 7
    end
    append!(bytes, temp)
end

"""Create a UTCTime node."""
function asn1_utctime(dt::DateTime)
    tag = ASN1Tag(UNIVERSAL, false, 0x17)
    s = Dates.format(dt, "yymmddHHMMSS") * "Z"
    ASN1Node(tag, Vector{UInt8}(s))
end

"""Create a GeneralizedTime node."""
function asn1_generalized_time(dt::DateTime)
    tag = ASN1Tag(UNIVERSAL, false, 0x18)
    s = Dates.format(dt, "yyyymmddHHMMSS") * "Z"
    ASN1Node(tag, Vector{UInt8}(s))
end

"""Create a context-specific tagged node."""
function asn1_context(tag_number::Int, children::Vector{ASN1Node}; constructed::Bool=true)
    tag = ASN1Tag(CONTEXT, constructed, UInt32(tag_number))
    if constructed
        ASN1Node(tag, children)
    else
        # For primitive context, flatten children to bytes
        bytes = UInt8[]
        for child in children
            append!(bytes, encode(child))
        end
        ASN1Node(tag, bytes)
    end
end

# ─────────────────────────────────────────────────────────────────────────────
#                              VALUE EXTRACTORS
# ─────────────────────────────────────────────────────────────────────────────

"""Extract boolean value from an ASN1Node."""
function extract_boolean(node::ASN1Node)::Bool
    node.value isa Vector{UInt8} || error("Expected primitive value")
    return node.value[1] != 0x00
end

"""Extract integer value from an ASN1Node."""
function extract_integer(node::ASN1Node)::BigInt
    node.value isa Vector{UInt8} || error("Expected primitive value")
    isempty(node.value) && return BigInt(0)
    
    # Check sign
    negative = (node.value[1] & 0x80) != 0
    
    result = BigInt(0)
    for b in node.value
        result = (result << 8) | BigInt(b)
    end
    
    if negative
        # Two's complement
        result -= BigInt(1) << (8 * length(node.value))
    end
    
    return result
end

"""Extract string value from an ASN1Node."""
function extract_string(node::ASN1Node)::String
    node.value isa Vector{UInt8} || error("Expected primitive value")
    return String(copy(node.value))
end

"""Extract OID as dotted string from an ASN1Node."""
function extract_oid(node::ASN1Node)::String
    node.value isa Vector{UInt8} || error("Expected primitive value")
    isempty(node.value) && return ""
    
    # First byte encodes first two components
    first_byte = Int(node.value[1])
    components = [first_byte ÷ 40, first_byte % 40]
    
    # Decode remaining components (base-128)
    i = 2
    while i <= length(node.value)
        val = 0
        while i <= length(node.value)
            b = Int(node.value[i])
            val = (val << 7) | (b & 0x7F)
            i += 1
            (b & 0x80) == 0 && break
        end
        push!(components, val)
    end
    
    return join(components, ".")
end

"""Extract UTCTime as DateTime."""
function extract_utctime(node::ASN1Node)::DateTime
    s = extract_string(node)
    # Format: YYMMDDHHMMSSZ
    s = rstrip(s, 'Z')
    yy = parse(Int, s[1:2])
    year = yy >= 50 ? 1900 + yy : 2000 + yy
    mm = parse(Int, s[3:4])
    dd = parse(Int, s[5:6])
    hh = parse(Int, s[7:8])
    mi = parse(Int, s[9:10])
    ss = length(s) >= 12 ? parse(Int, s[11:12]) : 0
    DateTime(year, mm, dd, hh, mi, ss)
end

"""Extract GeneralizedTime as DateTime."""
function extract_generalized_time(node::ASN1Node)::DateTime
    s = extract_string(node)
    s = rstrip(s, 'Z')
    year = parse(Int, s[1:4])
    mm = parse(Int, s[5:6])
    dd = parse(Int, s[7:8])
    hh = parse(Int, s[9:10])
    mi = parse(Int, s[11:12])
    ss = length(s) >= 14 ? parse(Int, s[13:14]) : 0
    DateTime(year, mm, dd, hh, mi, ss)
end

# ─────────────────────────────────────────────────────────────────────────────
#                              PEM SUPPORT
# ─────────────────────────────────────────────────────────────────────────────

"""Decode PEM-encoded data to raw DER bytes."""
function decode_pem(pem::AbstractString)::Vector{UInt8}
    lines = split(strip(pem), "\n")
    # Remove header/footer lines
    content_lines = filter(l -> !startswith(strip(l), "-----"), lines)
    b64 = join(strip.(content_lines), "")
    return base64_decode(b64)
end

"""Simple base64 decoder (no dependency on Base64 stdlib)."""
function base64_decode(s::AbstractString)::Vector{UInt8}
    b64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    lookup = Dict{Char, UInt8}()
    for (i, c) in enumerate(b64chars)
        lookup[c] = UInt8(i - 1)
    end
    
    # Remove whitespace and padding
    s = filter(c -> c != '=' && c != '\n' && c != '\r' && c != ' ', s)
    
    result = UInt8[]
    i = 1
    while i <= length(s)
        n = min(4, length(s) - i + 1)
        vals = UInt8[get(lookup, s[i+j-1], 0x00) for j in 1:n]
        
        if n >= 2
            push!(result, UInt8(((vals[1] << 2) | (vals[2] >> 4)) & 0xFF))
        end
        if n >= 3
            push!(result, UInt8(((vals[2] << 4) | (vals[3] >> 2)) & 0xFF))
        end
        if n >= 4
            push!(result, UInt8(((vals[3] << 6) | vals[4]) & 0xFF))
        end
        
        i += 4
    end
    
    return result
end

# ─────────────────────────────────────────────────────────────────────────────
#                              OID REGISTRY
# ─────────────────────────────────────────────────────────────────────────────

const OID_NAMES = Dict{String, String}(
    "1.2.840.113549.1.1.1"  => "rsaEncryption",
    "1.2.840.113549.1.1.5"  => "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.11" => "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12" => "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13" => "sha512WithRSAEncryption",
    "1.2.840.10045.2.1"     => "ecPublicKey",
    "1.2.840.10045.3.1.7"   => "prime256v1",
    "1.3.132.0.34"          => "secp384r1",
    "1.3.132.0.35"          => "secp521r1",
    "2.5.4.3"               => "commonName",
    "2.5.4.6"               => "countryName",
    "2.5.4.7"               => "localityName",
    "2.5.4.8"               => "stateOrProvinceName",
    "2.5.4.10"              => "organizationName",
    "2.5.4.11"              => "organizationalUnitName",
    "2.5.29.14"             => "subjectKeyIdentifier",
    "2.5.29.15"             => "keyUsage",
    "2.5.29.17"             => "subjectAltName",
    "2.5.29.19"             => "basicConstraints",
    "2.5.29.35"             => "authorityKeyIdentifier",
    "2.5.29.31"             => "cRLDistributionPoints",
    "2.5.29.32"             => "certificatePolicies",
    "2.5.29.37"             => "extKeyUsage",
    "1.3.6.1.5.5.7.1.1"    => "authorityInfoAccess",
    "1.3.6.1.5.5.7.3.1"    => "serverAuth",
    "1.3.6.1.5.5.7.3.2"    => "clientAuth",
    "1.3.6.1.4.1.11129.2.4.2" => "signedCertificateTimestampList",
)

"""Look up OID name."""
function oid_name(oid::String)::String
    return get(OID_NAMES, oid, oid)
end

# ─────────────────────────────────────────────────────────────────────────────
#                              X.509 CERTIFICATE
# ─────────────────────────────────────────────────────────────────────────────

"""Parsed X.509 certificate."""
struct X509Certificate
    version::Int
    serial_number::BigInt
    signature_algorithm::String
    issuer::Dict{String, String}
    not_before::DateTime
    not_after::DateTime
    subject::Dict{String, String}
    public_key_algorithm::String
    public_key_bytes::Vector{UInt8}
    extensions::Dict{String, Any}
    raw::ASN1Node
end

function Base.show(io::IO, cert::X509Certificate)
    println(io, "X509Certificate:")
    println(io, "  Version: $(cert.version)")
    println(io, "  Serial: $(cert.serial_number)")
    println(io, "  Signature Algorithm: $(cert.signature_algorithm)")
    println(io, "  Issuer: $(cert.issuer)")
    println(io, "  Subject: $(cert.subject)")
    println(io, "  Not Before: $(cert.not_before)")
    println(io, "  Not After: $(cert.not_after)")
    println(io, "  Public Key: $(cert.public_key_algorithm)")
    print(io, "  Extensions: $(length(cert.extensions))")
end

"""
    parse_x509(der_bytes::Vector{UInt8}) -> X509Certificate

Parse a DER-encoded X.509 certificate.
"""
function parse_x509(der_bytes::Vector{UInt8})::X509Certificate
    root = decode(der_bytes)
    _parse_x509_node(root)
end

"""
    parse_x509_pem(pem::AbstractString) -> X509Certificate

Parse a PEM-encoded X.509 certificate.
"""
function parse_x509_pem(pem::AbstractString)::X509Certificate
    der = decode_pem(pem)
    parse_x509(der)
end

"""Parse X.509 from decoded ASN1Node tree."""
function _parse_x509_node(root::ASN1Node)::X509Certificate
    # Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    children = root.value::Vector{ASN1Node}
    tbs = children[1]  # TBSCertificate
    
    tbs_children = tbs.value::Vector{ASN1Node}
    idx = 1
    
    # Version (optional, context [0])
    version = 1
    if tbs_children[idx].tag.class == CONTEXT && tbs_children[idx].tag.number == 0
        ver_node = tbs_children[idx].value::Vector{ASN1Node}
        version = Int(extract_integer(ver_node[1])) + 1
        idx += 1
    end
    
    # Serial number
    serial = extract_integer(tbs_children[idx])
    idx += 1
    
    # Signature algorithm
    sig_alg_seq = tbs_children[idx].value::Vector{ASN1Node}
    sig_alg = oid_name(extract_oid(sig_alg_seq[1]))
    idx += 1
    
    # Issuer
    issuer = _parse_name(tbs_children[idx])
    idx += 1
    
    # Validity
    validity = tbs_children[idx].value::Vector{ASN1Node}
    not_before = _parse_time(validity[1])
    not_after = _parse_time(validity[2])
    idx += 1
    
    # Subject
    subject = _parse_name(tbs_children[idx])
    idx += 1
    
    # Subject public key info
    spki = tbs_children[idx].value::Vector{ASN1Node}
    pk_alg_seq = spki[1].value::Vector{ASN1Node}
    pk_alg = oid_name(extract_oid(pk_alg_seq[1]))
    pk_bytes = spki[2].value isa Vector{UInt8} ? spki[2].value : UInt8[]
    idx += 1
    
    # Extensions (optional, context [3])
    extensions = Dict{String, Any}()
    while idx <= length(tbs_children)
        node = tbs_children[idx]
        if node.tag.class == CONTEXT && node.tag.number == 3
            ext_seq = node.value::Vector{ASN1Node}
            if !isempty(ext_seq)
                extensions = _parse_extensions(ext_seq[1])
            end
        end
        idx += 1
    end
    
    X509Certificate(version, serial, sig_alg, issuer, not_before, not_after,
                    subject, pk_alg, pk_bytes, extensions, root)
end

"""Parse an X.509 Name (SEQUENCE of SETs of SEQUENCE of {OID, value})."""
function _parse_name(node::ASN1Node)::Dict{String, String}
    result = Dict{String, String}()
    sets = node.value::Vector{ASN1Node}
    
    for set_node in sets
        seqs = set_node.value::Vector{ASN1Node}
        for seq in seqs
            pair = seq.value::Vector{ASN1Node}
            oid = oid_name(extract_oid(pair[1]))
            val = extract_string(pair[2])
            result[oid] = val
        end
    end
    
    return result
end

"""Parse a time value (UTCTime or GeneralizedTime)."""
function _parse_time(node::ASN1Node)::DateTime
    if node.tag.number == 0x17
        return extract_utctime(node)
    elseif node.tag.number == 0x18
        return extract_generalized_time(node)
    else
        error("Unknown time type: $(node.tag.number)")
    end
end

"""Parse X.509 extensions."""
function _parse_extensions(seq_node::ASN1Node)::Dict{String, Any}
    extensions = Dict{String, Any}()
    exts = seq_node.value::Vector{ASN1Node}
    
    for ext in exts
        ext_fields = ext.value::Vector{ASN1Node}
        oid = extract_oid(ext_fields[1])
        name = oid_name(oid)
        
        critical = false
        value_idx = 2
        if length(ext_fields) >= 3 && ext_fields[2].tag.number == 0x01
            critical = extract_boolean(ext_fields[2])
            value_idx = 3
        end
        
        ext_value = ext_fields[value_idx].value isa Vector{UInt8} ? ext_fields[value_idx].value : UInt8[]
        extensions[name] = Dict{String, Any}(
            "oid" => oid,
            "critical" => critical,
            "value" => ext_value
        )
    end
    
    return extensions
end

end # module ASN1
