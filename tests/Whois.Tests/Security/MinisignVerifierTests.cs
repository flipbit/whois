using Xunit;
using Whois.Security;

namespace Whois.Tests.Security;

/// <summary>
/// Tests for MinisignVerifier.
///
/// Test fixtures are derived from RFC 8032 §7.1 test vectors wrapped in the minisign
/// binary format (2-byte algorithm "Ed" + 8-byte key ID + Ed25519 key/signature).
///
/// RFC 8032 Test Vector 1: empty message, known public key + signature.
/// RFC 8032 Test Vector 2: message = [0x72], different known public key + signature.
/// </summary>
public class MinisignVerifierTests
{
    // -------------------------------------------------------------------------
    // Test fixtures derived from RFC 8032 §7.1 test vectors
    //
    // Public key blob layout (42 bytes): "Ed" (2) + keyId (8) + ed25519PubKey (32)
    // Signature blob layout (74 bytes):  "Ed" (2) + keyId (8) + ed25519Sig (64)
    //
    // All blobs are base64-encoded in the minisign file format.
    // -------------------------------------------------------------------------

    // RFC 8032 Vector 1  -  empty message
    private const string ValidPublicKey =
        "untrusted comment: minisign public key test\n" +
        "RWQBAgMEBQYHCNdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea";

    private const string ValidSignatureForEmptyContent =
        "untrusted comment: signature from test vector\n" +
        "RWQBAgMEBQYHCOVWQwDDYKxykIbizIBugoqEh38euOXZdNhz4GUiSQFVX7iCFZCjO6zGHjlwHPm0a9Jb9fBZW74kZVFBQ456EAs=";

    // RFC 8032 Vector 2  -  message = [0x72]
    private const string ValidPublicKey2 =
        "untrusted comment: minisign public key test 2\n" +
        "RWQBAgMEBQYHCD1AF8PoQ4lakrcKp00bfrycmCzPLsSWjMDNVfEq9GYM";

    private const string ValidSignatureForSingleByte =
        "untrusted comment: signature from test vector 2\n" +
        "RWQBAgMEBQYHCJKgCanw1Mq4cg6CC19kJUCisntUFlA/j7N2IiPr22naCFrB5D4VmW5FjzYT0PEdjDh7Lq60MCrusA0pFhK7DAA=";

    // Public key with a different key ID (key ID mismatch with the above signatures)
    private const string WrongKeyIdPublicKey =
        "untrusted comment: minisign public key wrong kid\n" +
        "RWSqu8zd7v8RItdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea";

    // -------------------------------------------------------------------------
    // Happy path
    // -------------------------------------------------------------------------

    [Fact]
    public void Verify_ValidSignatureForEmptyContent_ReturnsTrue()
    {
        var result = MinisignVerifier.Verify(
            content: Array.Empty<byte>(),
            signatureText: ValidSignatureForEmptyContent,
            publicKeyText: ValidPublicKey);

        Assert.True(result);
    }

    [Fact]
    public void Verify_ValidSignatureForSingleByteContent_ReturnsTrue()
    {
        var result = MinisignVerifier.Verify(
            content: new byte[] { 0x72 },
            signatureText: ValidSignatureForSingleByte,
            publicKeyText: ValidPublicKey2);

        Assert.True(result);
    }

    // -------------------------------------------------------------------------
    // Tampered content  -  same signature, different bytes
    // -------------------------------------------------------------------------

    [Fact]
    public void Verify_TamperedContent_ReturnsFalse()
    {
        var result = MinisignVerifier.Verify(
            content: new byte[] { 0xFF },
            signatureText: ValidSignatureForEmptyContent,
            publicKeyText: ValidPublicKey);

        Assert.False(result);
    }

    // -------------------------------------------------------------------------
    // Tampered signature  -  flip one bit in the Ed25519 sig bytes
    // -------------------------------------------------------------------------

    [Fact]
    public void Verify_TamperedSignature_ReturnsFalse()
    {
        // Decode the signature, flip a bit in the Ed25519 sig, re-encode
        var lines = ValidSignatureForEmptyContent.Split('\n');
        var sigBlob = Convert.FromBase64String(lines[1]);
        sigBlob[10] ^= 0x01; // flip bit in Ed25519 signature bytes (offset 10: after 2+8 header bytes)
        var tamperedSig =
            lines[0] + "\n" +
            Convert.ToBase64String(sigBlob);

        var result = MinisignVerifier.Verify(
            content: Array.Empty<byte>(),
            signatureText: tamperedSig,
            publicKeyText: ValidPublicKey);

        Assert.False(result);
    }

    // -------------------------------------------------------------------------
    // Wrong public key  -  use vector-2 key to verify vector-1 signature
    // -------------------------------------------------------------------------

    [Fact]
    public void Verify_WrongPublicKey_ReturnsFalse()
    {
        var result = MinisignVerifier.Verify(
            content: Array.Empty<byte>(),
            signatureText: ValidSignatureForEmptyContent,
            publicKeyText: ValidPublicKey2);

        Assert.False(result);
    }

    // -------------------------------------------------------------------------
    // Key ID mismatch  -  right Ed25519 key, but key ID in public key doesn't match sig
    // -------------------------------------------------------------------------

    [Fact]
    public void Verify_KeyIdMismatch_ReturnsFalse()
    {
        var result = MinisignVerifier.Verify(
            content: Array.Empty<byte>(),
            signatureText: ValidSignatureForEmptyContent,
            publicKeyText: WrongKeyIdPublicKey);

        Assert.False(result);
    }

    // -------------------------------------------------------------------------
    // Malformed public key
    // -------------------------------------------------------------------------

    [Fact]
    public void Verify_MalformedPublicKey_TooFewLines_ReturnsFalse()
    {
        var result = MinisignVerifier.Verify(
            content: Array.Empty<byte>(),
            signatureText: ValidSignatureForEmptyContent,
            publicKeyText: "RWQBAgMEBQYHCNdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea");

        Assert.False(result);
    }

    [Fact]
    public void Verify_MalformedPublicKey_NotBase64_ReturnsFalse()
    {
        var result = MinisignVerifier.Verify(
            content: Array.Empty<byte>(),
            signatureText: ValidSignatureForEmptyContent,
            publicKeyText: "untrusted comment: test\nnot-valid-base64!!!");

        Assert.False(result);
    }

    [Fact]
    public void Verify_MalformedPublicKey_TooShort_ReturnsFalse()
    {
        // Valid base64 but only 10 bytes  -  too short for a 42-byte public key blob
        var shortBlob = Convert.ToBase64String(new byte[10]);
        var result = MinisignVerifier.Verify(
            content: Array.Empty<byte>(),
            signatureText: ValidSignatureForEmptyContent,
            publicKeyText: $"untrusted comment: test\n{shortBlob}");

        Assert.False(result);
    }

    [Fact]
    public void Verify_MalformedPublicKey_WrongAlgorithm_ReturnsFalse()
    {
        // Construct a blob with algorithm "XX" instead of "Ed"
        var blob = Convert.FromBase64String(
            ValidPublicKey.Split('\n')[1]);
        blob[0] = (byte)'X';
        blob[1] = (byte)'X';
        var result = MinisignVerifier.Verify(
            content: Array.Empty<byte>(),
            signatureText: ValidSignatureForEmptyContent,
            publicKeyText: $"untrusted comment: test\n{Convert.ToBase64String(blob)}");

        Assert.False(result);
    }

    // -------------------------------------------------------------------------
    // Malformed signature
    // -------------------------------------------------------------------------

    [Fact]
    public void Verify_MalformedSignature_TooFewLines_ReturnsFalse()
    {
        var result = MinisignVerifier.Verify(
            content: Array.Empty<byte>(),
            signatureText: "RWQBAgMEBQYHCOVWQwDDYKxykIbizIBugoqEh38euOXZdNhz4GUiSQFVX7iCFZCjO6zGHjlwHPm0a9Jb9fBZW74kZVFBQ456EAs=",
            publicKeyText: ValidPublicKey);

        Assert.False(result);
    }

    [Fact]
    public void Verify_MalformedSignature_NotBase64_ReturnsFalse()
    {
        var result = MinisignVerifier.Verify(
            content: Array.Empty<byte>(),
            signatureText: "untrusted comment: test\nnot-valid-base64!!!",
            publicKeyText: ValidPublicKey);

        Assert.False(result);
    }

    [Fact]
    public void Verify_MalformedSignature_TooShort_ReturnsFalse()
    {
        var shortBlob = Convert.ToBase64String(new byte[10]);
        var result = MinisignVerifier.Verify(
            content: Array.Empty<byte>(),
            signatureText: $"untrusted comment: test\n{shortBlob}",
            publicKeyText: ValidPublicKey);

        Assert.False(result);
    }

    [Fact]
    public void Verify_MalformedSignature_WrongAlgorithm_ReturnsFalse()
    {
        // Construct a sig blob with algorithm "XX" instead of "Ed"
        var blob = Convert.FromBase64String(
            ValidSignatureForEmptyContent.Split('\n')[1]);
        blob[0] = (byte)'X';
        blob[1] = (byte)'X';
        var result = MinisignVerifier.Verify(
            content: Array.Empty<byte>(),
            signatureText: $"untrusted comment: test\n{Convert.ToBase64String(blob)}",
            publicKeyText: ValidPublicKey);

        Assert.False(result);
    }
}
