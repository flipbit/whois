namespace Whois.Security;

/// <summary>
/// Verifies minisign signatures (legacy "Ed" algorithm  -  raw Ed25519, no prehashing).
///
/// Minisign public key file format (two lines):
///   Line 1: "untrusted comment: ..." (ignored)
///   Line 2: base64-encoded blob (42 bytes): 2-byte algorithm ("Ed") + 8-byte key ID + 32-byte Ed25519 public key
///
/// Minisign signature file format (two lines):
///   Line 1: "untrusted comment: ..." (ignored)
///   Line 2: base64-encoded blob (74 bytes): 2-byte algorithm ("Ed") + 8-byte key ID + 64-byte Ed25519 signature
///
/// The Ed25519 signature covers the raw content bytes.
/// The key ID in the signature must match the key ID in the public key.
/// </summary>
// MA0182: Will be consumed by TemplatePackProvider (Task 7)  -  suppress until then.
#pragma warning disable MA0182
internal static class MinisignVerifier
#pragma warning restore MA0182
{
    private const int PublicKeyBlobLength = 42; // 2 (alg) + 8 (key id) + 32 (ed25519 key)
    private const int SignatureBlobLength = 74;  // 2 (alg) + 8 (key id) + 64 (ed25519 sig)
    private const int KeyIdOffset = 2;
    private const int KeyIdLength = 8;
    private const int Ed25519KeyOffset = 10; // 2 + 8
    private const int Ed25519SigOffset = 10; // 2 + 8

    /// <summary>
    /// Verifies a minisign signature over content.
    /// </summary>
    /// <param name="content">The bytes that were signed.</param>
    /// <param name="signatureText">The minisign signature file text (two lines).</param>
    /// <param name="publicKeyText">The minisign public key file text (two lines).</param>
    /// <returns>true if the signature is valid; false for any verification failure or format error.</returns>
    public static bool Verify(byte[] content, string signatureText, string publicKeyText)
    {
        if (!TryParseBlob(publicKeyText, PublicKeyBlobLength, out var pkBlob)) return false;
        if (!TryParseBlob(signatureText, SignatureBlobLength, out var sigBlob)) return false;

        if (!IsAlgorithmEd(pkBlob)) return false;
        if (!IsAlgorithmEd(sigBlob)) return false;

        // Key IDs must match
        if (!pkBlob.AsSpan(KeyIdOffset, KeyIdLength)
                   .SequenceEqual(sigBlob.AsSpan(KeyIdOffset, KeyIdLength)))
            return false;

        var publicKey = pkBlob.AsSpan(Ed25519KeyOffset, 32);
        var signature = sigBlob.AsSpan(Ed25519SigOffset, 64);

        return Ed25519Verifier.Verify(publicKey, content, signature);
    }

    /// <summary>
    /// Extracts and base64-decodes the payload line (line index 1) from a two-line minisign text.
    /// Returns false if the text does not have at least two lines, the payload is not valid base64,
    /// or the decoded blob is shorter than <paramref name="requiredLength"/>.
    /// </summary>
    private static bool TryParseBlob(string text, int requiredLength, out byte[] blob)
    {
        blob = Array.Empty<byte>();

        var lines = text.Split('\n');
        if (lines.Length < 2) return false;

        var payloadLine = lines[1].Trim();
        if (payloadLine.Length == 0) return false;

        try
        {
            blob = Convert.FromBase64String(payloadLine);
        }
        catch (FormatException)
        {
            return false;
        }

        return blob.Length >= requiredLength;
    }

    private static bool IsAlgorithmEd(byte[] blob)
        => blob[0] == (byte)'E' && blob[1] == (byte)'d';
}
