using System.Security.Cryptography;

namespace Whois.Security.Internal;

/// <summary>
/// Pure managed Ed25519 signature verification.
///
/// Derived from the Chaos.NaCl library (MIT) and RFC 8032.
/// Only verification is implemented — no key generation or signing.
/// </summary>
internal static class ManagedEd25519
{
    /// <summary>
    /// Verifies an Ed25519 signature.
    /// </summary>
    /// <param name="signature">64-byte Ed25519 signature.</param>
    /// <param name="message">The signed message.</param>
    /// <param name="publicKey">32-byte Ed25519 public key.</param>
    /// <returns>true if the signature is valid; false otherwise.</returns>
    internal static bool Verify(ReadOnlySpan<byte> signature, ReadOnlySpan<byte> message, ReadOnlySpan<byte> publicKey)
    {
        if (signature.Length != 64) return false;
        if (publicKey.Length != 32) return false;

        // Decode the public key as a curve point A
        if (!GroupElement.TryFromBytes(out var a, publicKey)) return false;

        // Split signature into R (bytes 0..31) and S (bytes 32..63)
        var rBytes = signature.Slice(0, 32);
        var sBytes = signature.Slice(32, 32);

        // S must be a canonical scalar (S < L)
        if (!ScalarOps.IsCanonical(sBytes)) return false;

        // Decode R as a curve point
        if (!GroupElement.TryFromBytes(out var r, rBytes)) return false;

        // k = SHA-512(R || A || message) reduced mod L
        Span<byte> kHash = stackalloc byte[64];
        HashK(kHash, rBytes, publicKey, message);
        ScalarOps.Reduce(kHash);

        // Copy S and the reduced k into 32-byte scalars
        Span<byte> sScalar = stackalloc byte[32];
        sBytes.CopyTo(sScalar);
        Span<byte> kScalar = stackalloc byte[32];
        kHash.Slice(0, 32).CopyTo(kScalar);

        // Negate A so we can compute [S]B + [k](-A) = [S]B - [k]A
        GroupElement.NegateSelf(ref a);

        // Compute check = [S]B + [k](-A)
        var check = GroupElement.DoubleScalarMulVartime(sScalar, kScalar, ref a);

        // If check == R (mod cofactor), the signature is valid
        return GroupElement.EqualsCofactor(in check, in r);
    }

    private static void HashK(
        Span<byte> output,
        ReadOnlySpan<byte> rBytes,
        ReadOnlySpan<byte> aBytes,
        ReadOnlySpan<byte> message)
    {
        // k = SHA-512(R || A || M)
        var buf = new byte[64 + message.Length];
        rBytes.CopyTo(buf);
        aBytes.CopyTo(buf.AsSpan(32));
        message.CopyTo(buf.AsSpan(64));
        using var sha = SHA512.Create();
        sha.ComputeHash(buf).AsSpan().CopyTo(output);
    }
}
