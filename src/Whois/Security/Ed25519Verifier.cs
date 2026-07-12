using Whois.Security.Internal;

namespace Whois.Security;

/// <summary>
/// Verifies Ed25519 signatures.
///
/// On all target frameworks this delegates to the managed implementation in
/// <see cref="ManagedEd25519"/>. A native-API fast path can be added here
/// when a stable System.Security.Cryptography.Ed25519 is available (currently
/// only in .NET 9+ preview, not yet in the stable API surface).
/// </summary>
// MA0182: This class will be consumed by MinisignVerifier (Task 2) — suppress until then.
#pragma warning disable MA0182
internal static class Ed25519Verifier
#pragma warning restore MA0182
{
    /// <summary>
    /// Verifies an Ed25519 signature.
    /// </summary>
    /// <param name="publicKey">32-byte Ed25519 public key.</param>
    /// <param name="message">The signed message.</param>
    /// <param name="signature">64-byte Ed25519 signature.</param>
    /// <returns>true if the signature is valid; false otherwise.</returns>
    public static bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
        => ManagedEd25519.Verify(signature, message, publicKey);
}
