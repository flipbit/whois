using System.Text;
using Whois.Security;
using Xunit;

namespace WhoisRefresh.Tests;

/// <summary>
/// Round-trip tests that verify <see cref="MinisignVerifier"/> works against real
/// signatures produced by the minisign CLI. The key pairs and signatures were generated
/// once during development and are embedded as constants — no minisign CLI required at
/// test time.
/// </summary>
public class MinisignRoundTripTests
{
    // Production signing key — matches EmbeddedPublicKey in TemplatePackProvider.
    // Generated with: minisign -G -W -p whois-prod.pub -s whois-prod.key -c "whois template signing key"
    private const string ProductionPublicKey =
        "untrusted comment: minisign public key BB627A8035F5648F\n" +
        "RWSPZPU1gHpiu6ORNoQUGiAeuxhdDaq9rJ8HVRaqBy/PtM0//4zByp2I";

    private const string TestPayload = "test payload for signature verification";

    // Signature produced by: minisign -S -l -m test-payload.bin -s whois-prod.key -t "test signature"
    // The -l flag uses legacy raw Ed25519 (algorithm "Ed"), required by MinisignVerifier.
    private const string ValidSignature =
        "untrusted comment: signature from minisign secret key\n" +
        "RWSPZPU1gHpiuypHe8BITMc22gOoX9WSLCbUu06BtHZpw/SYNksOnOCHufcc4BLPL+SRVpA0D+24KRF2J+3u0j2uSqOIxzblKgU=\n" +
        "trusted comment: test signature\n" +
        "3X5rPOd8zicHRFDLV8vTofY6Mg70ENxwBgpf4m7hWeLI8rge7Ix+faCLH+HjjdINb4AXv54RetmbwWap7IkzAA==";

    // A second key pair used only for the negative tests.
    // Generated with: minisign -G -W -p test-b.pub -s test-b.key -c "test key B"
    private const string DifferentPublicKey =
        "untrusted comment: minisign public key 97636088B9510793\n" +
        "RWSTB1G5iGBjl/SRTWMd/77cPrCKk+QtCkh+TlXxcJPU0i7CBjL9eoYt";

    // Signature produced by: minisign -S -l -m test-payload.bin -s test-b.key -t "test signature B"
    // The -l flag uses legacy raw Ed25519 (algorithm "Ed"), required by MinisignVerifier.
    private const string DifferentKeySignature =
        "untrusted comment: signature from minisign secret key\n" +
        "RWSTB1G5iGBjlwZBZ+Qt8OQpzPxJrZELvbTJ2/AwQ2Qezd9Cg4119EtADu4vXvlH6wZN0SJXSgjovevH62MNZa3oXNfRn4t/qgc=\n" +
        "trusted comment: test signature B\n" +
        "zoE7+f8wvNK6fXyOAL6Hq/SCTzlDteDezC1WHrlSZOa3uMN+g2jtK1XKEITMqyp7W4uo4SS65qh9GfxgVHcRCw==";

    [Fact]
    public void ProductionKey_VerifiesSignatureFromMinisignCli()
    {
        var content = Encoding.UTF8.GetBytes(TestPayload);

        var result = MinisignVerifier.Verify(content, ValidSignature, ProductionPublicKey);

        Assert.True(result, "Signature produced by minisign CLI should verify against production public key");
    }

    [Fact]
    public void ProductionKey_RejectsTamperedContent()
    {
        var tampered = Encoding.UTF8.GetBytes(TestPayload + " TAMPERED");

        var result = MinisignVerifier.Verify(tampered, ValidSignature, ProductionPublicKey);

        Assert.False(result, "Tampered content should fail verification");
    }

    [Fact]
    public void ProductionKey_RejectsSignatureFromDifferentKey()
    {
        var content = Encoding.UTF8.GetBytes(TestPayload);

        // Signature was generated with a different key — key IDs won't match
        var result = MinisignVerifier.Verify(content, DifferentKeySignature, ProductionPublicKey);

        Assert.False(result, "Signature from a different key must not verify against the production public key");
    }

    [Fact]
    public void DifferentKey_VerifiesItsOwnSignature()
    {
        var content = Encoding.UTF8.GetBytes(TestPayload);

        // Sanity check: the different key's signature verifies against its own public key
        var result = MinisignVerifier.Verify(content, DifferentKeySignature, DifferentPublicKey);

        Assert.True(result, "Signature should verify against the key that produced it");
    }
}
