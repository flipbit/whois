using System.Text.Json;
using Xunit;
using Whois.Templates;

namespace Whois.Tests.Templates;

public class TemplateManifestTests
{
    private const string ValidJson = """
        {
          "version": "2026.07.12.1",
          "contentHash": "abc123def456",
          "templateCount": 500,
          "templates": [
            {"path": "whois.nic.uk/uk/found/01.txt", "hash": "sha256hexvalue"}
          ]
        }
        """;

    [Fact]
    public void Deserialize_WellFormedJson_ReturnsManifest()
    {
        var manifest = TemplateManifest.Deserialize(ValidJson);

        Assert.NotNull(manifest);
        Assert.Equal("2026.07.12.1", manifest.Version);
        Assert.Equal("abc123def456", manifest.ContentHash);
        Assert.Equal(500, manifest.TemplateCount);
        Assert.Single(manifest.Templates);
        Assert.Equal("whois.nic.uk/uk/found/01.txt", manifest.Templates[0].Path);
        Assert.Equal("sha256hexvalue", manifest.Templates[0].Hash);
    }

    [Fact]
    public void Deserialize_EmptyTemplatesList_ReturnsManifestWithEmptyList()
    {
        var json = """
            {
              "version": "2026.07.12.1",
              "contentHash": "abc123",
              "templateCount": 0,
              "templates": []
            }
            """;

        var manifest = TemplateManifest.Deserialize(json);

        Assert.NotNull(manifest);
        Assert.Empty(manifest.Templates);
    }

    [Fact]
    public void Deserialize_MissingVersionField_ThrowsInvalidOperationException()
    {
        var json = """
            {
              "contentHash": "abc123",
              "templateCount": 0,
              "templates": []
            }
            """;

        Assert.Throws<InvalidOperationException>(() => TemplateManifest.Deserialize(json));
    }

    [Fact]
    public void Deserialize_InvalidVersionString_ThrowsInvalidOperationException()
    {
        var json = """
            {
              "version": "not-a-version",
              "contentHash": "abc123",
              "templateCount": 0,
              "templates": []
            }
            """;

        Assert.Throws<InvalidOperationException>(() => TemplateManifest.Deserialize(json));
    }

    [Fact]
    public void Deserialize_MissingContentHash_ThrowsInvalidOperationException()
    {
        var json = """
            {
              "version": "2026.07.12.1",
              "templateCount": 0,
              "templates": []
            }
            """;

        Assert.Throws<InvalidOperationException>(() => TemplateManifest.Deserialize(json));
    }

    [Fact]
    public void Deserialize_MalformedJson_ThrowsJsonException()
    {
        Assert.Throws<JsonException>(() => TemplateManifest.Deserialize("not json at all {{{"));
    }
}
