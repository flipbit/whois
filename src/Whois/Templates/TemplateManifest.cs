using System.Text.Json;
using System.Text.Json.Serialization;

namespace Whois.Templates;

/// <summary>
/// Describes the contents of a template pack zip, as serialized in its <c>manifest.json</c>.
/// </summary>
public class TemplateManifest
{
    [JsonPropertyName("version")]
    public string Version { get; set; } = string.Empty;

    [JsonPropertyName("contentHash")]
    public string ContentHash { get; set; } = string.Empty;

    [JsonPropertyName("templateCount")]
    public int TemplateCount { get; set; }

    [JsonPropertyName("templates")]
    public IList<TemplateEntry> Templates { get; set; } = new List<TemplateEntry>();

    /// <summary>
    /// Deserializes and validates a manifest from JSON.
    /// </summary>
    /// <exception cref="JsonException">The JSON is malformed.</exception>
    /// <exception cref="InvalidOperationException">Required fields are missing or the version string is invalid.</exception>
    public static TemplateManifest Deserialize(string json)
    {
        var manifest = JsonSerializer.Deserialize<TemplateManifest>(json)
            ?? throw new InvalidOperationException("Manifest JSON deserialized to null.");

        if (string.IsNullOrEmpty(manifest.Version))
            throw new InvalidOperationException("Manifest is missing required field: version.");

        if (!TemplateVersion.TryParse(manifest.Version, out _))
            throw new InvalidOperationException($"Manifest version '{manifest.Version}' is not a valid version string.");

        if (string.IsNullOrEmpty(manifest.ContentHash))
            throw new InvalidOperationException("Manifest is missing required field: contentHash.");

        return manifest;
    }
}
