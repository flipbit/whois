using System.Text.Json.Serialization;

namespace Whois.Templates;

/// <summary>
/// A single template entry within a <see cref="TemplateManifest"/>.
/// </summary>
public class TemplateEntry
{
    [JsonPropertyName("path")]
    public string Path { get; set; } = string.Empty;

    [JsonPropertyName("hash")]
    public string Hash { get; set; } = string.Empty;
}
