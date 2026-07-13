using System.Text.Json;
using Whois.Templates;
using WhoisRefresh.Domain;
using Xunit;

namespace WhoisRefresh.Tests;

public class ChangelogGeneratorTests
{
    private static TemplateManifest MakeManifest(string version, params (string path, string hash)[] templates)
    {
        var entries = templates.Select(t => new TemplateEntry { Path = t.path, Hash = t.hash }).ToList();
        return new TemplateManifest
        {
            Version = version,
            ContentHash = "ignored",
            TemplateCount = entries.Count,
            Templates = entries,
        };
    }

    [Fact]
    public void Generate_DetectsAddedTemplates()
    {
        var previous = MakeManifest("2026.07.01.1",
            ("whois.nic.uk/uk/found/01.txt", "aaa"));
        var current = MakeManifest("2026.07.13.1",
            ("whois.nic.uk/uk/found/01.txt", "aaa"),
            ("whois.nic.uk/uk/not-found/01.txt", "bbb"));

        var result = ChangelogGenerator.Generate(current, previous);

        Assert.Single(result.Added);
        Assert.Equal("whois.nic.uk/uk/not-found/01.txt", result.Added[0]);
        Assert.Empty(result.Removed);
        Assert.Empty(result.Modified);
    }

    [Fact]
    public void Generate_DetectsRemovedTemplates()
    {
        var previous = MakeManifest("2026.07.01.1",
            ("whois.nic.uk/uk/found/01.txt", "aaa"),
            ("whois.nic.uk/uk/found/02.txt", "bbb"));
        var current = MakeManifest("2026.07.13.1",
            ("whois.nic.uk/uk/found/01.txt", "aaa"));

        var result = ChangelogGenerator.Generate(current, previous);

        Assert.Single(result.Removed);
        Assert.Equal("whois.nic.uk/uk/found/02.txt", result.Removed[0]);
    }

    [Fact]
    public void Generate_DetectsModifiedTemplates()
    {
        var previous = MakeManifest("2026.07.01.1",
            ("whois.nic.uk/uk/found/01.txt", "aaa"));
        var current = MakeManifest("2026.07.13.1",
            ("whois.nic.uk/uk/found/01.txt", "bbb"));

        var result = ChangelogGenerator.Generate(current, previous);

        Assert.Single(result.Modified);
        Assert.Equal("whois.nic.uk/uk/found/01.txt", result.Modified[0]);
    }

    [Fact]
    public void Generate_IdenticalManifests_ProducesEmptyChangelog()
    {
        var manifest = MakeManifest("2026.07.13.1",
            ("whois.nic.uk/uk/found/01.txt", "aaa"));

        var result = ChangelogGenerator.Generate(manifest, manifest);

        Assert.Empty(result.Added);
        Assert.Empty(result.Removed);
        Assert.Empty(result.Modified);
        Assert.False(result.HasChanges);
    }

    [Fact]
    public void Generate_NoPreviousManifest_AllTemplatesAreAdded()
    {
        var current = MakeManifest("2026.07.13.1",
            ("whois.nic.uk/uk/found/01.txt", "aaa"),
            ("generic/tld/found/01.txt", "bbb"));

        var result = ChangelogGenerator.Generate(current, previous: null);

        Assert.Equal(2, result.Added.Count);
        Assert.Empty(result.Removed);
        Assert.Empty(result.Modified);
    }

    [Fact]
    public void ToJson_ProducesValidJson()
    {
        var current = MakeManifest("2026.07.13.1",
            ("whois.nic.uk/uk/found/01.txt", "aaa"));

        var result = ChangelogGenerator.Generate(current, previous: null);
        var json = result.ToJson();

        // Should parse without throwing
        using var doc = JsonDocument.Parse(json);
        Assert.True(doc.RootElement.TryGetProperty("added", out _));
        Assert.True(doc.RootElement.TryGetProperty("removed", out _));
        Assert.True(doc.RootElement.TryGetProperty("modified", out _));
    }

    [Fact]
    public void ToMarkdown_ContainsSectionHeadings()
    {
        var previous = MakeManifest("2026.07.01.1",
            ("whois.nic.uk/uk/found/01.txt", "aaa"),
            ("old/tld/found/01.txt", "bbb"));
        var current = MakeManifest("2026.07.13.1",
            ("whois.nic.uk/uk/found/01.txt", "ccc"),
            ("new/tld/found/01.txt", "ddd"));

        var result = ChangelogGenerator.Generate(current, previous);
        var md = result.ToMarkdown();

        Assert.Contains("## Added", md);
        Assert.Contains("## Removed", md);
        Assert.Contains("## Modified", md);
        Assert.Contains("new/tld/found/01.txt", md);
        Assert.Contains("old/tld/found/01.txt", md);
        Assert.Contains("whois.nic.uk/uk/found/01.txt", md);
    }

    [Fact]
    public void ToMarkdown_EmptyChangelog_SaysNoChanges()
    {
        var manifest = MakeManifest("2026.07.13.1",
            ("whois.nic.uk/uk/found/01.txt", "aaa"));

        var result = ChangelogGenerator.Generate(manifest, manifest);
        var md = result.ToMarkdown();

        Assert.Contains("No changes", md);
    }
}
