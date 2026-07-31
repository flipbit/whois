using Xunit;
using Whois.Refresh.Domain;

namespace Whois.Refresh.Tests;

public class DomainRegistryTests
{
    [Fact]
    public async Task LoadAsync_ValidJsonc_ParsesServers()
    {
        var jsonc = """
            {
              "servers": {
                "whois.nic.uk": {
                  // UK registry
                  "tld": "uk",
                  "domains": {
                    "found": ["google.co.uk", "bbc.co.uk"],
                    "not-found": ["u34jedzcq.co.uk"]
                  }
                }
              }
            }
            """;

        var registry = await DomainRegistry.LoadAsync(jsonc);

        Assert.Single(registry.Servers);
        var server = registry.Servers["whois.nic.uk"];
        Assert.Equal("uk", server.Tld);
        Assert.False(server.IsStatic);
        Assert.Null(server.RateGroup);
        Assert.Equal(2, server.Domains["found"].Count);
        Assert.Contains(server.Domains["found"], d => d == "google.co.uk");
        Assert.Single(server.Domains["not-found"]);
    }

    [Fact]
    public async Task LoadAsync_StaticServer_ParsesFlag()
    {
        var jsonc = """
            {
              "servers": {
                "whois.denic.de": {
                  "tld": "de",
                  "static": true,
                  "domains": {
                    "found": ["google.de"]
                  }
                }
              }
            }
            """;

        var registry = await DomainRegistry.LoadAsync(jsonc);

        Assert.True(registry.Servers["whois.denic.de"].IsStatic);
    }

    [Fact]
    public async Task LoadAsync_RateGroup_ParsesGroup()
    {
        var jsonc = """
            {
              "servers": {
                "whois.verisign-grs.com": {
                  "tld": "com",
                  "rateGroup": "verisign",
                  "domains": { "found": ["google.com"] }
                },
                "ccwhois.verisign-grs.com": {
                  "tld": "cc",
                  "rateGroup": "verisign",
                  "domains": { "found": ["example.cc"] }
                }
              }
            }
            """;

        var registry = await DomainRegistry.LoadAsync(jsonc);

        Assert.Equal("verisign", registry.Servers["whois.verisign-grs.com"].RateGroup);
        Assert.Equal("verisign", registry.Servers["ccwhois.verisign-grs.com"].RateGroup);
    }

    [Fact]
    public async Task LoadAsync_DomainWithPathSeparator_ThrowsValidation()
    {
        var jsonc = """
            {
              "servers": {
                "whois.nic.uk": {
                  "tld": "uk",
                  "domains": { "found": ["../etc/passwd"] }
                }
              }
            }
            """;

        var ex = await Assert.ThrowsAsync<DomainRegistryValidationException>(
            () => DomainRegistry.LoadAsync(jsonc));
        Assert.Contains("../etc/passwd", ex.Message);
    }

    [Fact]
    public async Task LoadAsync_DomainWithBackslash_ThrowsValidation()
    {
        var jsonc = """
            {
              "servers": {
                "whois.nic.uk": {
                  "tld": "uk",
                  "domains": { "found": ["foo\\bar.uk"] }
                }
              }
            }
            """;

        var ex = await Assert.ThrowsAsync<DomainRegistryValidationException>(
            () => DomainRegistry.LoadAsync(jsonc));
        Assert.Contains("foo\\bar.uk", ex.Message);
    }

    [Fact]
    public async Task LoadAsync_TrailingCommas_Accepted()
    {
        var jsonc = """
            {
              "servers": {
                "whois.nic.uk": {
                  "tld": "uk",
                  "domains": {
                    "found": ["google.co.uk",],
                  },
                },
              },
            }
            """;

        var registry = await DomainRegistry.LoadAsync(jsonc);

        Assert.Single(registry.Servers);
    }

    [Fact]
    public async Task LoadAsync_DuplicateDomainAcrossStatuses_ThrowsValidation()
    {
        var jsonc = """
            {
              "servers": {
                "whois.nic.uk": {
                  "tld": "uk",
                  "domains": {
                    "found": ["google.co.uk"],
                    "not-found": ["google.co.uk"]
                  }
                }
              }
            }
            """;

        var ex = await Assert.ThrowsAsync<DomainRegistryValidationException>(
            () => DomainRegistry.LoadAsync(jsonc));
        Assert.Contains("google.co.uk", ex.Message);
        Assert.Contains("found", ex.Message);
        Assert.Contains("not-found", ex.Message);
    }

    [Fact]
    public async Task LoadAsync_UnknownStatusKey_ThrowsValidation()
    {
        var jsonc = """
            {
              "servers": {
                "whois.nic.uk": {
                  "tld": "uk",
                  "domains": {
                    "active": ["google.co.uk"]
                  }
                }
              }
            }
            """;

        var ex = await Assert.ThrowsAsync<DomainRegistryValidationException>(
            () => DomainRegistry.LoadAsync(jsonc));
        Assert.Contains("active", ex.Message);
    }

    [Theory]
    [InlineData("../evil", "../evil")]
    [InlineData("foo/bar", "foo/bar")]
    [InlineData("foo\\\\bar", "foo\\bar")]  // JSON \\\\  -> JSON-string \\  -> C# string \
    public async Task LoadAsync_ServerNameWithPathTraversal_ThrowsValidation(string jsonServerName, string expectedInMessage)
    {
        var jsonc = $$"""
            {
              "servers": {
                "{{jsonServerName}}": {
                  "tld": "uk",
                  "domains": { "found": ["google.co.uk"] }
                }
              }
            }
            """;

        var ex = await Assert.ThrowsAsync<DomainRegistryValidationException>(
            () => DomainRegistry.LoadAsync(jsonc));
        Assert.Contains("server name", ex.Message);
        Assert.Contains(expectedInMessage, ex.Message);
    }

    [Theory]
    [InlineData("../etc", "../etc")]
    [InlineData("foo/bar", "foo/bar")]
    [InlineData("foo\\\\bar", "foo\\bar")]  // JSON \\\\  -> JSON-string \\  -> C# string \
    public async Task LoadAsync_TldWithPathTraversal_ThrowsValidation(string jsonTld, string expectedInMessage)
    {
        var jsonc = $$"""
            {
              "servers": {
                "whois.nic.uk": {
                  "tld": "{{jsonTld}}",
                  "domains": { "found": ["google.co.uk"] }
                }
              }
            }
            """;

        var ex = await Assert.ThrowsAsync<DomainRegistryValidationException>(
            () => DomainRegistry.LoadAsync(jsonc));
        Assert.Contains("tld", ex.Message);
        Assert.Contains(expectedInMessage, ex.Message);
    }

    [Fact]
    public async Task LoadAsync_AllValidStatusKeys_Accepted()
    {
        // Verify each valid status key is accepted without exception
        foreach (var status in DomainRegistry.ValidStatusKeys)
        {
            var jsonc = $$"""
                {
                  "servers": {
                    "whois.nic.uk": {
                      "tld": "uk",
                      "domains": { "{{status}}": ["google.co.uk"] }
                    }
                  }
                }
                """;

            var registry = await DomainRegistry.LoadAsync(jsonc);
            Assert.True(registry.Servers["whois.nic.uk"].Domains.ContainsKey(status));
        }
    }

    [Fact]
    public async Task GetRateGroups_GroupsServersCorrectly()
    {
        var jsonc = """
            {
              "servers": {
                "whois.verisign-grs.com": {
                  "tld": "com",
                  "rateGroup": "verisign",
                  "domains": { "found": ["google.com"] }
                },
                "ccwhois.verisign-grs.com": {
                  "tld": "cc",
                  "rateGroup": "verisign",
                  "domains": { "found": ["example.cc"] }
                },
                "whois.nic.uk": {
                  "tld": "uk",
                  "domains": { "found": ["google.co.uk"] }
                }
              }
            }
            """;

        var registry = await DomainRegistry.LoadAsync(jsonc);
        var groups = registry.GetRateGroups();

        // "verisign" group has 2 servers, "whois.nic.uk" is its own group
        Assert.Equal(2, groups.Count);
        var verisignGroup = groups.First(g => string.Equals(g.Key, "verisign", StringComparison.Ordinal));
        Assert.Equal(2, verisignGroup.Count());
        var ukGroup = groups.First(g => string.Equals(g.Key, "whois.nic.uk", StringComparison.Ordinal));
        Assert.Single(ukGroup);
    }
}
