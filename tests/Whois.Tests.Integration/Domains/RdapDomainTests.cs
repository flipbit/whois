using Whois.Refresh.Domain;
using Xunit;

namespace Whois.Domains;

public class RdapDomainTests
{
    private static readonly Lazy<DomainRegistryData> Registry = new(
        () => DomainRegistry.LoadFromFileAsync(GetRegistryPath()).GetAwaiter().GetResult());

    private static string GetRegistryPath()
    {
        // Walk up from bin output to repo root
        var dir = AppContext.BaseDirectory;
        while (dir != null && !File.Exists(Path.Combine(dir, "Whois.sln")))
            dir = Path.GetDirectoryName(dir);

        return Path.Combine(dir ?? throw new InvalidOperationException("Could not find repo root"),
            "tools", "Whois.Refresh", "domains-rdap.jsonc");
    }

    public static IEnumerable<object[]> GetTestDomains()
    {
        var registry = Registry.Value;
        var testCases = new List<object[]>();

        foreach (var (serverName, server) in registry.Servers)
        {
            if (server.IsStatic) continue;

            foreach (var (status, domains) in server.Domains)
            {
                foreach (var domain in domains)
                {
                    testCases.Add([serverName, domain, status]);
                }
            }
        }

        return testCases;
    }

    [Theory]
    [MemberData(nameof(GetTestDomains))]
    [Trait("Category", "Integration")]
    public async Task RdapLookup_ReturnsExpectedStatus(
        string serverName, string domain, string expectedStatus)
    {
        var lookup = new WhoisLookup();
        var request = new WhoisRequest(domain)
        {
            PreferredProtocol = ProtocolPreference.Rdap,
        };

        var result = await lookup.Lookup(request);

        Assert.Equal(LookupProtocol.Rdap, result.Protocol);

        var expected = MapStatus(expectedStatus);
        Assert.Equal(expected, result.Response.Status);

        if (expected == RegistrationStatus.Found)
        {
            Assert.NotNull(result.Response.DomainName);
        }

        _ = serverName; // used as test case label via MemberData
    }

    private static RegistrationStatus MapStatus(string status) => status switch
    {
        "found" => RegistrationStatus.Found,
        "not-found" => RegistrationStatus.NotFound,
        "throttled" => RegistrationStatus.Throttled,
        _ => RegistrationStatus.Unknown,
    };
}
