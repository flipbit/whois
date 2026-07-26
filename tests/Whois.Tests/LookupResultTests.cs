using Xunit;

namespace Whois;

public class LookupResultTests
{
    [Fact]
    public void Constructor_SetsAllProperties()
    {
        var domainInfo = new DomainInfo
        {
            DomainName = new HostName("example.com"),
            Status = RegistrationStatus.Found,
        };
        var diagnostics = new LookupDiagnostics
        {
            FieldsParsed = 10,
            Duration = TimeSpan.FromMilliseconds(250),
            ServerUrl = "whois.example.com",
        };

        var result = new LookupResult<DomainInfo>(domainInfo, LookupProtocol.Whois, "raw content", diagnostics);

        Assert.Same(domainInfo, result.Response);
        Assert.Equal(LookupProtocol.Whois, result.Protocol);
        Assert.Equal("raw content", result.RawContent);
        Assert.Same(diagnostics, result.Diagnostics);
    }

    [Fact]
    public void DomainInfo_DefaultCollections_AreEmpty()
    {
        var info = new DomainInfo();

        Assert.Empty(info.DomainStatus);
        Assert.Empty(info.NameServers);
    }

    [Fact]
    public void Address_Lines_DefaultsToEmpty()
    {
        var address = new Address();

        Assert.Empty(address.Lines);
        Assert.Null(address.Street);
        Assert.Null(address.City);
        Assert.Null(address.Country);
    }
}
