using Whois.Protocols;
using Xunit;

namespace Whois;

public class WhoisRecordMapperTests
{
    [Fact]
    public void ToDomainInfo_MapsAllFields()
    {
        var record = new WhoisRecord
        {
            DomainName = new HostName("example.com"),
            RegistryDomainId = "D123",
            Status = RegistrationStatus.Found,
            Registered = new DateTime(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc),
            Updated = new DateTime(2023, 6, 15, 0, 0, 0, DateTimeKind.Utc),
            Expiration = new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc),
            Remarks = "Test remarks",
            DnsSecStatus = "unsigned",
            Registrar = new WhoisRegistrar
            {
                Name = "Test Registrar",
                IanaId = "1234",
                WhoisServer = new HostName("whois.test.com"),
            },
            Registrant = new WhoisContact
            {
                Name = "John Doe",
                Organization = "Example Inc.",
                Email = "john@example.com",
            },
        };
        record.DomainStatus.Add("clientTransferProhibited");
        record.NameServers.Add("ns1.example.com");
        record.NameServers.Add("ns2.example.com");
        record.Registrant.Address.Add("123 Main St");
        record.Registrant.Address.Add("Springfield, IL 62701");

        var info = WhoisRecordMapper.ToDomainInfo(record);

        Assert.Equal("example.com", info.DomainName!.Value);
        Assert.Equal("D123", info.RegistryDomainId);
        Assert.Equal(RegistrationStatus.Found, info.Status);
        Assert.Single(info.DomainStatus);
        Assert.Equal("clientTransferProhibited", info.DomainStatus[0]);
        Assert.Equal(record.Registered, info.Registered);
        Assert.Equal(record.Updated, info.Updated);
        Assert.Equal(record.Expiration, info.Expiration);
        Assert.Equal("Test Registrar", info.Registrar!.Name);
        Assert.Equal("1234", info.Registrar.IanaId);
        Assert.Equal("whois.test.com", info.Registrar.WhoisServer!.Value);
        Assert.Equal("John Doe", info.Registrant!.Name);
        Assert.Equal("Example Inc.", info.Registrant.Organization);
        Assert.Equal("john@example.com", info.Registrant.Email);
        Assert.NotNull(info.Registrant.Address);
        Assert.Equal(2, info.Registrant.Address!.Lines.Count);
        Assert.Equal("123 Main St", info.Registrant.Address.Lines[0]);
        Assert.Equal(2, info.NameServers.Count);
        Assert.Equal("ns1.example.com", info.NameServers[0]);
    }

    [Fact]
    public void ToDomainInfo_NullContacts_MapsToNull()
    {
        var record = new WhoisRecord
        {
            DomainName = new HostName("example.com"),
            Status = RegistrationStatus.NotFound,
        };

        var info = WhoisRecordMapper.ToDomainInfo(record);

        Assert.Null(info.Registrant);
        Assert.Null(info.AdminContact);
        Assert.Null(info.TechnicalContact);
        Assert.Null(info.BillingContact);
        Assert.Null(info.Registrar);
    }

    [Fact]
    public void ToDomainInfo_EmptyAddress_MapsToNull()
    {
        var record = new WhoisRecord
        {
            Registrant = new WhoisContact { Name = "John" },
        };

        var info = WhoisRecordMapper.ToDomainInfo(record);

        Assert.Null(info.Registrant!.Address);
    }

    [Fact]
    public void ToDiagnostics_MapsAllFields()
    {
        var record = new WhoisRecord
        {
            FieldsParsed = 15,
            ParsingErrors = 2,
            TemplateName = "whois.test.com/com/found/01",
        };
        var duration = TimeSpan.FromMilliseconds(342);
        var chain = new List<string> { "whois.verisign.com", "whois.test.com" }.AsReadOnly();

        var diag = WhoisRecordMapper.ToDiagnostics(record, "whois.test.com", duration, chain);

        Assert.Equal(15, diag.FieldsParsed);
        Assert.Equal(2, diag.ParsingErrors);
        Assert.Equal("whois.test.com/com/found/01", diag.TemplateName);
        Assert.Equal("whois.test.com", diag.ServerUrl);
        Assert.Equal(duration, diag.Duration);
        Assert.Equal(2, diag.ReferralChain.Count);
    }
}
