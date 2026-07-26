using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Afilias.Grs.Info.Gi;

public class GiParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public GiParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.afilias-grs.info", "gi", "not-found", "not_found.txt");
        var response = parser.Parse("whois.afilias-grs.info", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.afilias-grs.info", "gi", "found", "found.txt");
        var response = parser.Parse("whois.afilias-grs.info", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/01", response.TemplateName);

        Assert.Equal("sapphire.gi", response.DomainName.ToString());
        Assert.Equal("D68296-LRCC", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("GibNet Registrar (R43-LRCC)", response.Registrar.Name);

        Assert.Equal(new DateTime(2008, 12, 20, 19, 25, 54, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2004, 12, 20, 13, 34, 34, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2009, 12, 20, 13, 34, 34, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("FR-1103549674779", response.Registrant.RegistryId);
        Assert.Equal("Jimmy Imossi", response.Registrant.Name);
        Assert.Equal("Broadband Gibraltar Limited", response.Registrant.Organization);
        Assert.Equal("+350.47200", response.Registrant.TelephoneNumber);
        Assert.Equal("+350.47272", response.Registrant.FaxNumber);
        Assert.Equal("jimossi@sapphire.gi", response.Registrant.Email);

        // Registrant Address
        Assert.Equal(5, response.Registrant.Address.Count);
        Assert.Equal("Suite 951", response.Registrant.Address[0]);
        Assert.Equal("Europort", response.Registrant.Address[1]);
        Assert.Equal("Gibraltar", response.Registrant.Address[2]);
        Assert.Equal("NA", response.Registrant.Address[3]);
        Assert.Equal("GI", response.Registrant.Address[4]);


        // AdminContact Details
        Assert.Equal("FR-1103549674779", response.AdminContact.RegistryId);
        Assert.Equal("Jimmy Imossi", response.AdminContact.Name);
        Assert.Equal("Broadband Gibraltar Limited", response.AdminContact.Organization);
        Assert.Equal("+350.47200", response.AdminContact.TelephoneNumber);
        Assert.Equal("+350.47272", response.AdminContact.FaxNumber);
        Assert.Equal("jimossi@sapphire.gi", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(5, response.AdminContact.Address.Count);
        Assert.Equal("Suite 951", response.AdminContact.Address[0]);
        Assert.Equal("Europort", response.AdminContact.Address[1]);
        Assert.Equal("Gibraltar", response.AdminContact.Address[2]);
        Assert.Equal("NA", response.AdminContact.Address[3]);
        Assert.Equal("GI", response.AdminContact.Address[4]);


        // BillingContact Details
        Assert.Equal("FR-1103549674779", response.BillingContact.RegistryId);
        Assert.Equal("Jimmy Imossi", response.BillingContact.Name);
        Assert.Equal("Broadband Gibraltar Limited", response.BillingContact.Organization);
        Assert.Equal("+350.47200", response.BillingContact.TelephoneNumber);
        Assert.Equal("+350.47272", response.BillingContact.FaxNumber);
        Assert.Equal("jimossi@sapphire.gi", response.BillingContact.Email);

        // BillingContact Address
        Assert.Equal(5, response.BillingContact.Address.Count);
        Assert.Equal("Suite 951", response.BillingContact.Address[0]);
        Assert.Equal("Europort", response.BillingContact.Address[1]);
        Assert.Equal("Gibraltar", response.BillingContact.Address[2]);
        Assert.Equal("NA", response.BillingContact.Address[3]);
        Assert.Equal("GI", response.BillingContact.Address[4]);


        // TechnicalContact Details
        Assert.Equal("FR-10a223e2e4cf0", response.TechnicalContact.RegistryId);
        Assert.Equal("Tech Dept", response.TechnicalContact.Name);
        Assert.Equal("Broadband Gibraltar Ltd", response.TechnicalContact.Organization);
        Assert.Equal("+350.47200", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("+350.47271", response.TechnicalContact.FaxNumber);
        Assert.Equal("tech@sapphire.gi", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(5, response.TechnicalContact.Address.Count);
        Assert.Equal("Suite 9.5.1", response.TechnicalContact.Address[0]);
        Assert.Equal("Europort", response.TechnicalContact.Address[1]);
        Assert.Equal("N/A", response.TechnicalContact.Address[2]);
        Assert.Equal("N/A", response.TechnicalContact.Address[3]);
        Assert.Equal("GI", response.TechnicalContact.Address[4]);


        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("ns1-a.sapphire.gi", response.NameServers[0]);
        Assert.Equal("ns2-a.sapphire.gi", response.NameServers[1]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("OK", response.DomainStatus[0]);

        Assert.Equal(54, response.FieldsParsed);
    }
}
