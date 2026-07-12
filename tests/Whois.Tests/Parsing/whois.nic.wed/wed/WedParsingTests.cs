using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Wed.Wed;

public class WedParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public WedParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.wed", "wed", "not-found", "u34jedzcq.wed.txt");
        var response = parser.Parse("whois.nic.wed", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotAvailable, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/02", response.TemplateName);

        Assert.Equal("u34jedzcq.wed", response.DomainName.ToString());

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("Prohibited String - Object Cannot Be Registered", response.DomainStatus[0]);

        Assert.Equal(3, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.wed", "wed", "found", "nic.wed.txt");
        var response = parser.Parse("whois.nic.wed", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/01", response.TemplateName);

        Assert.Equal("nic.wed", response.DomainName.ToString());
        Assert.Equal("963171-CoCCA", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("WED gTLD Admin Reserved", response.Registrar.Name);
        Assert.Equal("whois.nic.wed", response.Registrar.WhoisServer.Value);

        Assert.Equal(new DateTime(2014, 01, 24, 05, 00, 34, 240, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2013, 12, 29, 22, 02, 21, 427, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2014, 12, 29, 22, 02, 21, 621, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("963170-CoCCA", response.Registrant.RegistryId);
        Assert.Equal("Garth Miller", response.Registrant.Name);
        Assert.Equal("CoCCA Registry Services (NZ) Ltd.", response.Registrant.Organization);
        Assert.Equal("+64.94466370", response.Registrant.TelephoneNumber);
        Assert.Equal("garth.miller@cocca.org.nz", response.Registrant.Email);

        // Registrant Address
        Assert.Equal(5, response.Registrant.Address.Count);
        Assert.Equal("11a Wynyard Street", response.Registrant.Address[0]);
        Assert.Equal("Auckland", response.Registrant.Address[1]);
        Assert.Equal("AKL", response.Registrant.Address[2]);
        Assert.Equal("0624", response.Registrant.Address[3]);
        Assert.Equal("NZ", response.Registrant.Address[4]);


        // AdminContact Details
        Assert.Equal("963170-CoCCA", response.AdminContact.RegistryId);
        Assert.Equal("Garth Miller", response.AdminContact.Name);
        Assert.Equal("CoCCA Registry Services (NZ) Ltd.", response.AdminContact.Organization);
        Assert.Equal("+64.94466370", response.AdminContact.TelephoneNumber);
        Assert.Equal("garth.miller@cocca.org.nz", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(5, response.AdminContact.Address.Count);
        Assert.Equal("11a Wynyard Street", response.AdminContact.Address[0]);
        Assert.Equal("Auckland", response.AdminContact.Address[1]);
        Assert.Equal("AKL", response.AdminContact.Address[2]);
        Assert.Equal("0624", response.AdminContact.Address[3]);
        Assert.Equal("NZ", response.AdminContact.Address[4]);


        // Nameservers
        Assert.Equal(3, response.NameServers.Count);
        Assert.Equal("ns1.enetworksgy.com", response.NameServers[0]);
        Assert.Equal("ns2.enetworksgy.com", response.NameServers[1]);
        Assert.Equal("ns3.enetworksgy.com", response.NameServers[2]);

        // Domain Status
        Assert.Equal(9, response.DomainStatus.Count);
        Assert.Equal("ok", response.DomainStatus[0]);
        Assert.Equal("serverTransferProhibited", response.DomainStatus[1]);
        Assert.Equal("clientUpdateProhibited", response.DomainStatus[2]);
        Assert.Equal("clientTransferProhibited", response.DomainStatus[3]);
        Assert.Equal("serverRenewProhibited", response.DomainStatus[4]);
        Assert.Equal("clientRenewProhibited", response.DomainStatus[5]);
        Assert.Equal("clientDeleteProhibited", response.DomainStatus[6]);
        Assert.Equal("serverUpdateProhibited", response.DomainStatus[7]);
        Assert.Equal("serverDeleteProhibited", response.DomainStatus[8]);

        Assert.Equal("signed", response.DnsSecStatus);
        Assert.Equal(41, response.FieldsParsed);
    }
}
