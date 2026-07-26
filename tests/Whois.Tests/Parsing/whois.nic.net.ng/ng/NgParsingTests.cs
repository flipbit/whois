using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Net.Ng.Ng;

public class NgParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public NgParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.net.ng", "ng", "not-found", "u34jedzcq.ng.txt");
        var response = parser.Parse("whois.nic.net.ng", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/not-found/05", response.TemplateName);

        Assert.Equal("u34jedzcq.ng", response.DomainName.ToString());

        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.net.ng", "ng", "found", "nic.net.ng.txt");
        var response = parser.Parse("whois.nic.net.ng", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/01", response.TemplateName);

        Assert.Equal("nic.net.ng", response.DomainName.ToString());
        Assert.Equal("6808-NIRA", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("nira", response.Registrar.Name);
        Assert.Equal("nira", response.Registrar.WhoisServer.Value);

        Assert.Equal(new DateTime(2012, 08, 24, 13, 46, 14, 774, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2009, 05, 13, 14, 27, 27, 009, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2020, 07, 30, 23, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("80023-NIRA", response.Registrant.RegistryId);
        Assert.Equal("Domain Admin", response.Registrant.Name);
        Assert.Equal("Nigeria Internet Registration Association", response.Registrant.Organization);
        Assert.Equal("+2348086031704", response.Registrant.TelephoneNumber);
        Assert.Equal("admin@nira.org.ng", response.Registrant.Email);

        // Registrant Address
        Assert.Equal(5, response.Registrant.Address.Count);
        Assert.Equal("9 Kofo Abayomi Street", response.Registrant.Address[0]);
        Assert.Equal("Victoria Island", response.Registrant.Address[1]);
        Assert.Equal("Lagos", response.Registrant.Address[2]);
        Assert.Equal("101241", response.Registrant.Address[3]);
        Assert.Equal("NG", response.Registrant.Address[4]);


        // AdminContact Details
        Assert.Equal("23141-NIRA", response.AdminContact.RegistryId);
        Assert.Equal("Nigeria Internet Registration Association (NIRA)", response.AdminContact.Organization);
        Assert.Equal("ugo@nira.org.ng", response.AdminContact.Email);


        // Nameservers
        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("rns1.nic.net.ng", response.NameServers[0]);
        Assert.Equal("rns2.nic.net.ng", response.NameServers[1]);
        Assert.Equal("rns3.nic.net.ng", response.NameServers[2]);
        Assert.Equal("rns4.nic.net.ng", response.NameServers[3]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("ok", response.DomainStatus[0]);

        Assert.Equal("unsigned", response.DnsSecStatus);
        Assert.Equal(27, response.FieldsParsed);
    }

    [Fact]
    public void Test_not_found_status_available()
    {
        var sample = SampleReader.Read("whois.nic.net.ng", "ng", "not-found", "not_found_status_available.txt");
        var response = parser.Parse("whois.nic.net.ng", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/not-found/05", response.TemplateName);

        Assert.Equal("u34jedzcq.ng", response.DomainName.ToString());

        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_status_registered()
    {
        var sample = SampleReader.Read("whois.nic.net.ng", "ng", "found", "found_status_registered.txt");
        var response = parser.Parse("whois.nic.net.ng", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/01", response.TemplateName);

        Assert.Equal("nic.net.ng", response.DomainName.ToString());
        Assert.Equal("6808-NIRA", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("nira", response.Registrar.Name);
        Assert.Equal("whois.nic.ng", response.Registrar.WhoisServer.Value);

        Assert.Equal(new DateTime(2012, 08, 24, 13, 46, 14, 774, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2009, 05, 13, 14, 27, 27, 009, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2020, 07, 30, 23, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("80023-NIRA", response.Registrant.RegistryId);
        Assert.Equal("Domain Admin", response.Registrant.Name);
        Assert.Equal("Nigeria Internet Registration Association", response.Registrant.Organization);
        Assert.Equal("+2348086031704", response.Registrant.TelephoneNumber);
        Assert.Equal("admin@nira.org.ng", response.Registrant.Email);

        // Registrant Address
        Assert.Equal(5, response.Registrant.Address.Count);
        Assert.Equal("9 Kofo Abayomi Street", response.Registrant.Address[0]);
        Assert.Equal("Victoria Island", response.Registrant.Address[1]);
        Assert.Equal("Lagos", response.Registrant.Address[2]);
        Assert.Equal("101241", response.Registrant.Address[3]);
        Assert.Equal("NG", response.Registrant.Address[4]);


        // AdminContact Details
        Assert.Equal("23141-NIRA", response.AdminContact.RegistryId);
        Assert.Equal("Nigeria Internet Registration Association (NIRA)", response.AdminContact.Organization);
        Assert.Equal("ugo@nira.org.ng", response.AdminContact.Email);


        // Nameservers
        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("rns1.nic.net.ng", response.NameServers[0]);
        Assert.Equal("rns2.nic.net.ng", response.NameServers[1]);
        Assert.Equal("rns3.nic.net.ng", response.NameServers[2]);
        Assert.Equal("rns4.nic.net.ng", response.NameServers[3]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("ok", response.DomainStatus[0]);

        Assert.Equal("unsigned", response.DnsSecStatus);
        Assert.Equal(27, response.FieldsParsed);
    }
}
