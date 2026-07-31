using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Donuts.Co.Bike;

public class BikeParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public BikeParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.donuts.co", "bike", "not-found", "not_found.txt");
        var response = parser.Parse("whois.donuts.co", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/not-found/03", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.donuts.co", "bike", "found", "whereismy.bike.txt");
        var response = parser.Parse("whois.donuts.co", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/01", response.TemplateName);

        Assert.Equal("whereismy.bike", response.DomainName.ToString());
        Assert.Equal("e25432d5c94440c4a8ca0e5ecbc13904-DONUTS", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("GoDaddy.com, LLC", response.Registrar.Name);
        Assert.Equal("146", response.Registrar.IanaId);
        Assert.Equal("http://www.godaddy.com/domains/search.aspx?ci=8990", response.Registrar.Url);
        Assert.Equal("who.godaddy.com", response.Registrar.WhoisServer.Value);
        Assert.Equal("abuse@godaddy.com", response.Registrar.AbuseEmail);
        Assert.Equal("+1.4806242505", response.Registrar.AbuseTelephoneNumber);

        Assert.Equal(new DateTime(2017, 04, 12, 16, 49, 41, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2016, 02, 26, 16, 49, 10, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2018, 02, 26, 16, 49, 10, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("2a94fd50b2ca42c685828dfa8c07e23d-DONUTS", response.Registrant.RegistryId);
        Assert.Equal("Marko Matenda", response.Registrant.Name);
        Assert.Equal("+385.916283632", response.Registrant.TelephoneNumber);
        Assert.Equal("marko.matenda@gmail.com", response.Registrant.Email);

        // Registrant Address
        Assert.Equal(5, response.Registrant.Address.Count);
        Assert.Equal("Ante Starcevica 9.", response.Registrant.Address[0]);
        Assert.Equal("Bjelovar", response.Registrant.Address[1]);
        Assert.Equal("Croatia", response.Registrant.Address[2]);
        Assert.Equal("43000", response.Registrant.Address[3]);
        Assert.Equal("HR", response.Registrant.Address[4]);


        // AdminContact Details
        Assert.Equal("a627ad7dc57343858c4397b9e3f9a530-DONUTS", response.AdminContact.RegistryId);
        Assert.Equal("Marko Matenda", response.AdminContact.Name);
        Assert.Equal("+385.916283632", response.AdminContact.TelephoneNumber);
        Assert.Equal("marko.matenda@gmail.com", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(5, response.AdminContact.Address.Count);
        Assert.Equal("Ante Starcevica 9.", response.AdminContact.Address[0]);
        Assert.Equal("Bjelovar", response.AdminContact.Address[1]);
        Assert.Equal("Croatia", response.AdminContact.Address[2]);
        Assert.Equal("43000", response.AdminContact.Address[3]);
        Assert.Equal("HR", response.AdminContact.Address[4]);


        // TechnicalContact Details
        Assert.Equal("08094e7dd78143d6b83338c5c59a8160-DONUTS", response.TechnicalContact.RegistryId);
        Assert.Equal("Marko Matenda", response.TechnicalContact.Name);
        Assert.Equal("+385.916283632", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("marko.matenda@gmail.com", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(5, response.TechnicalContact.Address.Count);
        Assert.Equal("Ante Starcevica 9.", response.TechnicalContact.Address[0]);
        Assert.Equal("Bjelovar", response.TechnicalContact.Address[1]);
        Assert.Equal("Croatia", response.TechnicalContact.Address[2]);
        Assert.Equal("43000", response.TechnicalContact.Address[3]);
        Assert.Equal("HR", response.TechnicalContact.Address[4]);


        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("ns68.domaincontrol.com", response.NameServers[0]);
        Assert.Equal("ns67.domaincontrol.com", response.NameServers[1]);

        // Domain Status
        Assert.Equal(4, response.DomainStatus.Count);
        Assert.Equal("clientDeleteProhibited", response.DomainStatus[0]);
        Assert.Equal("clientRenewProhibited", response.DomainStatus[1]);
        Assert.Equal("clientTransferProhibited", response.DomainStatus[2]);
        Assert.Equal("clientUpdateProhibited", response.DomainStatus[3]);

        Assert.Equal("unsigned", response.DnsSecStatus);
        Assert.Equal(49, response.FieldsParsed);
    }
}
