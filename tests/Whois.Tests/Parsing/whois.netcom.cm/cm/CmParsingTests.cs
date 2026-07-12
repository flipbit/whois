using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Netcom.Cm.Cm;

public class CmParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public CmParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.netcom.cm", "cm", "not-found", "u34jedzcq.cm.txt");
        var response = parser.Parse("whois.netcom.cm", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/not-found/04", response.TemplateName);

        Assert.Equal("u34jedzcq.cm", response.DomainName.ToString());

        // Domain Status
        Assert.Equal(0, response.DomainStatus.Count);

        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.netcom.cm", "cm", "found", "google.cm.txt");
        var response = parser.Parse("whois.netcom.cm", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/01", response.TemplateName);

        Assert.Equal("google.cm", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("Netcom.cm Sarl", response.Registrar.Name);

        Assert.Equal(new DateTime(2026, 06, 19, 10, 08, 27, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2009, 10, 07, 09, 02, 24, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2026, 10, 07, 09, 02, 24, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Null(response.Registrant);

        // Registrant Address


        // AdminContact Details
        Assert.Null(response.AdminContact);

        // AdminContact Address


        // BillingContact Details
        Assert.Null(response.BillingContact);

        // BillingContact Address


        // TechnicalContact Details
        Assert.Null(response.TechnicalContact);

        // TechnicalContact Address


        // Nameservers
        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns1.google.com", response.NameServers[0]);
        Assert.Equal("ns2.google.com", response.NameServers[1]);
        Assert.Equal("ns3.google.com", response.NameServers[2]);
        Assert.Equal("ns4.google.com", response.NameServers[3]);

        // Domain Status
        Assert.Equal(4, response.DomainStatus.Count);
        Assert.Equal("active", response.DomainStatus[0]);

        Assert.Equal(17, response.FieldsParsed);
    }

    [Fact]
    public void Test_suspended()
    {
        var sample = SampleReader.Read("whois.netcom.cm", "cm", "suspended", "suspended.txt");
        var response = parser.Parse("whois.netcom.cm", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Suspended, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.netcom.cm/cm/found/01", response.TemplateName);

        Assert.Equal("imdb.cm", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("Registrar ANTIC", response.Registrar.Name);

        Assert.Equal(new DateTime(2014, 01, 24, 08, 17, 00, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2009, 08, 28, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2011, 08, 28, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("cm.legacy@netcom.cm", response.Registrant.Email);


        // AdminContact Details
        Assert.Equal("Camtel | ANTIC l Legacy-Escrow", response.AdminContact.Name);
        Assert.Equal("cm.legacy@netcom.cm", response.AdminContact.Email);


        // BillingContact Details
        Assert.Equal("Camtel | ANTIC l Legacy-Escrow", response.BillingContact.Name);
        Assert.Equal("cm.legacy@netcom.cm", response.BillingContact.Email);


        // TechnicalContact Details
        Assert.Equal("Camtel | ANTIC l Legacy-Escrow", response.TechnicalContact.Name);
        Assert.Equal("cm.legacy@netcom.cm", response.TechnicalContact.Email);


        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("ns1.refinedhosting.net", response.NameServers[0]);
        Assert.Equal("ns2.refinedhosting.net", response.NameServers[1]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("Suspended", response.DomainStatus[0]);

        Assert.Equal(16, response.FieldsParsed);
    }
}
