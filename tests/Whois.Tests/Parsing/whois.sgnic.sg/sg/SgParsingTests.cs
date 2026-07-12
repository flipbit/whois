using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Sgnic.Sg.Sg;

public class SgParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public SgParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.sgnic.sg", "sg", "found", "google.sg.txt");
        var response = parser.Parse("whois.sgnic.sg", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.sgnic.sg/sg/found/01", response.TemplateName);

        Assert.Equal("google.sg", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("MARKMONITOR INC", response.Registrar.Name);

        Assert.Equal(new DateTime(2005, 01, 03, 12, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2011, 01, 03, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("GOOGLE INC.", response.Registrant.Name);
        Assert.Equal("+1.6503300100", response.Registrant.TelephoneNumber);
        Assert.Equal("+1.6506181434", response.Registrant.FaxNumber);
        Assert.Equal("dns-admin@google.com", response.Registrant.Email);

        // Registrant Address
        Assert.Equal(4, response.Registrant.Address.Count);
        Assert.Equal("1600 AMPHITHEATRE PARKWAY", response.Registrant.Address[0]);
        Assert.Equal("CA", response.Registrant.Address[1]);
        Assert.Equal("US", response.Registrant.Address[2]);
        Assert.Equal("94043", response.Registrant.Address[3]);


        // Domain Status
        Assert.Equal(4, response.DomainStatus.Count);
        Assert.Equal("OK", response.DomainStatus[0]);
        Assert.Equal("CLIENT UPDATE PROHIBITED", response.DomainStatus[1]);
        Assert.Equal("CLIENT TRANSFER PROHIBITED", response.DomainStatus[2]);
        Assert.Equal("CLIENT DELETE PROHIBITED", response.DomainStatus[3]);

        Assert.Equal(18, response.FieldsParsed);
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_found_nameservers_schema_1_with_ip()
    {
        var sample = SampleReader.Read("whois.sgnic.sg", "sg", "found", "canon.com.sg.txt");
        var response = parser.Parse("whois.sgnic.sg", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        AssertWriter.Write(response);
        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.sgnic.sg/sg/found/01", response.TemplateName);

        Assert.Equal("canon.com.sg", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("SINGNET PTE LTD", response.Registrar.Name);

        Assert.Equal(new DateTime(1996, 01, 09, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2012, 01, 09, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("CANON SINGAPORE PTE. LTD.", response.Registrant.Name);
        Assert.Equal("67845922", response.Registrant.TelephoneNumber);
        Assert.Equal("64753273", response.Registrant.FaxNumber);
        Assert.Equal("hostmaster@singnet.com.sg", response.Registrant.Email);

        // Registrant Address
        Assert.Equal(3, response.Registrant.Address.Count);
        Assert.Equal("1 HarbourFront Avenue", response.Registrant.Address[0]);
        Assert.Equal("SG", response.Registrant.Address[1]);
        Assert.Equal("098632", response.Registrant.Address[2]);


        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("OK", response.DomainStatus[0]);

        Assert.Equal(14, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_nameservers_schema_2()
    {
        var sample = SampleReader.Read("whois.sgnic.sg", "sg", "found", "found_nameservers_schema_2.txt");
        var response = parser.Parse("whois.sgnic.sg", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.sgnic.sg/sg/found/01", response.TemplateName);

        Assert.Equal("google.sg", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("MARKMONITOR INC", response.Registrar.Name);

        Assert.Equal(new DateTime(2005, 01, 03, 12, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2012, 01, 03, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("GOOGLE INC.", response.Registrant.Name);
        Assert.Equal("+1.6502530000", response.Registrant.TelephoneNumber);
        Assert.Equal("+1.6502530001", response.Registrant.FaxNumber);
        Assert.Equal("dns-admin@google.com", response.Registrant.Email);

        // Registrant Address
        Assert.Equal(4, response.Registrant.Address.Count);
        Assert.Equal("1600 AMPHITHEATRE PARKWAY", response.Registrant.Address[0]);
        Assert.Equal("CA", response.Registrant.Address[1]);
        Assert.Equal("US", response.Registrant.Address[2]);
        Assert.Equal("94043", response.Registrant.Address[3]);


        // Domain Status
        Assert.Equal(4, response.DomainStatus.Count);
        Assert.Equal("OK", response.DomainStatus[0]);
        Assert.Equal("CLIENT UPDATE PROHIBITED", response.DomainStatus[1]);
        Assert.Equal("CLIENT TRANSFER PROHIBITED", response.DomainStatus[2]);
        Assert.Equal("CLIENT DELETE PROHIBITED", response.DomainStatus[3]);

        Assert.Equal(18, response.FieldsParsed);
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.sgnic.sg", "sg", "not-found", "not_found.txt");
        var response = parser.Parse("whois.sgnic.sg", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/not-found/02", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_status_registered()
    {
        var sample = SampleReader.Read("whois.sgnic.sg", "sg", "found", "found_status_registered.txt");
        var response = parser.Parse("whois.sgnic.sg", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.sgnic.sg/sg/found/02", response.TemplateName);

        Assert.Equal("google.sg", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("MARKMONITOR INC", response.Registrar.Name);

        Assert.Equal(new DateTime(2005, 01, 03, 12, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2020, 01, 03, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("GOOGLE LLC", response.Registrant.Name);


        // AdminContact Details
        Assert.Equal("MARKMONITOR INC.", response.AdminContact.Name);


        // TechnicalContact Details
        Assert.Equal("GOOGLE LLC", response.TechnicalContact.Name);


        // Nameservers
        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns1.google.com", response.NameServers[0]);
        Assert.Equal("ns2.google.com", response.NameServers[1]);
        Assert.Equal("ns3.google.com", response.NameServers[2]);
        Assert.Equal("ns4.google.com", response.NameServers[3]);

        // Domain Status
        Assert.Equal(5, response.DomainStatus.Count);
        Assert.Equal("OK", response.DomainStatus[0]);
        Assert.Equal("CLIENT UPDATE PROHIBITED", response.DomainStatus[1]);
        Assert.Equal("CLIENT TRANSFER PROHIBITED", response.DomainStatus[2]);
        Assert.Equal("CLIENT DELETE PROHIBITED", response.DomainStatus[3]);
        Assert.Equal("VerifiedID@SG-Not Required", response.DomainStatus[4]);

        Assert.Equal(17, response.FieldsParsed);
    }
}
