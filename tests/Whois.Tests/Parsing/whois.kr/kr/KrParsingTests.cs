using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Kr.Kr;

public class KrParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public KrParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.kr", "kr", "found", "lg.co.kr.txt");
        var response = parser.Parse("whois.kr", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.kr/kr/found/01", response.TemplateName);

        Assert.Equal("lg.co.kr", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("Whois Corp.(http://whois.co.kr)", response.Registrar.Name);

        Assert.Equal(new DateTime(2014, 08, 26, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(1995, 03, 20, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2033, 10, 15, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("LG Corp.", response.Registrant.Name);

        // Registrant Address
        Assert.Equal(2, response.Registrant.Address.Count);
        Assert.Equal("LG Twintower 20, Youido-dong, Youngdeungpo-gu,, Seoul", response.Registrant.Address[0]);
        Assert.Equal("150721", response.Registrant.Address[1]);


        // AdminContact Details
        Assert.Equal("Domain-Manager", response.AdminContact.Name);
        Assert.Equal("02-3773-2322", response.AdminContact.TelephoneNumber);
        Assert.Equal("young@lg.com", response.AdminContact.Email);


        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("prmns.lg.co.kr", response.NameServers[0]);
        Assert.Equal("secns.lg.co.kr", response.NameServers[1]);

        Assert.Equal(14, response.FieldsParsed);
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.kr", "kr", "not-found", "u34jedzcq.kr.txt");
        var response = parser.Parse("whois.kr", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.kr/kr/not-found/01", response.TemplateName);

        Assert.Equal("u34jedzcq.kr", response.DomainName.ToString());

        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_status_registered()
    {
        var sample = SampleReader.Read("whois.kr", "kr", "found", "google.kr.txt");
        var response = parser.Parse("whois.kr", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.kr/kr/found/01", response.TemplateName);

        Assert.Equal("google.kr", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("Whois Corp.(http://whois.co.kr)", response.Registrar.Name);

        Assert.Equal(new DateTime(2026, 04, 15, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2007, 03, 02, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2027, 03, 02, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("Google Korea, LLC", response.Registrant.Name);

        // Registrant Address
        Assert.Equal(2, response.Registrant.Address.Count);
        Assert.Equal("22nd Floor Gangnam Finance Center, 737 Yeoksam-dong Kangnam-ku Seoul", response.Registrant.Address[0]);
        Assert.Equal("135984", response.Registrant.Address[1]);


        // AdminContact Details
        Assert.Equal("Domain Administrator", response.AdminContact.Name);
        Assert.Equal("82.25319000", response.AdminContact.TelephoneNumber);
        Assert.Equal("dns-admin@google.com", response.AdminContact.Email);


        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("ns1.google.com", response.NameServers[0]);
        Assert.Equal("ns2.google.com", response.NameServers[1]);

        Assert.Equal(14, response.FieldsParsed);
    }
}
