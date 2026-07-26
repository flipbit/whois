using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Ja.Net.AcUk;

public class AcUkParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public AcUkParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.ja.net", "ac.uk", "not-found", "not_found.txt");
        var response = parser.Parse("whois.ja.net", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.ja.net/not-found/01", response.TemplateName);

        Assert.Equal("u34jedzcq.ac.uk", response.DomainName.ToString());

        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.ja.net", "ac.uk", "found", "found.txt");
        var response = parser.Parse("whois.ja.net", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.ja.net/found/01", response.TemplateName);

        Assert.Equal("lboro.ac.uk", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("Jisc Collections and Janet Limited", response.Registrar.Name);

        Assert.Equal(new DateTime(2013, 03, 20, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2003, 11, 07, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2014, 06, 16, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("Loughborough University", response.Registrant.Name);


        // AdminContact Details
        Assert.Equal("M S Cook", response.AdminContact.Name);
        Assert.Equal("+44 1509 223498", response.AdminContact.TelephoneNumber);
        Assert.Equal("+44 1509 223989", response.AdminContact.FaxNumber);
        Assert.Equal("m.s.cook@lboro.ac.uk", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(3, response.AdminContact.Address.Count);
        Assert.Equal("Computing Services, Loughborough University, Loughborough, Leicestershire", response.AdminContact.Address[0]);
        Assert.Equal("LE11 3TU", response.AdminContact.Address[1]);
        Assert.Equal("United Kingdom", response.AdminContact.Address[2]);


        // Nameservers
        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("agate.lut.ac.uk", response.NameServers[0]);
        Assert.Equal("bgate.lut.ac.uk", response.NameServers[1]);
        Assert.Equal("cgate.lut.ac.uk", response.NameServers[2]);
        Assert.Equal("ns3.ja.net", response.NameServers[3]);

        Assert.Equal(18, response.FieldsParsed);
    }
}
