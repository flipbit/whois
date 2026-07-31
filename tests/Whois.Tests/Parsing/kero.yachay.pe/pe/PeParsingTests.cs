using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Kero.Yachay.Pe.Pe;

public class PeParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public PeParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_throttled()
    {
        var sample = SampleReader.Read("kero.yachay.pe", "pe", "throttled", "throttled.txt");
        var response = parser.Parse("kero.yachay.pe", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Throttled, response.Status);
        Assert.Equal(1, response.FieldsParsed);
        Assert.Equal(0, response.ParsingErrors);
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("kero.yachay.pe", "pe", "not-found", "u34jedzcq.pe.txt");
        var response = parser.Parse("kero.yachay.pe", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.NotFound, response.Status);

        Assert.Equal(2, response.FieldsParsed);
        Assert.Equal(0, response.ParsingErrors);

        Assert.Equal("u34jedzcq.pe", response.DomainName.ToString());

        Assert.Equal(0, response.DomainStatus.Count);
    }

    [Fact]
    public void Test_inactive()
    {
        var sample = SampleReader.Read("kero.yachay.pe", "pe", "inactive", "inactive.txt");
        var response = parser.Parse("kero.yachay.pe", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.NotAssigned, response.Status);

        Assert.Equal(7, response.FieldsParsed);
        Assert.Equal(0, response.ParsingErrors);

        Assert.Equal("zumba.pe", response.DomainName.ToString());

        Assert.Equal("NIC .PE", response.Registrar.Name);

        Assert.Equal("GRUPO ALBATROS SAC", response.Registrant.Name);

        Assert.Equal("GRUPO ALBATROS SAC", response.AdminContact.Name);
        Assert.Equal("jsotelo@galbatros.com", response.AdminContact.Email);


        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("Inactive", response.DomainStatus[0]);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("kero.yachay.pe", "pe", "found", "google.pe.txt");
        var response = parser.Parse("kero.yachay.pe", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(13, response.FieldsParsed);
        Assert.Equal(0, response.ParsingErrors);

        Assert.Equal("google.pe", response.DomainName.ToString());

        Assert.Equal("MarkMonitor Inc.", response.Registrar.Name);

        Assert.Equal("Google LLC", response.Registrant.Name);

        Assert.Equal("Google LLC", response.AdminContact.Name);
        Assert.Equal("dns-admin@google.com", response.AdminContact.Email);


        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns1.google.com", response.NameServers[0]);
        Assert.Equal("ns2.google.com", response.NameServers[1]);
        Assert.Equal("ns3.google.com", response.NameServers[2]);
        Assert.Equal("ns4.google.com", response.NameServers[3]);

        Assert.Equal(3, response.DomainStatus.Count);
        Assert.Equal("clientDeleteProhibited", response.DomainStatus[0]);
    }

    [Fact]
    public void Test_suspended()
    {
        var sample = SampleReader.Read("kero.yachay.pe", "pe", "suspended", "suspended.txt");
        var response = parser.Parse("kero.yachay.pe", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Suspended, response.Status);

        Assert.Equal(11, response.FieldsParsed);
        Assert.Equal(0, response.ParsingErrors);

        Assert.Equal("bangladesh.pe", response.DomainName.ToString());

        Assert.Equal("1API GmbH", response.Registrar.Name);

        Assert.Equal("Ahmed Nitul", response.Registrant.Name);

        Assert.Equal("Ahmed Nitul", response.AdminContact.Name);
        Assert.Equal("ahmed@nitul.net", response.AdminContact.Email);

        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns1.dnsimple.com", response.NameServers[0]);
        Assert.Equal("ns2.dnsimple.com", response.NameServers[1]);
        Assert.Equal("ns3.dnsimple.com", response.NameServers[2]);
        Assert.Equal("ns4.dnsimple.com", response.NameServers[3]);

        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("Suspended", response.DomainStatus[0]);
    }
}
