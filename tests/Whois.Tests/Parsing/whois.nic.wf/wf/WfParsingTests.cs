using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Wf.Wf;

public class WfParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public WfParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_throttled()
    {
        var sample = SampleReader.Read("whois.nic.wf", "wf", "throttled", "throttled.txt");
        var response = parser.Parse("whois.nic.wf", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Throttled, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/throttled/02", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.wf", "wf", "not-found", "not_found.txt");
        var response = parser.Parse("whois.nic.wf", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/not-found/06", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.wf", "wf", "found", "nic.wf.txt");
        var response = parser.Parse("whois.nic.wf", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/05", response.TemplateName);

        Assert.Null(response.DomainName);

        // Registrar Details
        Assert.Equal("                  Registry Operations", response.Registrar.Name);

        Assert.Null(response.Updated);
        Assert.Null(response.Registered);
        Assert.Null(response.Expiration);

        // Registrant Details
        Assert.Equal("                  NF100-FRNIC", response.Registrant.RegistryId);
        Assert.Equal("                  Nic wf", response.Registrant.Name);

        // Registrant Address
        Assert.Equal(5, response.Registrant.Address.Count);
        Assert.Equal("                  Afnic Backend Registry Operator", response.Registrant.Address[0]);
        Assert.Equal("                  immeuble le Stephenson", response.Registrant.Address[1]);
        Assert.Equal("                  1, rue Stephenson", response.Registrant.Address[2]);
        Assert.Equal("                  78180 Montigny le Bretonneux", response.Registrant.Address[3]);
        Assert.Equal("                  FR", response.Registrant.Address[4]);


        // AdminContact Details
        Assert.Equal("                  NF100-FRNIC", response.AdminContact.RegistryId);
        Assert.Equal("                  Nic wf", response.AdminContact.Name);
        Assert.Equal("                  +33.139308300", response.AdminContact.TelephoneNumber);
        Assert.Null(response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(5, response.AdminContact.Address.Count);
        Assert.Equal("                  Afnic Backend Registry Operator", response.AdminContact.Address[0]);
        Assert.Equal("                  immeuble le Stephenson", response.AdminContact.Address[1]);
        Assert.Equal("                  1, rue Stephenson", response.AdminContact.Address[2]);
        Assert.Equal("                  78180 Montigny le Bretonneux", response.AdminContact.Address[3]);
        Assert.Equal("                  FR", response.AdminContact.Address[4]);


        // TechnicalContact Details
        Assert.Equal("                  CTC9498-FRNIC", response.TechnicalContact.RegistryId);
        Assert.Equal("                  AFNIC", response.TechnicalContact.Name);
        Assert.Equal("                  +33.139308300", response.TechnicalContact.TelephoneNumber);
        Assert.Null(response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(4, response.TechnicalContact.Address.Count);
        Assert.Equal("                  ASSOCIATION FRANÇAISE POUR LE NOMMAGE INTERNET EN COOPERATION", response.TechnicalContact.Address[0]);
        Assert.Equal("                  7 Avenue du 8 mai 1945", response.TechnicalContact.Address[1]);
        Assert.Equal("                  78280 Guyancourt", response.TechnicalContact.Address[2]);
        Assert.Equal("                  FR", response.TechnicalContact.Address[3]);


        // ZoneContact Details
        Assert.Null(response.ZoneContact);

        // ZoneContact Address


        // Nameservers
        Assert.Equal(0, response.NameServers.Count);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("                  ACTIVE", response.DomainStatus[0]);

        Assert.Equal(27, response.FieldsParsed);
    }
}
