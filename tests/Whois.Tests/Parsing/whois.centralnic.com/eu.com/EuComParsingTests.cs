using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Centralnic.Com.EuCom;

public class EuComParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public EuComParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.centralnic.com", "eu.com", "not-found", "not_found.txt");
        var response = parser.Parse("whois.centralnic.com", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.centralnic.com/not-found/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.centralnic.com", "eu.com", "found", "found.txt");
        var response = parser.Parse("whois.centralnic.com", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.centralnic.com/found/01", response.TemplateName);

        Assert.Equal("walkabout.eu.com", response.DomainName.ToString());
        Assert.Equal("CNIC-DO85080", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("iTransact Ltd", response.Registrar.Name);
        Assert.Equal("01223 700322", response.Registrar.AbuseTelephoneNumber);
        Assert.Equal("www.itransact.ltd.uk", response.Registrar.Url);

        Assert.Equal(new DateTime(2013, 8, 15, 11, 25, 43, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2001, 8, 14, 10, 14, 41, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2015, 8, 14, 23, 59, 59, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("H1045382", response.Registrant.RegistryId);
        Assert.Equal("Regent Inns Plc", response.Registrant.Name);

        // Registrant Address
        Assert.Equal(4, response.Registrant.Address.Count);
        Assert.Equal("77 Muswell Hill", response.Registrant.Address[0]);
        Assert.Equal("London", response.Registrant.Address[1]);
        Assert.Equal("N10 3PJ", response.Registrant.Address[2]);
        Assert.Equal("GB", response.Registrant.Address[3]);

        Assert.Equal("+44.2083753155", response.Registrant.TelephoneNumber);
        Assert.Equal("john.boyle@regent-inns.plc.uk", response.Registrant.Email);


        // AdminContact Details
        Assert.Equal("H64717", response.AdminContact.RegistryId);
        Assert.Equal("John Boyle", response.AdminContact.Name);
        Assert.Equal("Regent Inns Plc", response.AdminContact.Organization);

        // AdminContact Address
        Assert.Equal(4, response.AdminContact.Address.Count);
        Assert.Equal("77 Muswell Hill", response.AdminContact.Address[0]);
        Assert.Equal("London", response.AdminContact.Address[1]);
        Assert.Equal("N10 3PJ", response.AdminContact.Address[2]);
        Assert.Equal("GB", response.AdminContact.Address[3]);

        Assert.Equal("+44.2083753155", response.AdminContact.TelephoneNumber);
        Assert.Equal("john.boyle@regent-inns.plc.uk", response.AdminContact.Email);


        // TechnicalContact Details
        Assert.Equal("H126914", response.TechnicalContact.RegistryId);
        Assert.Equal("Constantine Pagonis", response.TechnicalContact.Name);
        Assert.Equal("iTransact Ltd", response.TechnicalContact.Organization);

        // TechnicalContact Address
        Assert.Equal(4, response.TechnicalContact.Address.Count);
        Assert.Equal("PO Box 430", response.TechnicalContact.Address[0]);
        Assert.Equal("Cambridge", response.TechnicalContact.Address[1]);
        Assert.Equal("CB1 2WE", response.TechnicalContact.Address[2]);
        Assert.Equal("GB", response.TechnicalContact.Address[3]);

        Assert.Equal("+44.1223700322", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("constantine@itransact.ltd.uk", response.TechnicalContact.Email);


        // Nameservers
        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns-1146.awsdns-15.org", response.NameServers[0]);
        Assert.Equal("ns-1741.awsdns-25.co.uk", response.NameServers[1]);
        Assert.Equal("ns-374.awsdns-46.com", response.NameServers[2]);
        Assert.Equal("ns-914.awsdns-50.net", response.NameServers[3]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("ok", response.DomainStatus[0]);

        Assert.Equal("Unsigned", response.DnsSecStatus);
        Assert.Equal(41, response.FieldsParsed);
    }
}
