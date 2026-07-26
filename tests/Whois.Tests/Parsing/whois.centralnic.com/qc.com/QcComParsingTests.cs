using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Centralnic.Com.QcCom;

public class QcComParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public QcComParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.centralnic.com", "qc.com", "not-found", "not_found.txt");
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
        var sample = SampleReader.Read("whois.centralnic.com", "qc.com", "found", "found.txt");
        var response = parser.Parse("whois.centralnic.com", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.centralnic.com/found/01", response.TemplateName);

        Assert.Equal("ceo.qc.com", response.DomainName.ToString());
        Assert.Equal("CNIC-DO327026", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("eNom, Inc.", response.Registrar.Name);
        Assert.Equal("http://www.enom.com/", response.Registrar.Url);
        Assert.Equal("425-274-4500", response.Registrar.AbuseTelephoneNumber);

        Assert.Equal(new DateTime(2012, 11, 23, 18, 3, 55, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2004, 10, 8, 2, 12, 49, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2014, 10, 8, 23, 59, 59, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("H1062277", response.Registrant.RegistryId);
        Assert.Equal("helene", response.Registrant.Name);

        // Registrant Address
        Assert.Equal(3, response.Registrant.Address.Count);
        Assert.Equal("309 Laurendeau, Magog Qc", response.Registrant.Address[0]);
        Assert.Equal("J1X 3W4", response.Registrant.Address[1]);
        Assert.Equal("CA", response.Registrant.Address[2]);

        Assert.Equal("+1.8198438380", response.Registrant.TelephoneNumber);
        Assert.Equal("docjgs@videotron.ca", response.Registrant.Email);


        // AdminContact Details
        Assert.Equal("H114589", response.AdminContact.RegistryId);
        Assert.Equal("helene viens", response.AdminContact.Name);

        // AdminContact Address
        Assert.Equal(3, response.AdminContact.Address.Count);
        Assert.Equal("309 Laurendeau, Magog Qc", response.AdminContact.Address[0]);
        Assert.Equal("J1X 3W4", response.AdminContact.Address[1]);
        Assert.Equal("CA", response.AdminContact.Address[2]);

        Assert.Equal("+1.8198438380", response.AdminContact.TelephoneNumber);
        Assert.Equal("docjgs@videotron.ca", response.AdminContact.Email);


        // TechnicalContact Details
        Assert.Equal("H114590", response.TechnicalContact.RegistryId);
        Assert.Equal("helene viens", response.TechnicalContact.Name);

        // TechnicalContact Address
        Assert.Equal(3, response.TechnicalContact.Address.Count);
        Assert.Equal("309 Laurendeau, Magog Qc", response.TechnicalContact.Address[0]);
        Assert.Equal("J1X 3W4", response.TechnicalContact.Address[1]);
        Assert.Equal("CA", response.TechnicalContact.Address[2]);

        Assert.Equal("+1.8198438380", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("docjgs@videotron.ca", response.TechnicalContact.Email);


        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("ns12.zoneedit.com", response.NameServers[0]);
        Assert.Equal("t1.zoneedit.com", response.NameServers[1]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("ok", response.DomainStatus[0]);

        Assert.Equal("Unsigned", response.DnsSecStatus);
        Assert.Equal(35, response.FieldsParsed);
    }
}
