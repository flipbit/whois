using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Centralnic.Com.KrCom;

public class KrComParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public KrComParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.centralnic.com", "kr.com", "not-found", "not_found.txt");
        var response = parser.Parse("whois.centralnic.com", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.centralnic.com/not-found/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.centralnic.com", "kr.com", "found", "found.txt");
        var response = parser.Parse("whois.centralnic.com", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.centralnic.com/found/01", response.TemplateName);

        Assert.Equal("academyart.kr.com", response.DomainName.ToString());
        Assert.Equal("CNIC-DO569707", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("Network Solutions LLC", response.Registrar.Name);
        Assert.Equal("http://www.networksolutions.com/", response.Registrar.Url);
        Assert.Equal("+1.9046806600", response.Registrar.AbuseTelephoneNumber);

        Assert.Equal(new DateTime(2012, 1, 16, 16, 25, 41, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2008, 6, 11, 21, 25, 43, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2014, 6, 11, 23, 59, 59, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("41619876", response.Registrant.RegistryId);
        Assert.Equal("Academy of  Art College", response.Registrant.Name);
        Assert.Equal("Academy of  Art College", response.Registrant.Organization);

        // Registrant Address
        Assert.Equal(5, response.Registrant.Address.Count);
        Assert.Equal("79 NEW MONTGOMERY ST", response.Registrant.Address[0]);
        Assert.Equal("SAN FRANCISCO", response.Registrant.Address[1]);
        Assert.Equal("CA", response.Registrant.Address[2]);
        Assert.Equal("94105", response.Registrant.Address[3]);
        Assert.Equal("US", response.Registrant.Address[4]);

        Assert.Equal("+1.415618350", response.Registrant.TelephoneNumber);
        Assert.Equal("clefferts@academyart.edu", response.Registrant.Email);


        // AdminContact Details
        Assert.Equal("41619876", response.AdminContact.RegistryId);
        Assert.Equal("Academy of  Art College", response.AdminContact.Name);
        Assert.Equal("Academy of  Art College", response.AdminContact.Organization);

        // AdminContact Address
        Assert.Equal(5, response.AdminContact.Address.Count);
        Assert.Equal("79 NEW MONTGOMERY ST", response.AdminContact.Address[0]);
        Assert.Equal("SAN FRANCISCO", response.AdminContact.Address[1]);
        Assert.Equal("CA", response.AdminContact.Address[2]);
        Assert.Equal("94105", response.AdminContact.Address[3]);
        Assert.Equal("US", response.AdminContact.Address[4]);

        Assert.Equal("+1.415618350", response.AdminContact.TelephoneNumber);
        Assert.Equal("clefferts@academyart.edu", response.AdminContact.Email);


        // BillingContact Details
        Assert.Equal("41619877", response.BillingContact.RegistryId);
        Assert.Equal("Academy of Art University", response.BillingContact.Name);
        Assert.Equal("Academy of Art", response.BillingContact.Organization);

        // BillingContact Address
        Assert.Equal(5, response.BillingContact.Address.Count);
        Assert.Equal("79 New Montgomery, 3rd Floor", response.BillingContact.Address[0]);
        Assert.Equal("SAN FRANCISCO", response.BillingContact.Address[1]);
        Assert.Equal("CA", response.BillingContact.Address[2]);
        Assert.Equal("94105", response.BillingContact.Address[3]);
        Assert.Equal("US", response.BillingContact.Address[4]);

        Assert.Equal("+1.4156188582", response.BillingContact.TelephoneNumber);
        Assert.Equal("+1.4156186279", response.BillingContact.FaxNumber);
        Assert.Equal("Padsuar@academyart.edu", response.BillingContact.Email);


        // TechnicalContact Details
        Assert.Equal("41619876", response.TechnicalContact.RegistryId);
        Assert.Equal("Academy of  Art College", response.TechnicalContact.Name);
        Assert.Equal("Academy of  Art College", response.TechnicalContact.Organization);

        // TechnicalContact Address
        Assert.Equal(5, response.TechnicalContact.Address.Count);
        Assert.Equal("79 NEW MONTGOMERY ST", response.TechnicalContact.Address[0]);
        Assert.Equal("SAN FRANCISCO", response.TechnicalContact.Address[1]);
        Assert.Equal("CA", response.TechnicalContact.Address[2]);
        Assert.Equal("94105", response.TechnicalContact.Address[3]);
        Assert.Equal("US", response.TechnicalContact.Address[4]);

        Assert.Equal("+1.415618350", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("clefferts@academyart.edu", response.TechnicalContact.Email);


        // Nameservers
        Assert.Equal(5, response.NameServers.Count);
        Assert.Equal("ns1.academyart.edu", response.NameServers[0]);
        Assert.Equal("dbru.br.ns.els-gms.att.net", response.NameServers[1]);
        Assert.Equal("dmtu.mt.ns.els-gms.att.net", response.NameServers[2]);
        Assert.Equal("cbru.br.ns.els-gms.att.net", response.NameServers[3]);
        Assert.Equal("cmtu.mt.ns.els-gms.att.net", response.NameServers[4]);

        // Domain Status
        Assert.Equal(2, response.DomainStatus.Count);
        Assert.Equal("clientTransferProhibited", response.DomainStatus[0]);
        Assert.Equal("serverTransferProhibited", response.DomainStatus[1]);

        Assert.Equal("Unsigned", response.DnsSecStatus);
        Assert.Equal(59, response.FieldsParsed);
    }
}
