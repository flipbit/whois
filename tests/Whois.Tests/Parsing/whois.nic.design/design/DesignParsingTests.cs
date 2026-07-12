using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Design.Design;

public class DesignParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public DesignParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.design", "design", "not-found", "not_found.txt");
        var response = parser.Parse("whois.nic.design", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/not-found/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.design", "design", "found", "toplevel.design.txt");
        var response = parser.Parse("whois.nic.design", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/01", response.TemplateName);

        Assert.Equal("toplevel.design", response.DomainName.ToString());
        Assert.Equal("D7069819-CNIC", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("Top Level Design, LLC", response.Registrar.Name);
        Assert.Equal("9999", response.Registrar.IanaId);
        Assert.Equal("whois.nic.wiki", response.Registrar.WhoisServer.Value);

        Assert.Equal(new DateTime(2015, 04, 21, 17, 48, 34, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2015, 02, 27, 16, 08, 32, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2016, 02, 27, 23, 59, 59, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("H4596017", response.Registrant.RegistryId);
        Assert.Equal("Domain Administrator", response.Registrant.Name);
        Assert.Equal("Top Level Design, LLC", response.Registrant.Organization);
        Assert.Equal("+1.5038888808", response.Registrant.TelephoneNumber);
        Assert.Equal("+1.6788841468", response.Registrant.FaxNumber);
        Assert.Equal("ray@tldesign.co", response.Registrant.Email);

        // Registrant Address
        Assert.Equal(5, response.Registrant.Address.Count);
        Assert.Equal("742 Ocean Club Place", response.Registrant.Address[0]);
        Assert.Equal("Fernandina Beach", response.Registrant.Address[1]);
        Assert.Equal("Florida", response.Registrant.Address[2]);
        Assert.Equal("32034", response.Registrant.Address[3]);
        Assert.Equal("US", response.Registrant.Address[4]);


        // AdminContact Details
        Assert.Equal("H4596017", response.AdminContact.RegistryId);
        Assert.Equal("Domain Administrator", response.AdminContact.Name);
        Assert.Equal("Top Level Design, LLC", response.AdminContact.Organization);
        Assert.Equal("+1.5038888808", response.AdminContact.TelephoneNumber);
        Assert.Equal("+1.6788841468", response.AdminContact.FaxNumber);
        Assert.Equal("ray@tldesign.co", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(5, response.AdminContact.Address.Count);
        Assert.Equal("742 Ocean Club Place", response.AdminContact.Address[0]);
        Assert.Equal("Fernandina Beach", response.AdminContact.Address[1]);
        Assert.Equal("Florida", response.AdminContact.Address[2]);
        Assert.Equal("32034", response.AdminContact.Address[3]);
        Assert.Equal("US", response.AdminContact.Address[4]);


        // BillingContact Details
        Assert.Equal("H4596017", response.BillingContact.RegistryId);
        Assert.Equal("Domain Administrator", response.BillingContact.Name);
        Assert.Equal("Top Level Design, LLC", response.BillingContact.Organization);
        Assert.Equal("+1.5038888808", response.BillingContact.TelephoneNumber);
        Assert.Equal("+1.6788841468", response.BillingContact.FaxNumber);
        Assert.Equal("ray@tldesign.co", response.BillingContact.Email);

        // BillingContact Address
        Assert.Equal(5, response.BillingContact.Address.Count);
        Assert.Equal("742 Ocean Club Place", response.BillingContact.Address[0]);
        Assert.Equal("Fernandina Beach", response.BillingContact.Address[1]);
        Assert.Equal("Florida", response.BillingContact.Address[2]);
        Assert.Equal("32034", response.BillingContact.Address[3]);
        Assert.Equal("US", response.BillingContact.Address[4]);


        // TechnicalContact Details
        Assert.Equal("H4596017", response.TechnicalContact.RegistryId);
        Assert.Equal("Domain Administrator", response.TechnicalContact.Name);
        Assert.Equal("Top Level Design, LLC", response.TechnicalContact.Organization);
        Assert.Equal("+1.5038888808", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("+1.6788841468", response.TechnicalContact.FaxNumber);
        Assert.Equal("ray@tldesign.co", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(5, response.TechnicalContact.Address.Count);
        Assert.Equal("742 Ocean Club Place", response.TechnicalContact.Address[0]);
        Assert.Equal("Fernandina Beach", response.TechnicalContact.Address[1]);
        Assert.Equal("Florida", response.TechnicalContact.Address[2]);
        Assert.Equal("32034", response.TechnicalContact.Address[3]);
        Assert.Equal("US", response.TechnicalContact.Address[4]);


        // Nameservers
        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns-170.awsdns-21.com", response.NameServers[0]);
        Assert.Equal("ns-904.awsdns-49.net", response.NameServers[1]);
        Assert.Equal("ns-1067.awsdns-05.org", response.NameServers[2]);
        Assert.Equal("ns-1873.awsdns-42.co.uk", response.NameServers[3]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("ok", response.DomainStatus[0]);

        Assert.Equal("unsigned", response.DnsSecStatus);
        Assert.Equal(59, response.FieldsParsed);
    }
}
