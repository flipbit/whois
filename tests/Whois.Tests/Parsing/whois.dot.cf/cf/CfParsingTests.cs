using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Dot.Cf.Cf;

public class CfParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public CfParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.dot.cf", "cf", "found", "dot.cf.txt");
        var response = parser.Parse("whois.dot.cf", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.dot.cf/cf/found/01", response.TemplateName);

        Assert.Equal("dot.cf", response.DomainName.ToString());

        Assert.Equal(new DateTime(2013, 03, 28, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

        // Registrant Details
        Assert.Equal("Mr Joost  Zuurbier", response.Registrant.Name);
        Assert.Equal("Centrafrique TLD B.V.", response.Registrant.Organization);
        Assert.Equal("20-5315726", response.Registrant.TelephoneNumber);
        Assert.Equal("20-5315721", response.Registrant.FaxNumber);
        Assert.Equal("info@centrafriquetld.com", response.Registrant.Email);

        // Registrant Address
        Assert.Equal(5, response.Registrant.Address.Count);
        Assert.Equal("Keizersgracht 213", response.Registrant.Address[0]);
        Assert.Equal("1016DT", response.Registrant.Address[1]);
        Assert.Equal("Amsterdam", response.Registrant.Address[2]);
        Assert.Equal("Noord-Holland", response.Registrant.Address[3]);
        Assert.Equal("Netherlands", response.Registrant.Address[4]);


        // AdminContact Details
        Assert.Equal("Mr Joost  Zuurbier", response.AdminContact.Name);
        Assert.Equal("Centrafrique TLD B.V.", response.AdminContact.Organization);
        Assert.Equal("20-5315726", response.AdminContact.TelephoneNumber);
        Assert.Equal("20-5315721", response.AdminContact.FaxNumber);
        Assert.Equal("info@centrafriquetld.com", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(5, response.AdminContact.Address.Count);
        Assert.Equal("Keizersgracht 213", response.AdminContact.Address[0]);
        Assert.Equal("1016DT", response.AdminContact.Address[1]);
        Assert.Equal("Amsterdam", response.AdminContact.Address[2]);
        Assert.Equal("Noord-Holland", response.AdminContact.Address[3]);
        Assert.Equal("Netherlands", response.AdminContact.Address[4]);


        // BillingContact Details
        Assert.Equal("Mr Joost  Zuurbier", response.BillingContact.Name);
        Assert.Equal("Centrafrique TLD B.V.", response.BillingContact.Organization);
        Assert.Equal("20-5315726", response.BillingContact.TelephoneNumber);
        Assert.Equal("20-5315721", response.BillingContact.FaxNumber);
        Assert.Equal("info@centrafriquetld.com", response.BillingContact.Email);

        // BillingContact Address
        Assert.Equal(5, response.BillingContact.Address.Count);
        Assert.Equal("Keizersgracht 213", response.BillingContact.Address[0]);
        Assert.Equal("1016DT", response.BillingContact.Address[1]);
        Assert.Equal("Amsterdam", response.BillingContact.Address[2]);
        Assert.Equal("Noord-Holland", response.BillingContact.Address[3]);
        Assert.Equal("Netherlands", response.BillingContact.Address[4]);


        // TechnicalContact Details
        Assert.Equal("Mr Joost  Zuurbier", response.TechnicalContact.Name);
        Assert.Equal("Centrafrique TLD B.V.", response.TechnicalContact.Organization);
        Assert.Equal("20-5315726", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("20-5315721", response.TechnicalContact.FaxNumber);
        Assert.Equal("info@centrafriquetld.com", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(5, response.TechnicalContact.Address.Count);
        Assert.Equal("Keizersgracht 213", response.TechnicalContact.Address[0]);
        Assert.Equal("1016DT", response.TechnicalContact.Address[1]);
        Assert.Equal("Amsterdam", response.TechnicalContact.Address[2]);
        Assert.Equal("Noord-Holland", response.TechnicalContact.Address[3]);
        Assert.Equal("Netherlands", response.TechnicalContact.Address[4]);


        // Nameservers
        Assert.Equal(5, response.NameServers.Count);
        Assert.Equal("dns5.nettica.com", response.NameServers[0]);
        Assert.Equal("dns1.nettica.com", response.NameServers[1]);
        Assert.Equal("dns2.nettica.com", response.NameServers[2]);
        Assert.Equal("dns3.nettica.com", response.NameServers[3]);
        Assert.Equal("dns4.nettica.com", response.NameServers[4]);

        Assert.Equal(48, response.FieldsParsed);
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.dot.cf", "cf", "not-found", "not_found.txt");
        var response = parser.Parse("whois.dot.cf", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.dot.cf/cf/not-found/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_status_registered()
    {
        var sample = SampleReader.Read("whois.dot.cf", "cf", "found", "found_status_registered.txt");
        var response = parser.Parse("whois.dot.cf", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.dot.cf/cf/found/01", response.TemplateName);

        Assert.Equal("dot.cf", response.DomainName.ToString());

        Assert.Equal(new DateTime(2013, 03, 28, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

        // Registrant Details
        Assert.Equal("Mr Joost  Zuurbier", response.Registrant.Name);
        Assert.Equal("Centrafrique TLD B.V.", response.Registrant.Organization);
        Assert.Equal("20-5315726", response.Registrant.TelephoneNumber);
        Assert.Equal("20-5315721", response.Registrant.FaxNumber);
        Assert.Equal("info@centrafriquetld.com", response.Registrant.Email);

        // Registrant Address
        Assert.Equal(5, response.Registrant.Address.Count);
        Assert.Equal("Keizersgracht 213", response.Registrant.Address[0]);
        Assert.Equal("1016DT", response.Registrant.Address[1]);
        Assert.Equal("Amsterdam", response.Registrant.Address[2]);
        Assert.Equal("Noord-Holland", response.Registrant.Address[3]);
        Assert.Equal("Netherlands", response.Registrant.Address[4]);


        // AdminContact Details
        Assert.Equal("Mr Joost  Zuurbier", response.AdminContact.Name);
        Assert.Equal("Centrafrique TLD B.V.", response.AdminContact.Organization);
        Assert.Equal("20-5315726", response.AdminContact.TelephoneNumber);
        Assert.Equal("20-5315721", response.AdminContact.FaxNumber);
        Assert.Equal("info@centrafriquetld.com", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(5, response.AdminContact.Address.Count);
        Assert.Equal("Keizersgracht 213", response.AdminContact.Address[0]);
        Assert.Equal("1016DT", response.AdminContact.Address[1]);
        Assert.Equal("Amsterdam", response.AdminContact.Address[2]);
        Assert.Equal("Noord-Holland", response.AdminContact.Address[3]);
        Assert.Equal("Netherlands", response.AdminContact.Address[4]);


        // BillingContact Details
        Assert.Equal("Mr Joost  Zuurbier", response.BillingContact.Name);
        Assert.Equal("Centrafrique TLD B.V.", response.BillingContact.Organization);
        Assert.Equal("20-5315726", response.BillingContact.TelephoneNumber);
        Assert.Equal("20-5315721", response.BillingContact.FaxNumber);
        Assert.Equal("info@centrafriquetld.com", response.BillingContact.Email);

        // BillingContact Address
        Assert.Equal(5, response.BillingContact.Address.Count);
        Assert.Equal("Keizersgracht 213", response.BillingContact.Address[0]);
        Assert.Equal("1016DT", response.BillingContact.Address[1]);
        Assert.Equal("Amsterdam", response.BillingContact.Address[2]);
        Assert.Equal("Noord-Holland", response.BillingContact.Address[3]);
        Assert.Equal("Netherlands", response.BillingContact.Address[4]);


        // TechnicalContact Details
        Assert.Equal("Mr Joost  Zuurbier", response.TechnicalContact.Name);
        Assert.Equal("Centrafrique TLD B.V.", response.TechnicalContact.Organization);
        Assert.Equal("20-5315726", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("20-5315721", response.TechnicalContact.FaxNumber);
        Assert.Equal("info@centrafriquetld.com", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(5, response.TechnicalContact.Address.Count);
        Assert.Equal("Keizersgracht 213", response.TechnicalContact.Address[0]);
        Assert.Equal("1016DT", response.TechnicalContact.Address[1]);
        Assert.Equal("Amsterdam", response.TechnicalContact.Address[2]);
        Assert.Equal("Noord-Holland", response.TechnicalContact.Address[3]);
        Assert.Equal("Netherlands", response.TechnicalContact.Address[4]);


        // Nameservers
        Assert.Equal(5, response.NameServers.Count);
        Assert.Equal("dns5.nettica.com", response.NameServers[0]);
        Assert.Equal("dns1.nettica.com", response.NameServers[1]);
        Assert.Equal("dns2.nettica.com", response.NameServers[2]);
        Assert.Equal("dns3.nettica.com", response.NameServers[3]);
        Assert.Equal("dns4.nettica.com", response.NameServers[4]);

        Assert.Equal(48, response.FieldsParsed);
    }
}
