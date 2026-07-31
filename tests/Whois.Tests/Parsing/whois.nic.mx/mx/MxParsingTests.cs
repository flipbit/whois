using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Mx.Mx;

public class MxParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public MxParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.mx", "mx", "found", "mpsnet.net.mx.txt");
        var response = parser.Parse("whois.nic.mx", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.mx/mx/found/01", response.TemplateName);

        Assert.Equal("mpsnet.net.mx", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("AKKY ONLINE SOLUTIONS, S.A. DE C.V.", response.Registrar.Name);
        Assert.Equal("http://www.akky.mx", response.Registrar.Url);

        Assert.Equal(new DateTime(2026, 04, 07, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(1997, 04, 16, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2027, 04, 15, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("MPSNet Dominios", response.Registrant.Name);

        // Registrant Address
        Assert.Equal(3, response.Registrant.Address.Count);
        Assert.Equal("Mexico", response.Registrant.Address[0]);
        Assert.Equal("Distrito Federal", response.Registrant.Address[1]);
        Assert.Equal("Mexico", response.Registrant.Address[2]);


        // AdminContact Details
        Assert.Equal("Internet Engine S.A de C.V", response.AdminContact.Name);

        // AdminContact Address
        Assert.Equal(3, response.AdminContact.Address.Count);
        Assert.Equal("D.F.", response.AdminContact.Address[0]);
        Assert.Equal("Distrito Federal", response.AdminContact.Address[1]);
        Assert.Equal("Mexico", response.AdminContact.Address[2]);


        // BillingContact Details
        Assert.Equal("Internet Engine S.A de C.V", response.BillingContact.Name);

        // BillingContact Address
        Assert.Equal(3, response.BillingContact.Address.Count);
        Assert.Equal("D.F.", response.BillingContact.Address[0]);
        Assert.Equal("Distrito Federal", response.BillingContact.Address[1]);
        Assert.Equal("Mexico", response.BillingContact.Address[2]);


        // TechnicalContact Details
        Assert.Equal("Internet Engine S.A de C.V", response.TechnicalContact.Name);

        // TechnicalContact Address
        Assert.Equal(3, response.TechnicalContact.Address.Count);
        Assert.Equal("D.F.", response.TechnicalContact.Address[0]);
        Assert.Equal("Distrito Federal", response.TechnicalContact.Address[1]);
        Assert.Equal("Mexico", response.TechnicalContact.Address[2]);


        // Nameservers
        Assert.Equal(0, response.NameServers.Count);

        Assert.Equal(23, response.FieldsParsed);
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.mx", "mx", "not-found", "not_found.txt");
        var response = parser.Parse("whois.nic.mx", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.mx/mx/not-found/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_status_registered()
    {
        var sample = SampleReader.Read("whois.nic.mx", "mx", "found", "google.mx.txt");
        var response = parser.Parse("whois.nic.mx", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.mx/mx/found/01", response.TemplateName);

        Assert.Equal("google.mx", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("Markmonitor", response.Registrar.Name);
        Assert.Equal("http://www.markmonitor.com/", response.Registrar.Url);

        Assert.Equal(new DateTime(2026, 04, 12, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2009, 05, 12, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2027, 05, 11, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("DNS Admin", response.Registrant.Name);

        // Registrant Address
        Assert.Equal(3, response.Registrant.Address.Count);
        Assert.Equal("Mountain View", response.Registrant.Address[0]);
        Assert.Equal("California", response.Registrant.Address[1]);
        Assert.Equal("United States", response.Registrant.Address[2]);


        // AdminContact Details
        Assert.Equal("DNS Admin", response.AdminContact.Name);

        // AdminContact Address
        Assert.Equal(3, response.AdminContact.Address.Count);
        Assert.Equal("Mountain View", response.AdminContact.Address[0]);
        Assert.Equal("California", response.AdminContact.Address[1]);
        Assert.Equal("United States", response.AdminContact.Address[2]);


        // BillingContact Details
        Assert.Equal("CCOPs Provisioning", response.BillingContact.Name);

        // BillingContact Address
        Assert.Equal(3, response.BillingContact.Address.Count);
        Assert.Equal("Meridian", response.BillingContact.Address[0]);
        Assert.Equal("Idaho", response.BillingContact.Address[1]);
        Assert.Equal("United States", response.BillingContact.Address[2]);


        // TechnicalContact Details
        Assert.Equal("DNS Admin", response.TechnicalContact.Name);

        // TechnicalContact Address
        Assert.Equal(3, response.TechnicalContact.Address.Count);
        Assert.Equal("Mountain View", response.TechnicalContact.Address[0]);
        Assert.Equal("California", response.TechnicalContact.Address[1]);
        Assert.Equal("United States", response.TechnicalContact.Address[2]);


        Assert.Equal(23, response.FieldsParsed);
    }
}
