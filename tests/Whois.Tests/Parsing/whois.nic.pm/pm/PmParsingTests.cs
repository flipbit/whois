using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Pm.Pm;

public class PmParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public PmParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.pm", "pm", "found", "nic.pm.txt");
        var response = parser.Parse("whois.nic.pm", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.fr/found/01", response.TemplateName);

        Assert.Equal("nic.pm", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("Registry Operations", response.Registrar.Name);

        Assert.NotNull(response.Updated);
        Assert.Equal(new DateTime(2026, 06, 08), response.Updated!.Value.Date);
        Assert.Equal(new DateTime(1995, 01, 01, 00, 00, 00, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2029, 12, 31, 23, 00, 00, DateTimeKind.Utc), response.Expiration);

        // Nameservers
        Assert.Equal(3, response.NameServers.Count);
        Assert.Equal("ns4.nic.fr", response.NameServers[0]);
        Assert.Equal("ns6.ext.nic.fr", response.NameServers[1]);
        Assert.Equal("ns7.ext.nic.fr", response.NameServers[2]);
    }

    [Fact]
    public void Test_throttled()
    {
        var sample = SampleReader.Read("whois.nic.pm", "pm", "throttled", "throttled.txt");
        var response = parser.Parse("whois.nic.pm", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Throttled, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/throttled/02", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.pm", "pm", "not-found", "not_found.txt");
        var response = parser.Parse("whois.nic.pm", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/not-found/06", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_status_registered()
    {
        var sample = SampleReader.Read("whois.nic.pm", "pm", "found", "found_status_registered.txt");
        var response = parser.Parse("whois.nic.pm", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        // Old FRNIC-2.5 format sample - matches legacy catch-all template
        Assert.Equal("generic/tld/found/05", response.TemplateName);

        Assert.Equal("nic.pm", response.DomainName.ToString());
    }
}
