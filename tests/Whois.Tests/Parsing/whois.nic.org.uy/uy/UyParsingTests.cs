using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Org.Uy.Uy;

public class UyParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public UyParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact(Skip = "TODO")]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.org.uy", "uy", "found", "found.txt");
        var response = parser.Parse("whois.nic.org.uy", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);
    }

    [Fact(Skip = "TODO")]
    public void Test_error()
    {
        var sample = SampleReader.Read("whois.nic.org.uy", "uy", "error", "error.txt");
        var response = parser.Parse("whois.nic.org.uy", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Error, response.Status);
    }

    [Fact(Skip = "TODO")]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.org.uy", "uy", "not-found", "not_found.txt");
        var response = parser.Parse("whois.nic.org.uy", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.NotFound, response.Status);
    }

    [Fact(Skip = "TODO")]
    public void Test_found_status_registered()
    {
        var sample = SampleReader.Read("whois.nic.org.uy", "uy", "found", "found_status_registered.txt");
        var response = parser.Parse("whois.nic.org.uy", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);
    }
}
