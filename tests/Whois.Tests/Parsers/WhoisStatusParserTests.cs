using Whois.Parsers;
using Xunit;

namespace Whois.Tests.Parsers;

public class WhoisStatusParserTests
{
    [Fact]
    public void Suspended_Should_Map_To_RegistrationStatus_Suspended()
    {
        var result = WhoisStatusParser.Parse("whois.example.com", "Suspended", RegistrationStatus.Unknown);

        Assert.Equal(RegistrationStatus.Suspended, result);
    }
}
