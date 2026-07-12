using System.Text;
using Xunit;

namespace Whois.Net;

/// <summary>
/// These tests will only pass if your connected to the Internet
/// </summary>
public class TcpReaderTest
{
    [Fact]
    public async Task TestReadWhoisForCogworksCoUk()
    {
        var reader = new TcpReader();
        var result = await reader.Read("whois.nic.uk", 43, "cogworks.co.uk", Encoding.UTF8, 30);

        // Just check the domain name is in the response
        Assert.True(result.IndexOf("cogworks.co.uk") > -1);
    }

    [Fact(Skip = "Not working")]
    public async Task TestReadWhoisForSapoPt()
    {
        var reader = new TcpReader();
        var result = await reader.Read("whois.dns.pt", 43, "sapo.pt", Encoding.GetEncoding("ISO-8859-1"), 30);

        // Just check the domain name is in the response
        Assert.True(result.IndexOf("sapo.pt") > -1);
    }

    [Fact]
    public async Task TestReadWhoisForUolComBr()
    {
        var reader = new TcpReader();
        var result = await reader.Read("registro.br", 43, "uol.com.br", Encoding.GetEncoding("ISO-8859-1"), 30);

        // Just check the domain name is in the response
        Assert.True(result.IndexOf("uol.com.br") > -1);
    }

    [Fact]
    public async Task TestReadWhoisForUnknownDomain()
    {
        var reader = new TcpReader();
        var result = await reader.Read("whois.nic.uk", 43, "invalid domain", Encoding.UTF8, 30);

        // Should never be registered (as invalid)
        Assert.Equal(-1, result.IndexOf("Registered on:"));
    }

    [Fact]
    public async Task TestReadWhenInvalidHost()
    {
        try
        {
            var reader = new TcpReader();
            await reader.Read("invalid domain", 43, "invalid domain", Encoding.UTF8, 30);

            Assert.Fail("Should of thrown an exception!");
        }
        catch (WhoisException)
        {
            // Should thrown an exception
        }
        catch (Exception)
        {
            Assert.Fail("Thrown an unexpected exception!");
        }
    }
}
