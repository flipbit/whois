using System.Net;
using Xunit;

namespace Whois;

public class RequestTypeTests
{
    [Fact]
    public void DomainRequest_Sets_Query()
    {
        var request = new DomainRequest("example.com");

        Assert.Equal("example.com", request.Query);
    }

    [Fact]
    public void DomainRequest_Inherits_LookupRequest_Properties()
    {
        var request = new DomainRequest("example.com")
        {
            TimeoutSeconds = 30,
            FollowReferrer = false,
            PreferredProtocol = ProtocolPreference.Rdap,
            Port = 4343,
        };

        Assert.Equal(30, request.TimeoutSeconds);
        Assert.False(request.FollowReferrer);
        Assert.Equal(ProtocolPreference.Rdap, request.PreferredProtocol);
        Assert.Equal(4343, request.Port);
        Assert.IsAssignableFrom<LookupRequest>(request);
    }

    [Fact]
    public void IpRequest_From_IPAddress()
    {
        var ip = IPAddress.Parse("8.8.8.8");
        var request = new IpRequest(ip);

        Assert.Equal(ip, request.Address);
    }

    [Fact]
    public void IpRequest_From_String()
    {
        var request = new IpRequest("192.168.1.1");

        Assert.Equal(IPAddress.Parse("192.168.1.1"), request.Address);
    }

    [Fact]
    public void IpRequest_From_IPv6_String()
    {
        var request = new IpRequest("2001:4860:4860::8888");

        Assert.Equal(IPAddress.Parse("2001:4860:4860::8888"), request.Address);
    }

    [Fact]
    public void IpRequest_Invalid_String_Throws()
    {
        Assert.Throws<FormatException>(() => new IpRequest("not-an-ip"));
    }

    [Fact]
    public void IpRequest_Inherits_LookupRequest_Properties()
    {
        var request = new IpRequest("8.8.8.8")
        {
            TimeoutSeconds = 15,
            PreferredProtocol = ProtocolPreference.Whois,
        };

        Assert.Equal(15, request.TimeoutSeconds);
        Assert.Equal(ProtocolPreference.Whois, request.PreferredProtocol);
        Assert.IsAssignableFrom<LookupRequest>(request);
    }
}
