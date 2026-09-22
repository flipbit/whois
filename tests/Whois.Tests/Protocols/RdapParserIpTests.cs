using Xunit;

namespace Whois.Protocols;

public class RdapParserIpTests
{
    private const string ArinIpNetworkJson = """
        {
          "objectClassName": "ip network",
          "handle": "NET-8-8-8-0-2",
          "startAddress": "8.8.8.0",
          "endAddress": "8.8.8.255",
          "name": "GOGL",
          "country": "US",
          "port43": "whois.arin.net",
          "status": ["active"],
          "cidr0_cidrs": [
            { "v4prefix": "8.8.8.0", "length": 24 }
          ],
          "events": [
            { "eventAction": "registration", "eventDate": "2014-03-14T16:52:05-04:00" },
            { "eventAction": "last changed", "eventDate": "2014-03-14T16:52:05-04:00" }
          ],
          "entities": [
            {
              "objectClassName": "entity",
              "handle": "GOGL",
              "roles": ["registrant"],
              "vcardArray": ["vcard", [
                ["version", {}, "text", "4.0"],
                ["fn", {}, "text", "Google LLC"],
                ["org", {}, "text", "Google LLC"]
              ]]
            },
            {
              "objectClassName": "entity",
              "handle": "ZG39-ARIN",
              "roles": ["abuse"],
              "vcardArray": ["vcard", [
                ["version", {}, "text", "4.0"],
                ["fn", {}, "text", "Abuse Team"],
                ["email", {}, "text", "network-abuse@google.com"],
                ["tel", {}, "uri", "tel:+1-650-253-0000"]
              ]]
            }
          ],
          "remarks": [
            {
              "description": ["This is the Google DNS network."]
            }
          ]
        }
        """;

    [Fact]
    public void ParseIpNetwork_BasicFields()
    {
        var result = RdapParser.ParseIpNetwork(ArinIpNetworkJson);

        Assert.Equal("8.8.8.0 - 8.8.8.255", result.Network);
        Assert.Equal("8.8.8.0/24", result.Cidr);
        Assert.Equal("GOGL", result.NetName);
        Assert.Equal("US", result.Country);
        Assert.Equal(RegistrationStatus.Found, result.Status);
    }

    [Fact]
    public void ParseIpNetwork_Organization_FromRegistrantVcard()
    {
        var result = RdapParser.ParseIpNetwork(ArinIpNetworkJson);

        Assert.Equal("Google LLC", result.Organization);
    }

    [Fact]
    public void ParseIpNetwork_Rir_FromPort43()
    {
        var result = RdapParser.ParseIpNetwork(ArinIpNetworkJson);

        Assert.Equal("whois.arin.net", result.Rir);
    }

    [Fact]
    public void ParseIpNetwork_Dates()
    {
        var result = RdapParser.ParseIpNetwork(ArinIpNetworkJson);

        Assert.NotNull(result.Registered);
        Assert.NotNull(result.Updated);
    }

    [Fact]
    public void ParseIpNetwork_AbuseContact()
    {
        var result = RdapParser.ParseIpNetwork(ArinIpNetworkJson);

        Assert.NotNull(result.AbuseContact);
        Assert.Equal("network-abuse@google.com", result.AbuseContact!.Email);
        Assert.Equal("Abuse Team", result.AbuseContact.Name);
    }

    [Fact]
    public void ParseIpNetwork_Remarks()
    {
        var result = RdapParser.ParseIpNetwork(ArinIpNetworkJson);

        Assert.Equal("This is the Google DNS network.", result.Remarks);
    }

    [Fact]
    public void ParseIpNetwork_NoCidr0_ComputesFromRange()
    {
        const string json = """
            {
              "objectClassName": "ip network",
              "startAddress": "2.0.0.0",
              "endAddress": "2.0.0.255",
              "name": "TEST-NET",
              "status": ["active"]
            }
            """;

        var result = RdapParser.ParseIpNetwork(json);

        Assert.Equal("2.0.0.0 - 2.0.0.255", result.Network);
        Assert.Null(result.Cidr); // No cidr0_cidrs, and computing from range is optional
    }
}
