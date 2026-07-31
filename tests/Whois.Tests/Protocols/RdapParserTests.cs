using System.Text.Json;
using Whois.Protocols;
using Xunit;

namespace Whois;

public class RdapParserTests
{
    [Fact]
    public void Parse_ValidResponse_ExtractsDomainName()
    {
        var json = File.ReadAllText(Path.Combine("..", "..", "..", "Samples", "rdap", "google-com.json"));

        var info = RdapParser.Parse(json);

        Assert.NotNull(info.DomainName);
        Assert.Equal("google.com", info.DomainName!.Value.ToLowerInvariant());
    }

    [Fact]
    public void Parse_ValidResponse_ExtractsRegistrar()
    {
        var json = File.ReadAllText(Path.Combine("..", "..", "..", "Samples", "rdap", "google-com.json"));

        var info = RdapParser.Parse(json);

        Assert.NotNull(info.Registrar);
        Assert.NotNull(info.Registrar!.Name);
    }

    [Fact]
    public void Parse_ValidResponse_ExtractsDates()
    {
        var json = File.ReadAllText(Path.Combine("..", "..", "..", "Samples", "rdap", "google-com.json"));

        var info = RdapParser.Parse(json);

        Assert.NotNull(info.Registered);
        Assert.NotNull(info.Expiration);
    }

    [Fact]
    public void Parse_ValidResponse_ExtractsNameServers()
    {
        var json = File.ReadAllText(Path.Combine("..", "..", "..", "Samples", "rdap", "google-com.json"));

        var info = RdapParser.Parse(json);

        Assert.NotEmpty(info.NameServers);
    }

    [Fact]
    public void Parse_ValidResponse_ExtractsStatus()
    {
        var json = File.ReadAllText(Path.Combine("..", "..", "..", "Samples", "rdap", "google-com.json"));

        var info = RdapParser.Parse(json);

        Assert.NotEmpty(info.DomainStatus);
        Assert.Equal(RegistrationStatus.Found, info.Status);
    }

    [Fact]
    public void Parse_ValidResponse_BuildsAddressLines()
    {
        var json = File.ReadAllText(Path.Combine("..", "..", "..", "Samples", "rdap", "google-com.json"));

        var info = RdapParser.Parse(json);

        // If registrant exists and has address, Lines should be populated
        if (info.Registrant?.Address != null)
        {
            Assert.NotEmpty(info.Registrant.Address.Lines);
        }
    }

    [Fact]
    public void Parse_ValidResponse_ExtractsRegistrarName()
    {
        var json = File.ReadAllText(Path.Combine("..", "..", "..", "Samples", "rdap", "google-com.json"));

        var info = RdapParser.Parse(json);

        Assert.Equal("MarkMonitor Inc.", info.Registrar!.Name);
    }

    [Fact]
    public void Parse_ValidResponse_ExtractsRegistrarIanaId()
    {
        var json = File.ReadAllText(Path.Combine("..", "..", "..", "Samples", "rdap", "google-com.json"));

        var info = RdapParser.Parse(json);

        Assert.Equal("292", info.Registrar!.IanaId);
    }

    [Fact]
    public void Parse_ValidResponse_ExtractsAbuseContact()
    {
        var json = File.ReadAllText(Path.Combine("..", "..", "..", "Samples", "rdap", "google-com.json"));

        var info = RdapParser.Parse(json);

        Assert.Equal("abusecomplaints@markmonitor.com", info.Registrar!.AbuseEmail);
    }

    [Fact]
    public void Parse_ValidResponse_ExtractsRegistrationDate()
    {
        var json = File.ReadAllText(Path.Combine("..", "..", "..", "Samples", "rdap", "google-com.json"));

        var info = RdapParser.Parse(json);

        Assert.Equal(new DateTime(1997, 9, 15, 4, 0, 0, DateTimeKind.Utc), info.Registered);
    }

    [Fact]
    public void Parse_ValidResponse_ExtractsExpirationDate()
    {
        var json = File.ReadAllText(Path.Combine("..", "..", "..", "Samples", "rdap", "google-com.json"));

        var info = RdapParser.Parse(json);

        Assert.Equal(new DateTime(2028, 9, 14, 4, 0, 0, DateTimeKind.Utc), info.Expiration);
    }

    [Fact]
    public void Parse_ValidResponse_ExtractsNameServerCount()
    {
        var json = File.ReadAllText(Path.Combine("..", "..", "..", "Samples", "rdap", "google-com.json"));

        var info = RdapParser.Parse(json);

        Assert.Equal(4, info.NameServers.Count);
    }

    [Fact]
    public void Parse_ValidResponse_ExtractsDnsSecStatus()
    {
        var json = File.ReadAllText(Path.Combine("..", "..", "..", "Samples", "rdap", "google-com.json"));

        var info = RdapParser.Parse(json);

        Assert.Equal("unsigned", info.DnsSecStatus);
    }

    [Fact]
    public void Parse_MinimalJson_ReturnsUnknownStatus()
    {
        var json = """{"objectClassName":"domain","ldhName":"test.com","status":[]}""";

        var info = RdapParser.Parse(json);

        Assert.Equal(RegistrationStatus.Unknown, info.Status);
    }

    [Fact]
    public void Parse_ActiveStatus_ReturnsFounded()
    {
        var json = """{"objectClassName":"domain","ldhName":"test.com","status":["active"]}""";

        var info = RdapParser.Parse(json);

        Assert.Equal(RegistrationStatus.Found, info.Status);
    }

    [Fact]
    public void Parse_NonEmptyStatuses_ReturnsFounded()
    {
        // EPP lock codes with no explicit "active" -- domain exists, return Found
        var json = """{"objectClassName":"domain","ldhName":"test.com","status":["client delete prohibited","server transfer prohibited"]}""";

        var info = RdapParser.Parse(json);

        Assert.Equal(RegistrationStatus.Found, info.Status);
    }

    [Fact]
    public void Parse_JcardAddressAsArray_BuildsAddressLines()
    {
        var json = """
        {
            "objectClassName": "domain",
            "ldhName": "example.com",
            "status": ["active"],
            "entities": [
                {
                    "objectClassName": "entity",
                    "roles": ["registrant"],
                    "vcardArray": [
                        "vcard",
                        [
                            ["version", {}, "text", "4.0"],
                            ["fn", {}, "text", "Test User"],
                            ["adr", {}, "text", ["", "", ["123 Main St", "Suite 100"], "Springfield", "IL", "62701", "US"]]
                        ]
                    ]
                }
            ]
        }
        """;

        var info = RdapParser.Parse(json);

        Assert.NotNull(info.Registrant);
        Assert.NotNull(info.Registrant!.Address);
        Assert.Contains("123 Main St", info.Registrant.Address!.Lines);
        Assert.Equal("Springfield", info.Registrant.Address.City);
        Assert.Equal("IL", info.Registrant.Address.Region);
        Assert.Equal("62701", info.Registrant.Address.PostalCode);
        Assert.Equal("US", info.Registrant.Address.Country);
    }

    [Fact]
    public void Parse_JcardAddressAsString_BuildsAddressLines()
    {
        var json = """
        {
            "objectClassName": "domain",
            "ldhName": "example.com",
            "status": ["active"],
            "entities": [
                {
                    "objectClassName": "entity",
                    "roles": ["registrant"],
                    "vcardArray": [
                        "vcard",
                        [
                            ["version", {}, "text", "4.0"],
                            ["fn", {}, "text", "Test User"],
                            ["adr", {}, "text", ["", "", "456 Oak Ave", "Chicago", "IL", "60601", "US"]]
                        ]
                    ]
                }
            ]
        }
        """;

        var info = RdapParser.Parse(json);

        Assert.NotNull(info.Registrant);
        Assert.NotNull(info.Registrant!.Address);
        Assert.Contains("456 Oak Ave", info.Registrant.Address!.Lines);
        Assert.Equal("Chicago", info.Registrant.Address.City);
    }

    [Fact]
    public void Parse_HandleField_PopulatesRegistryDomainId()
    {
        var json = File.ReadAllText(Path.Combine("..", "..", "..", "Samples", "rdap", "google-com.json"));

        var info = RdapParser.Parse(json);

        Assert.Equal("2138514_DOMAIN_COM-VRSN", info.RegistryDomainId);
    }

    [Fact]
    public void Parse_EntityWithMultipleRoles_PopulatesAllRoles()
    {
        var json = """
        {
            "objectClassName": "domain",
            "ldhName": "example.com",
            "status": ["active"],
            "entities": [
                {
                    "objectClassName": "entity",
                    "roles": ["registrant", "administrative"],
                    "handle": "entity-123",
                    "vcardArray": [
                        "vcard",
                        [
                            ["version", {}, "text", "4.0"],
                            ["fn", {}, "text", "Multi-Role User"],
                            ["email", {}, "text", "user@example.com"]
                        ]
                    ]
                }
            ]
        }
        """;

        var info = RdapParser.Parse(json);

        Assert.NotNull(info.Registrant);
        Assert.Equal("Multi-Role User", info.Registrant!.Name);
        Assert.Equal("user@example.com", info.Registrant.Email);
        Assert.NotNull(info.AdminContact);
        Assert.Equal("Multi-Role User", info.AdminContact!.Name);
        Assert.Equal("user@example.com", info.AdminContact.Email);
    }

    // M13: malformed JSON
    [Fact]
    public void Parse_MalformedJson_ThrowsJsonException()
    {
        Assert.ThrowsAny<JsonException>(() => RdapParser.Parse("not json"));
    }

    // M14: MapStatus coverage via Parse
    [Theory]
    [InlineData("active", RegistrationStatus.Found)]
    [InlineData("inactive", RegistrationStatus.Inactive)]
    [InlineData("locked", RegistrationStatus.Locked)]
    [InlineData("pending delete", RegistrationStatus.PendingDelete)]
    [InlineData("redemption period", RegistrationStatus.Redemption)]
    [InlineData("pending create", RegistrationStatus.Other)]
    [InlineData("pending renew", RegistrationStatus.Other)]
    [InlineData("pending restore", RegistrationStatus.Other)]
    [InlineData("pending transfer", RegistrationStatus.Other)]
    [InlineData("pending update", RegistrationStatus.Other)]
    [InlineData("client transfer prohibited", RegistrationStatus.Found)]
    public void Parse_StatusMapping_ReturnsExpectedStatus(string statusValue, RegistrationStatus expected)
    {
        var json = $$"""{"objectClassName":"domain","ldhName":"test.com","status":["{{statusValue}}"]}""";

        var info = RdapParser.Parse(json);

        Assert.Equal(expected, info.Status);
    }

    [Fact]
    public void Parse_EmptyStatusArray_ReturnsUnknown()
    {
        var json = """{"objectClassName":"domain","ldhName":"test.com","status":[]}""";

        var info = RdapParser.Parse(json);

        Assert.Equal(RegistrationStatus.Unknown, info.Status);
    }

    [Fact]
    public void Parse_MissingStatusProperty_ReturnsUnknown()
    {
        var json = """{"objectClassName":"domain","ldhName":"test.com"}""";

        var info = RdapParser.Parse(json);

        Assert.Equal(RegistrationStatus.Unknown, info.Status);
    }

    // L7: unicodeName fallback when ldhName is absent
    [Fact]
    public void Parse_UnicodeName_WithNoLdhName_ParsesDomainName()
    {
        var json = """{"objectClassName":"domain","unicodeName":"example.com","status":["active"]}""";

        var info = RdapParser.Parse(json);

        Assert.NotNull(info.DomainName);
        Assert.Equal("example.com", info.DomainName!.Value.ToLowerInvariant());
    }

    // M5: multi-remark joining
    [Fact]
    public void Parse_MultipleRemarks_JoinsDescriptions()
    {
        var json = """
        {
            "objectClassName": "domain",
            "ldhName": "example.com",
            "status": ["active"],
            "remarks": [
                {"description": ["First remark line 1", "First remark line 2"]},
                {"description": ["Second remark line 1"]}
            ]
        }
        """;

        var info = RdapParser.Parse(json);

        Assert.NotNull(info.Remarks);
        Assert.Contains("First remark line 1", info.Remarks!, StringComparison.Ordinal);
        Assert.Contains("First remark line 2", info.Remarks!, StringComparison.Ordinal);
        Assert.Contains("Second remark line 1", info.Remarks!, StringComparison.Ordinal);
        // All lines joined with newline
        Assert.Equal("First remark line 1\nFirst remark line 2\nSecond remark line 1", info.Remarks);
    }

    // M6: DNSSEC delegationSigned true
    [Fact]
    public void Parse_DnssecSigned_ReturnsSignedDelegation()
    {
        var json = """
        {
            "objectClassName": "domain",
            "ldhName": "example.com",
            "status": ["active"],
            "secureDNS": {"delegationSigned": true}
        }
        """;

        var info = RdapParser.Parse(json);

        Assert.Equal("signedDelegation", info.DnsSecStatus);
    }

    // L8: billing contact
    [Fact]
    public void Parse_BillingEntity_PopulatesBillingContact()
    {
        var json = """
        {
            "objectClassName": "domain",
            "ldhName": "example.com",
            "status": ["active"],
            "entities": [
                {
                    "objectClassName": "entity",
                    "roles": ["billing"],
                    "handle": "billing-123",
                    "vcardArray": [
                        "vcard",
                        [
                            ["version", {}, "text", "4.0"],
                            ["fn", {}, "text", "Billing Contact"],
                            ["email", {}, "text", "billing@example.com"]
                        ]
                    ]
                }
            ]
        }
        """;

        var info = RdapParser.Parse(json);

        Assert.NotNull(info.BillingContact);
        Assert.Equal("Billing Contact", info.BillingContact!.Name);
        Assert.Equal("billing@example.com", info.BillingContact.Email);
    }
}
